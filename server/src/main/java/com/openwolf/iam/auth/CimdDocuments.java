package com.openwolf.iam.auth;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.*;
import com.openwolf.iam.service.ClientAssertionKeys;
import org.springframework.stereotype.Component;
import java.time.*;
import java.util.*;
import java.util.function.Consumer;

/** Separate bounded caches: metadata may be stale for 24 hours; assertion keys never outlive five minutes. */
@Component
public class CimdDocuments {
    public record Document(String name, List<String> redirects, Set<String> grants, Set<String> scopes,
                           String authenticationMethod, String jwksUri, String signingAlgorithm) {}
    private record Cached(Document document, Instant fetched, Instant freshUntil) {}
    private record Keys(ClientAssertionKeys.Registered value, Instant freshUntil, Instant forcedAt) {}
    private final Map<String, Cached> cache = new LinkedHashMap<>(16, .75f, true);
    private final Map<String, Keys> keyCache = new LinkedHashMap<>(16, .75f, true);
    private final CimdHttpFetcher fetcher;
    private final Clock clock;
    private final java.util.concurrent.locks.ReentrantLock[] locks = java.util.stream.IntStream.range(0, 64)
            .mapToObj(i -> new java.util.concurrent.locks.ReentrantLock()).toArray(java.util.concurrent.locks.ReentrantLock[]::new);
    private final ObjectMapper json = new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    @org.springframework.beans.factory.annotation.Autowired
    public CimdDocuments(CimdHttpFetcher fetcher) { this(fetcher, Clock.systemUTC()); }
    CimdDocuments(CimdHttpFetcher fetcher, Clock clock) { this.fetcher = fetcher; this.clock = clock; }

    public Document get(String clientId, Consumer<String> failureAudit) {
        var lock = acquire(clientId, failureAudit);
        try { return getLocked(clientId, failureAudit, false); }
        finally { lock.unlock(); }
    }
    /** Key delegation is security material too: assertions require metadata revalidated within five minutes. */
    public Document forAuthentication(String clientId, Consumer<String> failureAudit) {
        var lock = acquire(clientId, failureAudit);
        try { return getLocked(clientId, failureAudit, true); }
        finally { lock.unlock(); }
    }
    public void evict(String clientId) {
        Cached previous;
        synchronized (cache) { previous = cache.remove(clientId); }
        if (previous != null && previous.document().jwksUri() != null) synchronized (keyCache) { keyCache.remove(previous.document().jwksUri()); }
    }
    private java.util.concurrent.locks.ReentrantLock acquire(String key, Consumer<String> failureAudit) {
        var lock = locks[Math.floorMod(key.hashCode(), locks.length)];
        try {
            if (!lock.tryLock(5, java.util.concurrent.TimeUnit.SECONDS)) {
                failureAudit.accept("cache_busy"); throw new CimdHttpFetcher.FetchFailure("metadata cache busy");
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt(); failureAudit.accept("interrupted");
            throw new CimdHttpFetcher.FetchFailure("metadata cache wait interrupted", interrupted);
        }
        return lock;
    }
    private Document getLocked(String clientId, Consumer<String> failureAudit, boolean assertion) {
        Instant now = clock.instant();
        Cached existing;
        synchronized (cache) { existing = cache.get(clientId); }
        if (existing != null && now.isBefore(existing.freshUntil())
                && (!assertion || now.isBefore(existing.fetched().plusSeconds(300)))) return existing.document();
        try {
            var response = fetcher.fetch(clientId);
            JsonNode root = parse(response.body());
            if (!clientId.equals(text(root, "client_id")) || root.has("client_secret") || root.has("client_secret_expires_at")
                    || root.has("jwks")) throw new IllegalArgumentException("invalid CIMD identity or key material");
            String name = safeDisplayName(text(root, "client_name"));
            List<String> redirects = strings(root, "redirect_uris");
            redirects.forEach(CimdDocuments::requireRedirect);
            Set<String> grants = Set.copyOf(strings(root, "grant_types"));
            if (!grants.contains("authorization_code")) throw new IllegalArgumentException("authorization_code is required");
            if (root.has("response_types") && !strings(root, "response_types").contains("code")) throw new IllegalArgumentException("code response type is required");
            Set<String> scopes = root.has("scope") ? Set.copyOf(List.of(text(root, "scope").trim().split("\\s+"))) : null;
            String method = root.has("token_endpoint_auth_method") ? text(root, "token_endpoint_auth_method") : "none";
            String jwksUri = null, algorithm = null;
            if ("private_key_jwt".equals(method)) {
                jwksUri = text(root, "jwks_uri"); CimdHttpFetcher.requireUrl(jwksUri);
                if (root.has("token_endpoint_auth_signing_alg")) {
                    algorithm = text(root, "token_endpoint_auth_signing_alg");
                    if (!Set.of("RS256", "ES256").contains(algorithm)) throw new IllegalArgumentException("unsupported assertion algorithm");
                }
            } else if (!"none".equals(method)) throw new IllegalArgumentException("unsupported CIMD authentication method");
            if (response.ageSeconds() >= (assertion ? 300 : 86_400)) throw new IllegalArgumentException("metadata HTTP age exceeds its security lifetime");
            Document document = new Document(name, redirects, grants, scopes, method, jwksUri, algorithm);
            Duration freshness = freshness(response);
            synchronized (cache) {
                if (freshness.isZero()) cache.remove(clientId);
                else { cache.put(clientId, new Cached(document, now.minusSeconds(response.ageSeconds()), now.plus(freshness))); trim(cache); }
            }
            return document;
        } catch (CimdHttpFetcher.FetchFailure failure) {
            failureAudit.accept("retrieval");
            if (assertion) throw failure;
            if (existing != null && now.isBefore(existing.fetched().plus(Duration.ofHours(24)))) {
                Instant retry = now.plus(Duration.ofMinutes(5)), cap = existing.fetched().plus(Duration.ofHours(24));
                synchronized (cache) { cache.put(clientId, new Cached(existing.document(), existing.fetched(), retry.isBefore(cap) ? retry : cap)); }
                return existing.document();
            }
            synchronized (cache) { cache.remove(clientId); }
            throw failure;
        } catch (RuntimeException invalid) {
            synchronized (cache) { cache.remove(clientId); }
            failureAudit.accept("invalid_metadata"); throw invalid;
        }
    }

    /** Unknown kids can trigger at most one forced refresh per key URL per 30 seconds. No stale-key fallback. */
    public ClientAssertionKeys.Registered keys(Document document, String kid, Consumer<String> failureAudit) {
        if (!"private_key_jwt".equals(document.authenticationMethod()) || kid == null || kid.isBlank() || kid.length() > 200) {
            throw new IllegalArgumentException("invalid assertion key identifier");
        }
        String uri = document.jwksUri();
        var lock = acquire(uri, failureAudit);
        try {
            Instant now = clock.instant();
            Keys existing;
            synchronized (keyCache) { existing = keyCache.get(uri); }
            boolean fresh = existing != null && now.isBefore(existing.freshUntil());
            boolean forced = fresh && !existing.value().keyIds().contains(kid);
            if (fresh && (!forced || existing.forcedAt() != null && now.isBefore(existing.forcedAt().plusSeconds(30)))) {
                return compatible(document, existing.value());
            }
            if (forced) synchronized (keyCache) { keyCache.put(uri, new Keys(existing.value(), existing.freshUntil(), now)); }
            try {
                var response = fetcher.fetch(uri);
                if (response.ageSeconds() >= 300) throw new IllegalArgumentException("JWKS HTTP age exceeds five minutes");
                var value = ClientAssertionKeys.validate(json.convertValue(parse(response.body()), new com.fasterxml.jackson.core.type.TypeReference<Map<String,Object>>() {}));
                compatible(document, value);
                Duration ttl = keyFreshness(response);
                synchronized (keyCache) {
                    // A no-store response is used for this assertion only.
                    if (ttl.isZero()) keyCache.remove(uri);
                    else { keyCache.put(uri, new Keys(value, now.plus(ttl), forced || !value.keyIds().contains(kid) ? now : null)); trim(keyCache); }
                }
                return value;
            } catch (RuntimeException failure) {
                if (!fresh || !(failure instanceof CimdHttpFetcher.FetchFailure)) synchronized (keyCache) { keyCache.remove(uri); }
                failureAudit.accept("jwks_retrieval_or_validation"); throw failure;
            }
        } finally { lock.unlock(); }
    }
    private static ClientAssertionKeys.Registered compatible(Document document, ClientAssertionKeys.Registered keys) {
        if (document.signingAlgorithm() != null && !document.signingAlgorithm().equals(keys.algorithm().getName())) {
            throw new IllegalArgumentException("CIMD assertion algorithm disagrees with keys");
        }
        return keys;
    }
    private static void trim(Map<?,?> values) { if (values.size() > 1024) values.remove(values.keySet().iterator().next()); }
    private JsonNode parse(byte[] body) {
        if (body.length > CimdHttpFetcher.MAX_BYTES) throw new IllegalArgumentException("metadata exceeds 64 KB");
        try {
            JsonNode node = json.readTree(body);
            if (node == null || !node.isObject()) throw new IllegalArgumentException("metadata must be an object");
            return node;
        } catch (java.io.IOException failure) { throw new IllegalArgumentException("invalid metadata JSON", failure); }
    }
    static Duration freshness(CimdHttpFetcher.Response response) { return cacheLifetime(response, 300, 86_400); }
    static Duration keyFreshness(CimdHttpFetcher.Response response) { return cacheLifetime(response, 0, 300); }
    private static Duration cacheLifetime(CimdHttpFetcher.Response response, long minimum, long maximum) {
        long seconds = 300;
        for (String part : response.cacheControl().toLowerCase(Locale.ROOT).split(",")) {
            String directive = part.trim();
            if (directive.equals("no-store") || directive.equals("no-cache")) return Duration.ZERO;
            if (directive.startsWith("max-age=")) {
                try { seconds = Long.parseLong(directive.substring(8).replace("\"", "")); }
                catch (NumberFormatException invalid) { return Duration.ZERO; }
                if (seconds <= 0) return Duration.ZERO;
            }
        }
        seconds = Math.max(minimum, Math.min(maximum, seconds));
        return Duration.ofSeconds(Math.max(0, seconds - Math.min(seconds, response.ageSeconds())));
    }
    public static String safeDisplayName(String value) {
        StringBuilder clean = new StringBuilder();
        value.codePoints().filter(cp -> !Character.isISOControl(cp) && Character.getType(cp) != Character.FORMAT
                && Character.getType(cp) != Character.LINE_SEPARATOR && Character.getType(cp) != Character.PARAGRAPH_SEPARATOR)
                .limit(80).forEach(clean::appendCodePoint);
        String result = clean.toString().trim();
        if (result.isBlank()) throw new IllegalArgumentException("display name must contain visible text");
        return result;
    }
    public static void requireRedirect(String value) {
        java.net.URI uri = java.net.URI.create(value);
        if (value.length() > 2048 || uri.getPort() == 0 || uri.getPort() > 65535 || uri.getHost() == null || uri.getRawFragment() != null || uri.getRawUserInfo() != null
                || !("https".equals(uri.getScheme()) || LoopbackRedirects.isLoopback(value))) throw new IllegalArgumentException("invalid trusted redirect URI");
    }
    private static String text(JsonNode root, String name) {
        JsonNode value = root.get(name);
        if (value == null || !value.isTextual() || value.asText().isBlank()) throw new IllegalArgumentException("missing " + name);
        return value.asText();
    }
    private static List<String> strings(JsonNode root, String name) {
        JsonNode values = root.get(name);
        if (values == null || !values.isArray() || values.isEmpty() || values.size() > 32) throw new IllegalArgumentException("invalid " + name);
        List<String> result = new ArrayList<>();
        values.forEach(value -> { if (!value.isTextual() || value.asText().isBlank()) throw new IllegalArgumentException("invalid " + name); result.add(value.asText()); });
        return List.copyOf(result);
    }
}
