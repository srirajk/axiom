package com.openwolf.iam.auth;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.openwolf.iam.entity.Principal;
import com.openwolf.iam.entity.Role;
import com.openwolf.iam.repository.PrincipalRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Builds the enrichment claims for an access token <b>inside a read-only transaction</b>.
 *
 * <p>This MUST be a separate bean from {@link JwtClaimsCustomizer}: the customizer runs as a
 * lambda during token encoding (no active persistence session), and {@code @Transactional}
 * is ignored on self-invocation. By calling into this bean the lazy {@code Principal.roles}
 * collection initializes correctly instead of throwing {@code LazyInitializationException}
 * (which previously broke the OIDC authorization_code flow / SSO login).
 */
@Service
public class OidcClaimEnricher {

    private static final Logger log = LoggerFactory.getLogger(OidcClaimEnricher.class);
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};
    private static final TypeReference<List<String>> LIST_TYPE = new TypeReference<>() {};

    private final PrincipalRepository principalRepository;
    private final ObjectMapper objectMapper;
    public OidcClaimEnricher(
            PrincipalRepository principalRepository,
            ObjectMapper objectMapper) {
        this.principalRepository = principalRepository;
        this.objectMapper = objectMapper;
    }

    /** Returns the claims to add to the access token. Runs in a session so lazy roles load. */
    @Transactional(readOnly = true)
    public Map<String, Object> enrich(String subject) {
        Map<String, Object> claims = new HashMap<>();

        Principal principal = principalRepository.findById(subject)
                .or(() -> principalRepository.findByUsername(subject))
                .orElse(null);

        if (principal == null || !principal.isActive()) {
            throw new IllegalStateException("token subject is not an active Axiom principal");
        }

        List<String> roles = principal.getRoles().stream()
                .map(Role::getName)
                .sorted()
                .toList();

        Set<String> permissionsSet = new HashSet<>();
        for (Role role : principal.getRoles()) {
            permissionsSet.addAll(parseList(role.getPermissions()));
        }
        List<String> permissions = new ArrayList<>(permissionsSet);
        Collections.sort(permissions);

        Map<String, Object> attrs = parseAttributes(principal.getAttributes());
        List<String> adminDomains = getStringList(attrs, "admin_domains");
        Object classificationRaw = attrs.get("classification");
        String classification = (classificationRaw instanceof String s && !s.isBlank()) ? s : "internal";
        // segments is now a per-segment classification MAP {segment -> tier}. The numeric
        // `clearance` claim is dropped entirely — the per-segment tier is the ceiling.
        Map<String, String> segments = getSegmentMap(attrs, classification);

        claims.put("roles", roles);
        claims.put("segments", segments);
        claims.put("admin_domains", adminDomains);
        claims.put("classification", classification);
        // A1: tenant_id is mandatory and non-defaultable — a principal with a null/blank home
        // tenant is un-mintable (requireTenant throws) rather than silently defaulting.
        claims.put("tenant_id", TenantClaims.requireTenant(principal.getTenantId()));
        claims.put("permissions", permissions);

        log.debug("JWT enriched for sub={} roles={} segments={}", subject, roles, segments);
        return claims;
    }

    /**
     * OIDC standard identity claims for the <b>ID token</b> (and, by default mapping, the
     * userinfo endpoint): {@code email}, {@code email_verified}, {@code preferred_username},
     * {@code name}. SSO consumers (LibreChat) need at least an email to provision the user;
     * without these the id_token/userinfo carries only {@code sub} and login fails.
     */
    @Transactional(readOnly = true)
    public Map<String, Object> enrichIdToken(String subject) {
        Map<String, Object> claims = new HashMap<>();

        Principal principal = principalRepository.findById(subject)
                .or(() -> principalRepository.findByUsername(subject))
                .orElse(null);

        if (principal == null || !principal.isActive()) {
            throw new IllegalStateException("ID-token subject is not an active Axiom principal");
        }

        if (principal.getEmail() != null && !principal.getEmail().isBlank()) {
            claims.put("email", principal.getEmail());
            claims.put("email_verified", true);
        }
        claims.put("preferred_username", principal.getUsername());

        Map<String, Object> attrs = parseAttributes(principal.getAttributes());
        Object displayName = attrs.get("display_name");
        claims.put("name", (displayName != null && !displayName.toString().isBlank())
                ? displayName.toString() : principal.getUsername());

        log.debug("ID-token enriched for sub={} email={} name={}",
                subject, claims.get("email"), claims.get("name"));
        return claims;
    }

    private Map<String, Object> parseAttributes(String json) {
        if (json == null || json.isBlank()) return Map.of();
        try {
            return objectMapper.readValue(json, MAP_TYPE);
        } catch (JsonProcessingException ex) {
            log.warn("Failed to parse principal attributes for JWT: {}", ex.getMessage());
            return Map.of();
        }
    }

    private List<String> parseList(String json) {
        if (json == null || json.isBlank()) return List.of();
        try {
            return objectMapper.readValue(json, LIST_TYPE);
        } catch (JsonProcessingException ex) {
            return List.of();
        }
    }

    @SuppressWarnings("unchecked")
    private List<String> getStringList(Map<String, Object> attrs, String key) {
        Object val = attrs.get(key);
        if (val instanceof List<?> list) {
            return list.stream().filter(Objects::nonNull).map(Object::toString).toList();
        }
        return Collections.emptyList();
    }

    /**
     * Builds the per-segment classification map claim {@code {segment -> tier}}.
     *
     * <p>Preferred source: the {@code segments} attribute stored as a JSON object (the new
     * shape). Legacy tolerance: if {@code segments} is still a JSON array (old flat list),
     * each segment is mapped to the principal's global {@code classification} tier — this
     * auto-migrates un-reseeded principals to an equivalent per-segment ceiling instead of
     * losing their access, without inventing tiers.
     */
    private Map<String, String> getSegmentMap(Map<String, Object> attrs, String fallbackTier) {
        Object raw = attrs.get("segments");
        Map<String, String> out = new LinkedHashMap<>();
        if (raw instanceof Map<?, ?> m) {
            m.forEach((k, v) -> {
                if (k != null && v != null) out.put(k.toString(), v.toString());
            });
        } else if (raw instanceof List<?> list) {
            String tier = (fallbackTier == null || fallbackTier.isBlank()) ? "internal" : fallbackTier;
            for (Object s : list) {
                if (s != null) out.put(s.toString(), tier);
            }
        }
        return out;
    }
}
