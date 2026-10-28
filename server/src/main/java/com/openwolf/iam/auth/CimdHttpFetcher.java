package com.openwolf.iam.auth;

import jakarta.annotation.PreDestroy;
import org.apache.hc.client5.http.DnsResolver;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.core5.util.Timeout;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.*;
import java.util.concurrent.*;

/** A separate, closed network policy for CIMD and delegated JWKS. No federation host exceptions apply. */
@Component
public class CimdHttpFetcher implements AutoCloseable {
    public static final int MAX_BYTES = 65_536;
    public record Response(byte[] body, String cacheControl, long ageSeconds) {}
    public static final class FetchFailure extends RuntimeException {
        public FetchFailure(String message) { super(message); }
        public FetchFailure(String message, Throwable cause) { super(message, cause); }
    }
    private final CloseableHttpClient client;
    private final ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
    private final Semaphore capacity = new Semaphore(20);
    private final ScheduledExecutorService deadlines = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "cimd-http-deadline"); t.setDaemon(true); return t;
    });
    @org.springframework.beans.factory.annotation.Autowired
    public CimdHttpFetcher() {
        var manager = PoolingHttpClientConnectionManagerBuilder.create()
                .setConnectionFactory(org.apache.hc.client5.http.impl.io.ManagedHttpClientConnectionFactory.builder()
                        .http1Config(org.apache.hc.core5.http.config.Http1Config.custom().setMaxHeaderCount(64).setMaxLineLength(8192).build()).build())
                .setDnsResolver(new DnsResolver() {
            @Override public InetAddress[] resolve(String host) throws UnknownHostException {
                return resolvePublic(host);
            }
            @Override public String resolveCanonicalHostname(String host) { return host; }
        }).setMaxConnTotal(20).setMaxConnPerRoute(4)
                .setDefaultConnectionConfig(ConnectionConfig.custom().setConnectTimeout(Timeout.ofSeconds(5))
                        .setSocketTimeout(Timeout.ofSeconds(5)).build()).build();
        client = HttpClients.custom().setConnectionManager(manager).disableRedirectHandling().disableAutomaticRetries()
                .disableCookieManagement().disableContentCompression()
                .setDefaultRequestConfig(RequestConfig.custom().setConnectionRequestTimeout(Timeout.ofSeconds(5))
                        .setResponseTimeout(Timeout.ofSeconds(5)).build()).build();
    }

    CimdHttpFetcher(CloseableHttpClient client) { this.client = client; }

    public Response fetch(String address) {
        URI uri = requireUrl(address);
        if (!capacity.tryAcquire()) throw new FetchFailure("metadata retrieval capacity exhausted");
        HttpGet request = new HttpGet(uri);
        Future<Response> result;
        try {
            result = workers.submit(() -> {
                try { return fetchNow(request); }
                finally { capacity.release(); }
            });
        } catch (RejectedExecutionException closed) { capacity.release(); throw new FetchFailure("metadata transport is closed", closed); }
        try { return result.get(5, TimeUnit.SECONDS); }
        catch (TimeoutException timeout) { request.cancel(); throw new FetchFailure("metadata retrieval timed out", timeout); }
        catch (InterruptedException interrupted) { request.cancel(); Thread.currentThread().interrupt(); throw new FetchFailure("metadata retrieval interrupted", interrupted); }
        catch (ExecutionException failure) {
            if (failure.getCause() instanceof RuntimeException runtime) throw runtime;
            throw new FetchFailure("metadata retrieval failed", failure.getCause());
        }
    }

    private Response fetchNow(HttpGet request) {
        request.setHeader("Accept", "application/json");
        request.setHeader("Cache-Control", "no-cache");
        var deadline = deadlines.schedule(request::cancel, 5, TimeUnit.SECONDS);
        try {
            return client.execute(request, response -> {
                if (response.getCode() != 200) {
                    if (response.getCode() >= 500) { request.cancel(); throw new FetchFailure("metadata HTTP status " + response.getCode()); }
                    throw reject(request, "invalid metadata HTTP status " + response.getCode());
                }
                var type = response.getFirstHeader("Content-Type");
                String contentType = type == null ? "" : type.getValue().split(";", 2)[0].trim().toLowerCase(java.util.Locale.ROOT);
                if (!(contentType.equals("application/json") || contentType.matches("application/[a-z0-9!#$&^_.+-]+\\+json"))) {
                    throw reject(request, "metadata requires application/json");
                }
                var encoding = response.getFirstHeader("Content-Encoding");
                if (encoding != null && !"identity".equalsIgnoreCase(encoding.getValue())) {
                    throw reject(request, "encoded metadata is unsupported");
                }
                var entity = response.getEntity();
                if (entity == null || entity.getContentLength() > MAX_BYTES) throw reject(request, "metadata exceeds 64 KB");
                byte[] body;
                try (var stream = entity.getContent()) {
                    body = stream.readNBytes(MAX_BYTES + 1);
                    // Abort before closing: an HTTP entity close may otherwise drain an unbounded remaining body.
                    if (body.length > MAX_BYTES) throw reject(request, "metadata exceeds 64 KB");
                }
                String cache = response.getFirstHeader("Cache-Control") == null ? "" : response.getFirstHeader("Cache-Control").getValue();
                long age = 0;
                try { if (response.getFirstHeader("Age") != null) age = Long.parseLong(response.getFirstHeader("Age").getValue()); }
                catch (NumberFormatException ignored) { age = Long.MAX_VALUE; }
                return new Response(body, cache, Math.max(0, age));
            });
        } catch (IOException failure) { throw new FetchFailure("metadata retrieval failed", failure); }
        finally { deadline.cancel(false); }
    }

    private static IllegalArgumentException reject(HttpGet request, String message) {
        request.cancel(); return new IllegalArgumentException(message);
    }

    public static URI requireUrl(String address) {
        if (address == null || address.length() > 2048) throw new IllegalArgumentException("invalid metadata URL");
        URI uri = URI.create(address);
        if (!"https".equals(uri.getScheme()) || uri.getHost() == null || uri.getRawPath() == null || uri.getRawPath().isEmpty()
                || uri.getRawUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null
                || uri.getPort() != -1 && uri.getPort() != 443 || !address.equals(uri.toASCIIString()) || !uri.normalize().equals(uri)) {
            throw new IllegalArgumentException("metadata requires a path-bearing, query-free HTTPS URL");
        }
        String decodedPath = java.net.URLDecoder.decode(uri.getRawPath(), java.nio.charset.StandardCharsets.UTF_8);
        if (java.util.Arrays.stream(decodedPath.split("/", -1)).anyMatch(segment -> segment.equals(".") || segment.equals(".."))) {
            throw new IllegalArgumentException("metadata URLs must not contain encoded dot segments");
        }
        // HttpClient may bypass DnsResolver for IP literals; rejecting them closes that alternate connection path.
        if (uri.getHost().contains(":") || uri.getHost().matches("[0-9.]+")) {
            throw new IllegalArgumentException("metadata URLs require a public DNS hostname");
        }
        return uri;
    }

    @FunctionalInterface interface AddressResolver { InetAddress[] resolve(String host) throws UnknownHostException; }
    static InetAddress[] resolvePublic(String host) throws UnknownHostException { return resolvePublic(host, InetAddress::getAllByName); }
    static InetAddress[] resolvePublic(String host, AddressResolver resolver) throws UnknownHostException {
        InetAddress[] addresses = resolver.resolve(host);
        requirePublic(addresses);
        return addresses; // The exact checked addresses are used for this socket: no second DNS lookup.
    }

    static void requirePublic(InetAddress[] addresses) {
        if (addresses.length == 0) throw new IllegalArgumentException("metadata DNS returned no addresses");
        for (InetAddress address : addresses) {
            if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()
                    || address.isSiteLocalAddress() || address.isMulticastAddress()) throw new IllegalArgumentException("restricted metadata address");
            byte[] b = address.getAddress();
            if (b.length == 4) {
                int a = b[0] & 255, c = b[1] & 255, d = b[2] & 255, e = b[3] & 255;
                if (a == 0 || a == 10 || a == 127 || a == 169 && c == 254 || a == 172 && c >= 16 && c <= 31
                        || a == 168 && c == 63 && d == 129 && e == 16
                        || a == 192 && (c == 0 || c == 168 || c == 88 && d == 99) || a == 100 && c >= 64 && c <= 127
                        || a == 198 && (c == 18 || c == 19 || c == 51) || a == 203 && c == 0 || a >= 224) {
                    throw new IllegalArgumentException("restricted metadata address");
                }
            } else if (b.length != 16 || (b[0] & 0xe0) != 0x20 || (b[0] & 255) == 0x20 && (b[1] & 255) == 0x02
                    || b[0] == 0x20 && b[1] == 0x01 && ((b[2] & 255) < 2 || (b[2] & 255) == 0x0d && (b[3] & 255) == 0xb8)) {
                // Only ordinary global-unicast IPv6; reject mapped/compatible, ULA, Teredo, NAT64, 6to4 and special-use.
                throw new IllegalArgumentException("restricted metadata address");
            }
        }
    }

    @PreDestroy public void close() throws IOException { deadlines.shutdownNow(); workers.shutdownNow(); client.close(); }
}
