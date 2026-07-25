package com.openwolf.iam.federation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;

@Component
public final class HttpOidcMetadataFetcher implements OidcMetadataFetcher {
    private static final int MAX_BYTES = 1_048_576;
    private final ObjectMapper mapper;
    private final ConnectionBoundOidcTransport transport;

    @Autowired
    public HttpOidcMetadataFetcher(ObjectMapper mapper,
                                   ConnectionBoundOidcTransport transport,
                                   @Value("${iam.federation.metadata.allowed-hosts:}") String allowedHosts) {
        this.mapper = mapper;
        this.transport = transport;
        this.allowedHosts = Arrays.stream(allowedHosts == null ? new String[0] : allowedHosts.split(","))
                .map(String::trim).filter(value -> !value.isBlank()).collect(Collectors.toUnmodifiableSet());
    }

    /** Isolated constructor retained for static-policy unit tests. */
    public HttpOidcMetadataFetcher(ObjectMapper mapper, String allowedHosts) {
        this(mapper, new ConnectionBoundOidcTransport(new OidcNetworkAddressPolicy(allowedHosts)), allowedHosts);
    }

    private final Set<String> allowedHosts;

    @Override
    public OidcMetadata fetch(URI discoveryUri) {
        requireSafeHttps(discoveryUri);
        requireSafeResolution(discoveryUri.getHost(), allowedHosts);
        try {
            byte[] boundedBody = transport.restOperations().getForObject(discoveryUri, byte[].class);
            if (boundedBody == null) throw new IllegalArgumentException("OIDC discovery retrieval failed");
            if (boundedBody.length > MAX_BYTES) throw new IllegalArgumentException("OIDC discovery document is too large");
            JsonNode json = mapper.readTree(boundedBody);
            return new OidcMetadata(
                    text(json, "issuer"), uri(json, "authorization_endpoint"), uri(json, "token_endpoint"),
                    uri(json, "userinfo_endpoint"), uri(json, "jwks_uri"), list(json, "id_token_signing_alg_values_supported"),
                    list(json, "scopes_supported"), list(json, "claims_supported"), list(json, "acr_values_supported"));
        } catch (IOException | RuntimeException ex) {
            throw new IllegalArgumentException("OIDC discovery retrieval failed", ex);
        }
    }

    static void requireSafeHttps(URI uri) {
        if (uri == null || !"https".equalsIgnoreCase(uri.getScheme()) || uri.getUserInfo() != null
                || uri.getFragment() != null || uri.getQuery() != null) {
            throw new IllegalArgumentException("OIDC metadata must use a query-free HTTPS URI");
        }
    }

    static void requireSafeResolution(String host, Set<String> allowedHosts) {
        if (host == null || host.isBlank()) throw new IllegalArgumentException("OIDC metadata host is required");
        try {
            Set<String> normalizedAllowlist = new HashSet<>();
            for (String allowedHost : allowedHosts) normalizedAllowlist.add(allowedHost.toLowerCase(java.util.Locale.ROOT));
            boolean explicitlyAllowed = normalizedAllowlist.contains(host.toLowerCase(java.util.Locale.ROOT));
            for (InetAddress address : InetAddress.getAllByName(host)) {
                if (!explicitlyAllowed && isBlockedAddress(address)) {
                    throw new IllegalArgumentException("OIDC metadata host resolves to a restricted address");
                }
            }
        } catch (java.net.UnknownHostException ex) {
            throw new IllegalArgumentException("OIDC metadata host cannot be resolved");
        }
    }

    static boolean isBlockedAddress(InetAddress address) {
        if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()
                || address.isSiteLocalAddress() || address.isMulticastAddress()) return true;
        byte[] bytes = address.getAddress();
        if (address instanceof Inet4Address) {
            int first = bytes[0] & 0xff, second = bytes[1] & 0xff;
            return first == 0 || first == 10 || first == 127 || first == 169 && second == 254
                    || first == 172 && second >= 16 && second <= 31
                    || first == 192 && second == 168
                    || first == 100 && second >= 64 && second <= 127
                    || first >= 224;
        }
        if (address instanceof Inet6Address) {
            return (bytes[0] & 0xff) == 0xfc || (bytes[0] & 0xff) == 0xfd
                    || (bytes[0] & 0xff) == 0xfe && (bytes[1] & 0xc0) == 0x80
                    || isIpv4MappedRestricted(bytes);
        }
        return true;
    }

    private static boolean isIpv4MappedRestricted(byte[] bytes) {
        if (bytes.length != 16 || bytes[0] != 0 || bytes[1] != 0 || bytes[2] != 0 || bytes[3] != 0
                || bytes[4] != 0 || bytes[5] != 0 || bytes[6] != 0 || bytes[7] != 0
                || bytes[8] != 0 || bytes[9] != 0 || bytes[10] != (byte) 0xff || bytes[11] != (byte) 0xff) return false;
        int first = bytes[12] & 0xff, second = bytes[13] & 0xff;
        return first == 0 || first == 10 || first == 127 || (first == 169 && second == 254)
                || (first == 172 && second >= 16 && second <= 31)
                || (first == 192 && second == 168)
                || (first == 100 && second >= 64 && second <= 127)
                || first >= 224;
    }

    private static String text(JsonNode json, String name) {
        JsonNode value = json.get(name);
        if (value == null || !value.isTextual() || value.textValue().isBlank()) throw new IllegalArgumentException("OIDC discovery is missing " + name);
        return value.textValue();
    }
    private static URI uri(JsonNode json, String name) { return URI.create(text(json, name)); }
    private static List<String> list(JsonNode json, String name) {
        JsonNode values = json.get(name); if (values == null || !values.isArray()) return List.of();
        List<String> result = new ArrayList<>(); values.forEach(value -> { if (value.isTextual()) result.add(value.textValue()); }); return List.copyOf(result);
    }
}
