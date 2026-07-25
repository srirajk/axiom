package com.openwolf.iam.federation;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/** One SSRF/endpoint policy shared by discovery and every discovered OIDC endpoint. */
@Component
public final class OidcNetworkAddressPolicy {
    private final Set<String> allowedHosts;

    public OidcNetworkAddressPolicy(
            @Value("${iam.federation.metadata.allowed-hosts:}") String configuredHosts) {
        this.allowedHosts = Arrays.stream(configuredHosts == null ? new String[0] : configuredHosts.split(","))
                .map(String::trim)
                .filter(value -> !value.isBlank())
                .map(value -> value.toLowerCase(Locale.ROOT))
                .collect(Collectors.toUnmodifiableSet());
    }

    public void validate(URI endpoint, String label) {
        HttpOidcMetadataFetcher.requireSafeHttps(endpoint);
        resolveApproved(endpoint.getHost());
        if (endpoint.getUserInfo() != null) {
            throw new IllegalArgumentException(label + " must not contain user info");
        }
    }

    public Set<String> allowedHosts() {
        return allowedHosts;
    }

    /** Called by the transport for every new physical connection, not just at configuration time. */
    public InetAddress[] resolveApproved(String host) {
        HttpOidcMetadataFetcher.requireSafeResolution(host, allowedHosts);
        try {
            return InetAddress.getAllByName(host);
        } catch (java.net.UnknownHostException ex) {
            throw new IllegalArgumentException("OIDC endpoint host cannot be resolved", ex);
        }
    }
}
