package com.openwolf.iam.authority.delivery;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.URI;
import java.util.Locale;

/**
 * Phase 3.1 startup guard. The local-demo disclosure (returning an e-mail verification code in the registration
 * response) is a local test aid only. Axiom refuses to start with it enabled unless the issuer is a loopback host
 * ({@code localhost}, {@code *.localhost}, {@code 127.0.0.0/8}, {@code ::1}) and no real delivery provider is
 * configured. Recovery codes are never disclosed in any configuration.
 */
@Component
public class LocalDemoDisclosureGuard {

    public LocalDemoDisclosureGuard(
            @Value("${iam.ciam.local-demo-challenge-disclosure:false}") boolean disclosure,
            @Value("${spring.security.oauth2.authorizationserver.issuer:http://localhost:8084}") String issuer,
            ObjectProvider<CustomerCodeDeliveryProvider> providers) {
        if (!disclosure) return;
        if (providers.getIfAvailable() != null) {
            throw new IllegalStateException("local-demo challenge disclosure cannot be combined with a delivery provider");
        }
        if (!loopback(issuer)) {
            throw new IllegalStateException("local-demo challenge disclosure is allowed only on a loopback issuer");
        }
    }

    static boolean loopback(String issuer) {
        String host;
        try {
            host = URI.create(issuer).getHost();
        } catch (RuntimeException malformed) {
            return false;
        }
        if (host == null || host.isBlank()) return false;
        String h = host.toLowerCase(Locale.ROOT);
        if (h.equals("localhost") || h.endsWith(".localhost")) return true;
        if (h.startsWith("[") && h.endsWith("]")) h = h.substring(1, h.length() - 1);
        if (!h.matches("[0-9.]+") && !h.contains(":")) return false;  // a name other than localhost: never trusted
        try {
            return InetAddress.ofLiteral(h).isLoopbackAddress();
        } catch (IllegalArgumentException notLiteral) {
            return false;
        }
    }
}
