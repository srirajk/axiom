package com.openwolf.iam.policystudio.lifecycle;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CerbosRuntimeActivationProbeTest {

    @Test
    void requiresServingPdpToReportExactCandidateMatchedPolicy() throws Exception {
        PolicyBundle bundle = candidate();
        AtomicReference<String> version = new AtomicReference<>(bundle.bundleId());
        AtomicInteger requests = new AtomicInteger();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/check/resources", exchange -> {
            requests.incrementAndGet();
            String request = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String kind = request.contains("\"kind\":\"iam-resource\"") ? "iam-resource"
                    : request.contains("\"kind\":\"relationship\"") ? "relationship" : "agent";
            String action = kind.equals("iam-resource") ? "manage"
                    : kind.equals("relationship") ? "read" : "invoke";
            byte[] bytes = response(version.get(), kind, action).getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();
        try {
            URI endpoint = URI.create("http://127.0.0.1:" + server.getAddress().getPort()
                    + "/api/check/resources");
            CerbosRuntimeActivationProbe probe = new CerbosRuntimeActivationProbe(
                    HttpClient.newHttpClient(), new ObjectMapper(), endpoint, 100L, 5L);

            probe.awaitLoaded(bundle);
            org.assertj.core.api.Assertions.assertThat(requests.get()).isEqualTo(3);

            version.set("different-version");
            assertThatThrownBy(() -> probe.awaitLoaded(bundle))
                    .isInstanceOf(PromotedBundleLoadException.class)
                    .hasMessageContaining("refusing to activate");
        } finally {
            server.stop(0);
        }
    }

    private static PolicyBundle candidate() {
        String yaml = """
                apiVersion: api.cerbos.dev/v1
                resourcePolicy:
                  version: __BUNDLE_VERSION__
                  resource: agent
                  scope: acme
                  scopePermissions: SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS
                  rules:
                    - actions: [invoke]
                      effect: EFFECT_DENY
                      roles: [chat_user]
                """;
        String relationship = yaml.replace("resource: agent", "resource: relationship")
                .replace("actions: [invoke]", "actions: [read]");
        String iam = yaml.replace("resource: agent", "resource: iam-resource")
                .replace("actions: [invoke]", "actions: [manage]");
        return PolicyBundle.materialize("acme", List.of(
                        new BundleFile("agent@acme.yaml", yaml),
                        new BundleFile("relationship@acme.yaml", relationship),
                        new BundleFile("iam-resource@acme.yaml", iam)),
                List.of(), new BundleTestMetadata("fixture", 1, "oracle", "cerbos:0.53.0"),
                new BundleCanonicalizer());
    }

    private static String response(String version, String kind, String action) {
        return """
                {"requestId":"probe","results":[{"resource":{"id":"policy-activation-probe",
                "kind":"%s","policyVersion":"%s"},"actions":{"%s":"EFFECT_DENY"},
                "meta":{"actions":{"%s":{"matchedPolicy":"resource.%s.v%s/acme"}}}}]}
                """.formatted(kind, version, action, action,
                        CerbosRuntimeActivationProbe.cerbosFqnResource(kind), version);
    }
}
