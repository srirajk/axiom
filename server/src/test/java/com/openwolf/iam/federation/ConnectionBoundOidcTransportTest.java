package com.openwolf.iam.federation;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ConnectionBoundOidcTransportTest {
    @Test
    void actualRequestUsesThePolicyResolverAtConnectionTime() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext("/", exchange -> {
            byte[] body = "ok".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            try (var output = exchange.getResponseBody()) { output.write(body); }
        });
        server.start();
        try {
            var transport = new ConnectionBoundOidcTransport(new OidcNetworkAddressPolicy("localhost"));
            assertThat(transport.restOperations().getForObject(
                    "http://localhost:" + server.getAddress().getPort() + "/", String.class))
                    .isEqualTo("ok");
            var blocked = new ConnectionBoundOidcTransport(new OidcNetworkAddressPolicy(""));
            assertThatThrownBy(() -> blocked.restOperations().getForObject(
                    "http://localhost:" + server.getAddress().getPort() + "/", String.class))
                    .hasMessage("OIDC metadata host resolves to a restricted address");
        } finally {
            server.stop(0);
        }
    }
}
