package com.openwolf.iam.federation;

import org.apache.hc.client5.http.DnsResolver;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;
import org.apache.hc.core5.util.TimeValue;
import org.apache.hc.core5.util.Timeout;

import java.net.InetAddress;

/** Apache transport whose resolver is consulted by the connection manager for every new socket. */
@Component
public final class ConnectionBoundOidcTransport {
    private final RestTemplate restOperations;

    public ConnectionBoundOidcTransport(OidcNetworkAddressPolicy policy) {
        DnsResolver resolver = new DnsResolver() {
            @Override
            public InetAddress[] resolve(String host) {
                return policy.resolveApproved(host);
            }

            @Override
            public String resolveCanonicalHostname(String host) {
                return host;
            }
        };
        var manager = PoolingHttpClientConnectionManagerBuilder.create()
                .setDnsResolver(resolver)
                .setDefaultConnectionConfig(ConnectionConfig.custom()
                        .setConnectTimeout(Timeout.ofSeconds(3))
                        .setSocketTimeout(Timeout.ofSeconds(5))
                        .setValidateAfterInactivity(TimeValue.ofSeconds(5))
                        .build())
                .build();
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectionRequestTimeout(Timeout.ofSeconds(2))
                .setResponseTimeout(Timeout.ofSeconds(5))
                .build();
        CloseableHttpClient client = HttpClients.custom()
                .setConnectionManager(manager)
                .setDefaultRequestConfig(requestConfig)
                .evictExpiredConnections()
                .evictIdleConnections(TimeValue.ofSeconds(30))
                .disableRedirectHandling()
                .build();
        this.restOperations = new RestTemplate(new HttpComponentsClientHttpRequestFactory(client));
    }

    public RestOperations restOperations() {
        return restOperations;
    }
}
