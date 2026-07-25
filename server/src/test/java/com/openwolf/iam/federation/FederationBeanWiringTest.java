package com.openwolf.iam.federation;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

class FederationBeanWiringTest {
    @Test
    void metadataBeansUseTheirExplicitProductionConstructors() {
        new ApplicationContextRunner()
                .withBean(ObjectMapper.class, ObjectMapper::new)
                .withBean(OidcNetworkAddressPolicy.class, () -> new OidcNetworkAddressPolicy(""))
                .withBean(ConnectionBoundOidcTransport.class)
                .withBean(HttpOidcMetadataFetcher.class)
                .withBean(OidcProviderValidator.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(HttpOidcMetadataFetcher.class);
                    assertThat(context).hasSingleBean(OidcProviderValidator.class);
                });
    }
}
