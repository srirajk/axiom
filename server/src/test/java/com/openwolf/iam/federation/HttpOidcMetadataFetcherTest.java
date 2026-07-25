package com.openwolf.iam.federation;

import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class HttpOidcMetadataFetcherTest {
    @Test
    void blocksRestrictedResolvedAddressesUnlessExplicitHostAllowlisted() throws Exception {
        assertThat(HttpOidcMetadataFetcher.isBlockedAddress(InetAddress.getByName("127.0.0.1"))).isTrue();
        assertThat(HttpOidcMetadataFetcher.isBlockedAddress(InetAddress.getByName("169.254.169.254"))).isTrue();
        assertThat(HttpOidcMetadataFetcher.isBlockedAddress(InetAddress.getByName("10.0.0.4"))).isTrue();
        assertThatThrownBy(() -> HttpOidcMetadataFetcher.requireSafeResolution("localhost", Set.of()))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("restricted");
        HttpOidcMetadataFetcher.requireSafeResolution("localhost", Set.of("localhost"));
    }

    @Test
    void rejectsNonHttpsOrQueryDiscoveryUris() {
        assertThatThrownBy(() -> HttpOidcMetadataFetcher.requireSafeHttps(java.net.URI.create("http://idp.example.test/discovery")))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("HTTPS");
        assertThatThrownBy(() -> HttpOidcMetadataFetcher.requireSafeHttps(java.net.URI.create("https://idp.example.test/discovery?x=1")))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("query-free");
    }
}
