package com.openwolf.iam.authority.delivery;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** Which issuers count as loopback for the local-demo disclosure guard (Phase 3.1). */
class LocalDemoDisclosureGuardTest {

    @Test
    void onlyLoopbackIssuersQualify() {
        assertThat(LocalDemoDisclosureGuard.loopback("http://localhost:8084")).isTrue();
        assertThat(LocalDemoDisclosureGuard.loopback("http://LOCALHOST:8180")).isTrue();
        assertThat(LocalDemoDisclosureGuard.loopback("http://axiom.localhost")).isTrue();
        assertThat(LocalDemoDisclosureGuard.loopback("http://127.0.0.1:8084")).isTrue();
        assertThat(LocalDemoDisclosureGuard.loopback("http://127.8.9.10")).isTrue();
        assertThat(LocalDemoDisclosureGuard.loopback("http://[::1]:8084")).isTrue();

        assertThat(LocalDemoDisclosureGuard.loopback("https://axiom.example.test")).isFalse();
        assertThat(LocalDemoDisclosureGuard.loopback("http://localhost.example.test")).isFalse();
        assertThat(LocalDemoDisclosureGuard.loopback("http://10.0.0.5:8084")).isFalse();
        assertThat(LocalDemoDisclosureGuard.loopback("http://0.0.0.0:8084")).isFalse();
        assertThat(LocalDemoDisclosureGuard.loopback("http://[::]:8084")).isFalse();
        assertThat(LocalDemoDisclosureGuard.loopback("not a uri")).isFalse();
        assertThat(LocalDemoDisclosureGuard.loopback("")).isFalse();
    }
}
