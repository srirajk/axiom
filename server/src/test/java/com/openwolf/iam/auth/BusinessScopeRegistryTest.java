package com.openwolf.iam.auth;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BusinessScopeRegistryTest {
    @Test
    void exposesOnlyDeploymentApprovedBusinessScopes() {
        BusinessScopeRegistry registry = new BusinessScopeRegistry(
                "cards:incident.read,wealth:portfolio.review");
        assertThat(registry.isApproved("cards:incident.read")).isTrue();
        assertThat(registry.isApproved("cards:incident.write")).isFalse();
    }

    @Test
    void refusesReservedOrMalformedConfiguration() {
        assertThatThrownBy(() -> new BusinessScopeRegistry("axiom.platform-authz.decide"))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new BusinessScopeRegistry("wildcard-*"))
                .isInstanceOf(IllegalStateException.class);
    }
}
