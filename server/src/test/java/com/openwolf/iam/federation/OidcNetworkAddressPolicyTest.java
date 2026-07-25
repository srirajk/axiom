package com.openwolf.iam.federation;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class OidcNetworkAddressPolicyTest {
    @Test
    void resolverRejectsRestrictedAddressUnlessExplicitlyAllowlisted() {
        assertThatThrownBy(() -> new OidcNetworkAddressPolicy("").resolveApproved("localhost"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("restricted");
        assertThat(new OidcNetworkAddressPolicy("localhost").resolveApproved("localhost"))
                .isNotEmpty();
    }
}
