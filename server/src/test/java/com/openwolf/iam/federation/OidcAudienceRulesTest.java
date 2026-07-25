package com.openwolf.iam.federation;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class OidcAudienceRulesTest {
    @Test
    void singletonAudienceAllowsAbsentOrMatchingAuthorizedParty() {
        assertThat(OidcAudienceRules.matches(List.of("client"), "client", null)).isTrue();
        assertThat(OidcAudienceRules.matches(List.of("client"), "client", "client")).isTrue();
    }

    @Test
    void singletonAudienceRejectsConflictingAuthorizedParty() {
        assertThat(OidcAudienceRules.matches(List.of("client"), "client", "other")).isFalse();
    }

    @Test
    void multipleAudiencesRequireMatchingAuthorizedParty() {
        assertThat(OidcAudienceRules.matches(List.of("client", "resource"), "client", "client")).isTrue();
        assertThat(OidcAudienceRules.matches(List.of("client", "resource"), "client", null)).isFalse();
        assertThat(OidcAudienceRules.matches(List.of("client", "resource"), "client", "other")).isFalse();
    }

    @Test
    void clientMustBeInAudience() {
        assertThat(OidcAudienceRules.matches(List.of("other"), "client", "client")).isFalse();
    }
}
