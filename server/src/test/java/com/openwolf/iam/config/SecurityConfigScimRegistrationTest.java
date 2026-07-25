package com.openwolf.iam.config;

import com.openwolf.iam.scim.ScimAuthenticationFilter;
import com.openwolf.iam.config.S256PkceEnforcementFilter;
import org.junit.jupiter.api.Test;
import org.springframework.boot.web.servlet.FilterRegistrationBean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class SecurityConfigScimRegistrationTest {
    @Test
    void disablesBootGlobalRegistrationForTheChainOnlyScimFilter() {
        SecurityConfig config = new SecurityConfig(mock(S256PkceEnforcementFilter.class), null, null, null,
                mock(ScimAuthenticationFilter.class), null);
        FilterRegistrationBean<ScimAuthenticationFilter> registration = config.scimAuthenticationFilterRegistration();

        assertThat(registration.isEnabled()).isFalse();
    }
}
