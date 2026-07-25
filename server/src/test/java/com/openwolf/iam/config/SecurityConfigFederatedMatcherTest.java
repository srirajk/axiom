package com.openwolf.iam.config;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.util.matcher.RequestMatcher;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityConfigFederatedMatcherTest {
    @Test
    void includesOauth2AuthorizationStartAndExcludesUnrelatedApiRoutes() {
        RequestMatcher matcher = SecurityConfig.authorizationServerMatcher(request -> false);
        MockHttpServletRequest start = new MockHttpServletRequest("GET", "/oauth2/authorization/source.1");
        start.setServletPath("/oauth2/authorization/source.1");
        MockHttpServletRequest api = new MockHttpServletRequest("GET", "/api/users");
        api.setServletPath("/api/users");
        assertThat(matcher.matches(start)).isTrue();
        assertThat(matcher.matches(api)).isFalse();
    }
}
