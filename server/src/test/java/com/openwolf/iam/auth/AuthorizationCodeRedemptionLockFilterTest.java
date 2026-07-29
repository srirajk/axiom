package com.openwolf.iam.auth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthorizationCodeRedemptionLockFilterTest {
    private final StringRedisTemplate redis = mock(StringRedisTemplate.class);
    @SuppressWarnings("unchecked")
    private final ValueOperations<String, String> values = mock(ValueOperations.class);
    private AuthorizationCodeRedemptionLockFilter filter;

    @BeforeEach
    void setUp() {
        when(redis.opsForValue()).thenReturn(values);
        filter = new AuthorizationCodeRedemptionLockFilter(redis, "iam:oauth2", 0);
    }

    @Test
    void serializesAuthorizationCodeRedemptionAndReleasesOnlyItsOwnLock() throws Exception {
        when(values.setIfAbsent(anyString(), anyString(), eq(Duration.ofSeconds(30)))).thenReturn(true);
        MockHttpServletRequest request = codeRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        boolean[] proceeded = {false};

        filter.doFilter(request, response, (ignoredRequest, ignoredResponse) -> proceeded[0] = true);

        assertTrue(proceeded[0]);
        verify(redis).execute(any(), any(), anyString());
    }

    @Test
    void concurrentRedemptionFailsClosedWithoutReachingTokenProvider() throws Exception {
        when(values.setIfAbsent(anyString(), anyString(), eq(Duration.ofSeconds(30)))).thenReturn(false);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(codeRequest(), response, (ignoredRequest, ignoredResponse) -> {
            throw new AssertionError("contending redemption must not reach the token provider");
        });

        assertEquals(400, response.getStatus());
        assertEquals("{\"error\":\"invalid_grant\"}", response.getContentAsString());
        verify(redis, never()).execute(any(), any(), anyString());
    }

    @Test
    void ignoresOtherTokenGrantTypes() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest(
                "POST", AuthorizationCodeRedemptionLockFilter.TOKEN_ENDPOINT);
        request.setParameter("grant_type", "client_credentials");
        MockHttpServletResponse response = new MockHttpServletResponse();
        boolean[] proceeded = {false};

        filter.doFilter(request, response, (ignoredRequest, ignoredResponse) -> proceeded[0] = true);

        assertTrue(proceeded[0]);
        verify(redis, never()).opsForValue();
    }

    private static MockHttpServletRequest codeRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest(
                "POST", AuthorizationCodeRedemptionLockFilter.TOKEN_ENDPOINT);
        request.setParameter("grant_type", "authorization_code");
        request.setParameter("code", "opaque-code");
        return request;
    }
}
