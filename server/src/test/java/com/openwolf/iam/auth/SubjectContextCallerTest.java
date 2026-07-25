package com.openwolf.iam.auth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import com.openwolf.iam.entity.TenantApplicationClient;
import com.openwolf.iam.service.TenantApplicationService;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SubjectContextCallerTest {
    private final TenantApplicationService applications = mock(TenantApplicationService.class);
    private final SubjectContextCaller caller = new SubjectContextCaller(applications);

    SubjectContextCallerTest() {
        when(applications.activeAuthority("sample-worker")).thenReturn(java.util.Optional.of(
                new TenantApplicationService.ClientAuthority("tenant-a", "sample-api",
                        TenantApplicationClient.Type.CONFIDENTIAL_SERVICE,
                        List.of(ApplicationScopes.SUBJECT_CONTEXT_READ))));
    }

    @BeforeEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void acceptsOnlyAnActiveRegisteredApplicationServiceToken() {
        authenticate(token("sample-worker", "sample-worker", "sample-api", "tenant-a",
                List.of(ApplicationScopes.SUBJECT_CONTEXT_READ)));

        assertThatCode(() -> caller.requireAuthorized("tenant-a")).doesNotThrowAnyException();
    }

    @Test
    void rejectsWrongClientAudienceScopeAndTenantWithoutDisclosingAssignments() {
        List<Runnable> invalid = List.of(
                () -> authenticate(token("axiom-admin", "axiom-admin", "axiom-api", "tenant-a",
                        List.of(ApplicationScopes.SUBJECT_CONTEXT_READ))),
                () -> authenticate(token("sample-worker", "sample-worker", "axiom-api", "tenant-a",
                        List.of(ApplicationScopes.SUBJECT_CONTEXT_READ))),
                () -> authenticate(token("sample-worker", "sample-worker", "sample-api", "tenant-a", List.of())),
                () -> authenticate(token("sample-worker", "sample-worker", "sample-api", "tenant-b",
                        List.of(ApplicationScopes.SUBJECT_CONTEXT_READ)))
        );

        for (Runnable setup : invalid) {
            setup.run();
            assertThatThrownBy(() -> caller.requireAuthorized("tenant-a"))
                    .isInstanceOf(AccessDeniedException.class);
        }
    }

    @Test
    void rejectsAnUnauthenticatedOrUnboundCaller() {
        assertThatThrownBy(() -> caller.requireAuthorized("tenant-a"))
                .isInstanceOf(AccessDeniedException.class);

        authenticate(token("sample-worker", "sample-worker", "sample-api", "tenant-a",
                List.of(ApplicationScopes.SUBJECT_CONTEXT_READ), "different-worker"));
        assertThatThrownBy(() -> caller.requireAuthorized("tenant-a"))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void rejectsABrowserClientEvenWhenItsJwtLooksLikeAnAccessToken() {
        when(applications.activeAuthority("browser-client")).thenReturn(java.util.Optional.of(
                new TenantApplicationService.ClientAuthority("tenant-a", "sample-api",
                        TenantApplicationClient.Type.PUBLIC_BROWSER,
                        List.of(ApplicationScopes.SUBJECT_CONTEXT_READ))));
        authenticate(token("browser-client", "browser-client", "sample-api", "tenant-a",
                List.of(ApplicationScopes.SUBJECT_CONTEXT_READ)));

        assertThatThrownBy(() -> caller.requireAuthorized("tenant-a"))
                .isInstanceOf(AccessDeniedException.class);
    }

    private void authenticate(Jwt jwt) {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(jwt, "n/a", List.of()));
    }

    private static Jwt token(String clientId, String subject, String audience, String tenant, List<String> scopes) {
        return token(clientId, subject, audience, tenant, scopes, null);
    }

    private static Jwt token(
            String clientId, String subject, String audience, String tenant, List<String> scopes, String azp) {
        Map<String, Object> claims = new java.util.HashMap<>();
        claims.put("client_id", clientId);
        claims.put("scope", scopes);
        claims.put("tenant_id", tenant);
        if (azp != null) claims.put("azp", azp);
        Instant now = Instant.now();
        return new Jwt("token", now, now.plusSeconds(60),
                Map.of("alg", "RS256", "typ", "at+jwt"),
                claimsWithSubject(claims, subject, audience, clientId));
    }

    private static Map<String, Object> claimsWithSubject(
            Map<String, Object> claims, String subject, String audience, String clientId) {
        claims.put("sub", subject);
        claims.put("aud", List.of(audience));
        claims.put("client_id", clientId);
        return claims;
    }
}
