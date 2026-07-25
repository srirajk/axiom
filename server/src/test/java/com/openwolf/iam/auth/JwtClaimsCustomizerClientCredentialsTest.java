package com.openwolf.iam.auth;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwsHeader;
import com.openwolf.iam.entity.TenantApplicationClient;
import com.openwolf.iam.service.ApplicationAccessService;
import com.openwolf.iam.service.IamSessionService;
import com.openwolf.iam.service.TenantApplicationService;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.Map;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class JwtClaimsCustomizerClientCredentialsTest {
    @Test
    void unregisteredServiceClientCannotMintThroughLegacyConfiguration() {
        OidcClaimEnricher enricher = mock(OidcClaimEnricher.class);
        TenantApplicationService applications = mock(TenantApplicationService.class);
        ApplicationAccessService applicationAccess = mock(ApplicationAccessService.class);
        JwtClaimsCustomizer customizer = new JwtClaimsCustomizer(enricher, applications, applicationAccess);
        when(applications.activeAuthority("unregistered-worker")).thenReturn(Optional.empty());
        when(applications.knownButDisabled("unregistered-worker")).thenReturn(false);

        assertThatThrownBy(() -> customizer.jwtTokenCustomizer().customize(
                contextFor("unregistered-worker").context()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not registered");
        verify(enricher, never()).enrich("unregistered-worker");
    }

    @Test
    void applicationServiceClientDerivesTenantAndAudienceFromPersistedAuthority() {
        OidcClaimEnricher enricher = mock(OidcClaimEnricher.class);
        TenantApplicationService applications = mock(TenantApplicationService.class);
        ApplicationAccessService applicationAccess = mock(ApplicationAccessService.class);
        JwtClaimsCustomizer customizer = new JwtClaimsCustomizer(enricher, applications, applicationAccess);
        when(applications.activeAuthority("sample-worker")).thenReturn(Optional.of(
                new TenantApplicationService.ClientAuthority("tenant-b", "sample-api",
                        TenantApplicationClient.Type.CONFIDENTIAL_SERVICE, List.of("axiom.application.read"))));

        TokenContext fixture = contextFor("sample-worker");
        customizer.jwtTokenCustomizer().customize(fixture.context());

        Map<String, Object> claims = fixture.claims().build().getClaims();
        assertThat(claims).containsEntry("tenant_id", "tenant-b")
                .containsEntry("client_id", "sample-worker")
                .containsEntry("aud", List.of("sample-api"));
        verify(enricher, never()).enrich("sample-worker");
    }

    @Test
    void disabledApplicationClientCannotFallBackToLegacyTokenRules() {
        OidcClaimEnricher enricher = mock(OidcClaimEnricher.class);
        TenantApplicationService applications = mock(TenantApplicationService.class);
        ApplicationAccessService applicationAccess = mock(ApplicationAccessService.class);
        JwtClaimsCustomizer customizer = new JwtClaimsCustomizer(enricher, applications, applicationAccess);
        when(applications.activeAuthority("disabled-worker")).thenReturn(Optional.empty());
        when(applications.knownButDisabled("disabled-worker")).thenReturn(true);

        assertThatThrownBy(() -> customizer.jwtTokenCustomizer().customize(contextFor("disabled-worker").context()))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("disabled");
    }

    @Test
    void publicApplicationTokenUsesOnlyApplicationEntitlementsNotTenantWideRoles() {
        OidcClaimEnricher enricher = mock(OidcClaimEnricher.class);
        TenantApplicationService applications = mock(TenantApplicationService.class);
        ApplicationAccessService applicationAccess = mock(ApplicationAccessService.class);
        JwtClaimsCustomizer customizer = new JwtClaimsCustomizer(enricher, applications, applicationAccess);
        when(applications.activeAuthority("sample-portal")).thenReturn(Optional.of(
                new TenantApplicationService.ClientAuthority("tenant-a", "sample-api",
                        TenantApplicationClient.Type.PUBLIC_BROWSER, List.of("openid"))));
        when(applicationAccess.tokenClaims("sample-portal", "principal-a")).thenReturn(Map.of(
                "tenant_id", "tenant-a", "application_id", "sample-portal", "roles", List.of("reader"),
                "permissions", List.of("record.read"), "attributes", Map.of("region", "north"),
                "entitlement_revision", 3L));
        when(enricher.enrichIdToken("principal-a")).thenReturn(Map.of("email", "principal@example.test"));

        TokenContext fixture = contextFor("sample-portal", AuthorizationGrantType.AUTHORIZATION_CODE, "principal-a");
        customizer.jwtTokenCustomizer().customize(fixture.context());

        Map<String, Object> claims = fixture.claims().build().getClaims();
        assertThat(claims).containsEntry("roles", List.of("reader"))
                .containsEntry("permissions", List.of("record.read"))
                .containsEntry("aud", List.of("sample-api"))
                .doesNotContainValue("platform_admin");
        verify(enricher, never()).enrich("principal-a");
    }

    @Test
    void publicApplicationEntitlementDenialBecomesNonDisclosingInvalidGrant() {
        OidcClaimEnricher enricher = mock(OidcClaimEnricher.class);
        TenantApplicationService applications = mock(TenantApplicationService.class);
        ApplicationAccessService applicationAccess = mock(ApplicationAccessService.class);
        JwtClaimsCustomizer customizer = new JwtClaimsCustomizer(enricher, applications, applicationAccess);
        when(applications.activeAuthority("sample-portal")).thenReturn(Optional.of(
                new TenantApplicationService.ClientAuthority("tenant-a", "sample-api",
                        TenantApplicationClient.Type.PUBLIC_BROWSER, List.of("openid"))));
        when(applicationAccess.tokenClaims("sample-portal", "principal-a"))
                .thenThrow(new IllegalStateException("principal is not a member of this application"));

        assertThatThrownBy(() -> customizer.jwtTokenCustomizer().customize(
                contextFor("sample-portal", AuthorizationGrantType.AUTHORIZATION_CODE, "principal-a").context()))
                .isInstanceOfSatisfying(OAuth2AuthenticationException.class,
                        error -> assertThat(error.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_GRANT));
        verify(enricher, never()).enrich("principal-a");
    }

    @Test
    void accessTokenCarriesTheDurableAxiomSessionUuid() {
        OidcClaimEnricher enricher = mock(OidcClaimEnricher.class);
        TenantApplicationService applications = mock(TenantApplicationService.class);
        ApplicationAccessService applicationAccess = mock(ApplicationAccessService.class);
        IamSessionService sessions = mock(IamSessionService.class);
        JwtClaimsCustomizer customizer = new JwtClaimsCustomizer(enricher, applications, applicationAccess, sessions);
        UUID applicationId = UUID.randomUUID();
        UUID sessionId = UUID.randomUUID();
        when(applications.activeAuthority("sample-portal")).thenReturn(Optional.of(
                new TenantApplicationService.ClientAuthority("tenant-a", "sample-api",
                        TenantApplicationClient.Type.PUBLIC_BROWSER, List.of("openid"), applicationId)));
        when(applicationAccess.tokenClaims("sample-portal", "principal-a")).thenReturn(Map.of(
                "tenant_id", "tenant-a", "application_id", "sample-portal", "roles", List.of("reader"),
                "permissions", List.of("record.read"), "attributes", Map.of(), "entitlement_revision", 3L));
        when(enricher.enrichIdToken("principal-a")).thenReturn(Map.of());
        TokenContext fixture = sessionContextFor(OAuth2TokenType.ACCESS_TOKEN);
        when(sessions.issue(eq("authorization-a"), eq("tenant-a"), eq("principal-a"), eq(applicationId),
                eq("sample-portal"), any())).thenReturn(sessionId);

        customizer.jwtTokenCustomizer().customize(fixture.context());

        assertThat(fixture.claims().build().getClaims().get("sid")).isEqualTo(sessionId.toString());
    }

    @Test
    void idTokenPreservesTheFrameworkOidcLogoutSid() {
        OidcClaimEnricher enricher = mock(OidcClaimEnricher.class);
        TenantApplicationService applications = mock(TenantApplicationService.class);
        ApplicationAccessService applicationAccess = mock(ApplicationAccessService.class);
        IamSessionService sessions = mock(IamSessionService.class);
        JwtClaimsCustomizer customizer = new JwtClaimsCustomizer(enricher, applications, applicationAccess, sessions);
        UUID applicationId = UUID.randomUUID();
        when(applications.activeAuthority("sample-portal")).thenReturn(Optional.of(
                new TenantApplicationService.ClientAuthority("tenant-a", "sample-api",
                        TenantApplicationClient.Type.PUBLIC_BROWSER, List.of("openid"), applicationId)));
        when(enricher.enrichIdToken("principal-a")).thenReturn(Map.of("email", "principal@example.test"));
        TokenContext fixture = sessionContextFor(new OAuth2TokenType(OidcParameterNames.ID_TOKEN));
        fixture.claims().claim("sid", "framework-oidc-session");
        when(sessions.issue(eq("authorization-a"), eq("tenant-a"), eq("principal-a"), eq(applicationId),
                eq("sample-portal"), any())).thenReturn(UUID.randomUUID());

        customizer.jwtTokenCustomizer().customize(fixture.context());

        assertThat(fixture.claims().build().getClaims().get("sid")).isEqualTo("framework-oidc-session");
        verify(sessions).issue(eq("authorization-a"), eq("tenant-a"), eq("principal-a"), eq(applicationId),
                eq("sample-portal"), any());
    }

    private static TokenContext contextFor(String clientId) {
        return contextFor(clientId, AuthorizationGrantType.CLIENT_CREDENTIALS, clientId);
    }

    private static TokenContext contextFor(String clientId, AuthorizationGrantType grantType, String subject) {
        JwtEncodingContext context = mock(JwtEncodingContext.class);
        RegisteredClient client = mock(RegisteredClient.class);
        Authentication principal = mock(Authentication.class);
        when(context.getRegisteredClient()).thenReturn(client);
        when(client.getClientId()).thenReturn(clientId);
        when(context.getPrincipal()).thenReturn(principal);
        when(principal.getName()).thenReturn(subject);
        when(context.getTokenType()).thenReturn(OAuth2TokenType.ACCESS_TOKEN);
        when(context.getAuthorizationGrantType()).thenReturn(grantType);
        when(context.getJwsHeader()).thenReturn(JwsHeader.with(() -> "RS256"));
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder();
        when(context.getClaims()).thenReturn(claims);
        return new TokenContext(context, claims);
    }

    private static TokenContext sessionContextFor(OAuth2TokenType tokenType) {
        JwtEncodingContext context = mock(JwtEncodingContext.class);
        RegisteredClient client = mock(RegisteredClient.class);
        Authentication principal = mock(Authentication.class);
        OAuth2Authorization authorization = mock(OAuth2Authorization.class);
        when(context.getRegisteredClient()).thenReturn(client);
        when(client.getClientId()).thenReturn("sample-portal");
        when(client.getTokenSettings()).thenReturn(
                TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(15)).build());
        when(context.getPrincipal()).thenReturn(principal);
        when(principal.getName()).thenReturn("principal-a");
        when(context.getTokenType()).thenReturn(tokenType);
        when(context.getAuthorizationGrantType()).thenReturn(AuthorizationGrantType.AUTHORIZATION_CODE);
        when(context.getAuthorization()).thenReturn(authorization);
        when(authorization.getId()).thenReturn("authorization-a");
        when(context.getJwsHeader()).thenReturn(JwsHeader.with(() -> "RS256"));
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder();
        when(context.getClaims()).thenReturn(claims);
        return new TokenContext(context, claims);
    }

    private record TokenContext(JwtEncodingContext context, JwtClaimsSet.Builder claims) {}
}
