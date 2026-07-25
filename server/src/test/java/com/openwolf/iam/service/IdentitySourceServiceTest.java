package com.openwolf.iam.service;

import com.openwolf.iam.auth.ExecutionTenant;
import com.openwolf.iam.dto.CreateExternalIdentityLinkRequest;
import com.openwolf.iam.entity.IdentitySource;
import com.openwolf.iam.entity.Principal;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.federation.OidcProviderValidator;
import com.openwolf.iam.repository.ExternalIdentityLinkRepository;
import com.openwolf.iam.repository.IdentitySourceRepository;
import com.openwolf.iam.repository.PrincipalRepository;
import com.openwolf.iam.security.SecretProtector;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;

class IdentitySourceServiceTest {
    private static final String TENANT = "tenant-a";
    private static final String ISSUER = "https://idp.example";

    @Test
    void acceptsOpaqueSubjectsWithoutEmailShapeHeuristics() {
        IdentitySource source = activeSource();
        IdentitySourceRepository sources = mock(IdentitySourceRepository.class);
        ExternalIdentityLinkRepository links = mock(ExternalIdentityLinkRepository.class);
        PrincipalRepository principals = mock(PrincipalRepository.class);
        when(sources.findByIdAndTenantId(source.getId(), TENANT)).thenReturn(Optional.of(source));
        when(principals.findByIdAndTenantId("principal-1", TENANT)).thenReturn(Optional.of(mock(Principal.class)));
        when(links.existsBySourceIdAndIssuerAndSubject(source.getId(), ISSUER, "user@example.com")).thenReturn(false);
        when(links.existsBySourceIdAndPrincipalId(source.getId(), "principal-1")).thenReturn(false);
        when(links.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        IdentitySourceService service = service(sources, links, principals);
        var result = service.link(TENANT, source.getId(),
                new CreateExternalIdentityLinkRequest(source.getId(), ISSUER, "user@example.com", "principal-1"), null);

        assertThat(result.subject()).isEqualTo("user@example.com");
    }

    @Test
    void rejectsSecondPrincipalLinkForTheSameSource() {
        IdentitySource source = activeSource();
        IdentitySourceRepository sources = mock(IdentitySourceRepository.class);
        ExternalIdentityLinkRepository links = mock(ExternalIdentityLinkRepository.class);
        PrincipalRepository principals = mock(PrincipalRepository.class);
        when(sources.findByIdAndTenantId(source.getId(), TENANT)).thenReturn(Optional.of(source));
        when(principals.findByIdAndTenantId("principal-1", TENANT)).thenReturn(Optional.of(mock(Principal.class)));
        when(links.existsBySourceIdAndIssuerAndSubject(source.getId(), ISSUER, "opaque-sub")).thenReturn(false);
        when(links.existsBySourceIdAndPrincipalId(source.getId(), "principal-1")).thenReturn(true);

        assertThatThrownBy(() -> service(sources, links, principals).link(TENANT, source.getId(),
                new CreateExternalIdentityLinkRequest(source.getId(), ISSUER, "opaque-sub", "principal-1"), null))
                .isInstanceOf(ResourceConflictException.class)
                .hasMessageContaining("already linked");
    }

    @Test
    void recordsStructuredAfterStateForSecretRotation() {
        IdentitySource source = activeSource();
        IdentitySourceRepository sources = mock(IdentitySourceRepository.class);
        ExternalIdentityLinkRepository links = mock(ExternalIdentityLinkRepository.class);
        PrincipalRepository principals = mock(PrincipalRepository.class);
        SecretProtector secrets = mock(SecretProtector.class);
        AuditService audit = mock(AuditService.class);
        ExecutionTenant executionTenant = mock(ExecutionTenant.class);
        when(executionTenant.require()).thenReturn(TENANT);
        when(sources.findByIdAndTenantId(source.getId(), TENANT)).thenReturn(Optional.of(source));
        when(secrets.protect("replacement-secret")).thenReturn("encrypted-secret");

        IdentitySourceService service = new IdentitySourceService(sources, links, principals,
                mock(OidcProviderValidator.class), secrets, audit, executionTenant);
        service.rotateSecret(TENANT, source.getId(),
                new com.openwolf.iam.dto.RotateIdentitySourceSecretRequest("replacement-secret"), null);

        ArgumentCaptor<Object> after = ArgumentCaptor.forClass(Object.class);
        verify(audit).logRequired(org.mockito.ArgumentMatchers.eq(TENANT), org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.eq("ROTATE_IDENTITY_SOURCE_SECRET"),
                org.mockito.ArgumentMatchers.eq("identity_source"), org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.isNull(), after.capture(), org.mockito.ArgumentMatchers.isNull());
        assertThat(after.getValue()).isEqualTo(java.util.Map.of("status", "rotated"));
    }

    private static IdentitySourceService service(IdentitySourceRepository sources,
                                                  ExternalIdentityLinkRepository links,
                                                  PrincipalRepository principals) {
        ExecutionTenant executionTenant = mock(ExecutionTenant.class);
        when(executionTenant.require()).thenReturn(TENANT);
        return new IdentitySourceService(sources, links, principals, mock(OidcProviderValidator.class),
                mock(SecretProtector.class), mock(AuditService.class), executionTenant);
    }

    private static IdentitySource activeSource() {
        IdentitySource source = new IdentitySource(TENANT, "Customer", ISSUER, ISSUER + "/.well-known/openid-configuration",
                "client", "ciphertext", List.of("openid"), List.of("RS256"),
                List.of("sub", "iss", "aud", "exp", "iat", "nonce"), List.of());
        source.applyValidatedMetadata(ISSUER + "/authorize", ISSUER + "/token", ISSUER + "/userinfo", ISSUER + "/jwks",
                java.time.Instant.now());
        source.activate();
        return source;
    }
}
