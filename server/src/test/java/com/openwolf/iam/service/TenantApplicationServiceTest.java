package com.openwolf.iam.service;

import com.openwolf.iam.auth.ExecutionTenant;
import com.openwolf.iam.dto.CreateTenantApplicationClientRequest;
import com.openwolf.iam.dto.CreateTenantApplicationRequest;
import com.openwolf.iam.dto.CreatedTenantApplicationClientResponse;
import com.openwolf.iam.dto.RevokeTenantApplicationClientRequest;
import com.openwolf.iam.dto.RotateTenantApplicationClientSecretRequest;
import com.openwolf.iam.dto.TenantApplicationResponse;
import com.openwolf.iam.entity.Tenant;
import com.openwolf.iam.entity.TenantApplication;
import com.openwolf.iam.entity.TenantApplicationClient;
import com.openwolf.iam.exception.EntityNotFoundException;
import com.openwolf.iam.repository.TenantApplicationClientRepository;
import com.openwolf.iam.repository.TenantApplicationRepository;
import com.openwolf.iam.repository.TenantRepository;
import com.openwolf.iam.tenancy.ActiveTenantDirectory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.argThat;

class TenantApplicationServiceTest {
    private final TenantApplicationRepository applications = mock(TenantApplicationRepository.class);
    private final TenantApplicationClientRepository clients = mock(TenantApplicationClientRepository.class);
    private final TenantRepository tenants = mock(TenantRepository.class);
    private final ActiveTenantDirectory activeTenants = mock(ActiveTenantDirectory.class);
    private final RegisteredClientRepository registeredClients = mock(RegisteredClientRepository.class);
    private final ExecutionTenant executionTenant = mock(ExecutionTenant.class);
    private final TenantApplicationService service = new TenantApplicationService(applications, clients, tenants, activeTenants,
            registeredClients, new BCryptPasswordEncoder(), executionTenant, mock(AuditService.class));

    @AfterEach
    void clearSecurity() { SecurityContextHolder.clearContext(); }

    @Test
    void createsPublicAndConfidentialClientsWithServerOwnedPostureAndOneTimeSecret() {
        TenantApplication application = application();
        authorizeTenant("tenant-a");
        when(applications.findByIdAndTenantId(application.getId(), "tenant-a")).thenReturn(Optional.of(application));
        when(registeredClients.findByClientId(any())).thenReturn(null);
        when(clients.findByClientId(any())).thenReturn(Optional.empty());
        when(clients.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        CreatedTenantApplicationClientResponse browser = service.createClient("tenant-a", application.getId(),
                new CreateTenantApplicationClientRequest("sample-portal", TenantApplicationClient.Type.PUBLIC_BROWSER,
                        List.of("https://portal.example/oidc/callback"), List.of(), List.of("openid", "profile")), null);
        CreatedTenantApplicationClientResponse machine = service.createClient("tenant-a", application.getId(),
                new CreateTenantApplicationClientRequest("sample-worker", TenantApplicationClient.Type.CONFIDENTIAL_SERVICE,
                        List.of(), List.of(), List.of("axiom.application.read")), null);

        assertThat(browser.serviceSecret()).isNull();
        assertThat(machine.serviceSecret()).isNotBlank();
        assertThat(machine.client().clientId()).isEqualTo("sample-worker");
        assertThat(machine.client().scopes()).containsExactly("axiom.application.read");
        assertThat(browser.client().redirectUris()).containsExactly("https://portal.example/oidc/callback");
        assertThat(browser.client().postLogoutRedirectUris()).isEmpty();
        assertThat(browser.client().grantTypes()).containsExactly("authorization_code");
        assertThat(browser.client().pkceRequired()).isTrue();
        assertThat(browser.client().createdAt()).isNotNull();
        assertThat(browser.client().updatedAt()).isNotNull();
        assertThat(machine.client().redirectUris()).isEmpty();
        assertThat(machine.client().grantTypes()).containsExactly("client_credentials");
        assertThat(machine.client().pkceRequired()).isFalse();
    }

    @Test
    void exposesApplicationLifecycleMetadataWithoutAnyClientSecretMaterial() {
        authorizeTenant("tenant-a");
        when(tenants.findById("tenant-a")).thenReturn(Optional.of(new Tenant("tenant-a", "Tenant A", "tenant-a", "[]")));
        when(applications.existsByTenantIdAndApplicationKey("tenant-a", "sample-portal")).thenReturn(false);
        when(applications.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        TenantApplicationResponse response = service.create("tenant-a",
                new CreateTenantApplicationRequest("sample-portal", "Sample Portal", "", "sample-api"), null);

        assertThat(response.createdAt()).isNotNull();
        assertThat(response.updatedAt()).isNotNull();
    }

    @Test
    void rejectsWrongScopeAndRedirectPosture() {
        TenantApplication application = application();
        authorizeTenant("tenant-a");
        when(applications.findByIdAndTenantId(application.getId(), "tenant-a")).thenReturn(Optional.of(application));
        when(registeredClients.findByClientId(any())).thenReturn(null);
        when(clients.findByClientId(any())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.createClient("tenant-a", application.getId(),
                new CreateTenantApplicationClientRequest("bad-browser", TenantApplicationClient.Type.PUBLIC_BROWSER,
                        List.of("https://portal.example/callback"), List.of(), List.of("axiom.application.read")), null))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("scopes");
        assertThatThrownBy(() -> service.createClient("tenant-a", application.getId(),
                new CreateTenantApplicationClientRequest("bad-service", TenantApplicationClient.Type.CONFIDENTIAL_SERVICE,
                        List.of("https://portal.example/callback"), List.of(), List.of()), null))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("redirects");
    }

    @Test
    void rejectsCrossTenantReadsAndDisabledClientsAtTokenTime() {
        authorizeTenant("tenant-a");
        assertThatThrownBy(() -> service.list("tenant-b")).isInstanceOf(EntityNotFoundException.class);

        TenantApplication application = application();
        TenantApplicationClient client = new TenantApplicationClient(application.getId(), "sample-worker",
                TenantApplicationClient.Type.CONFIDENTIAL_SERVICE, List.of("axiom.application.read"));
        client.disable();
        when(clients.findByClientId("sample-worker")).thenReturn(Optional.of(client));
        when(applications.findById(application.getId())).thenReturn(Optional.of(application));

        assertThat(service.activeAuthority("sample-worker")).isEmpty();
        assertThat(service.knownButDisabled("sample-worker")).isTrue();
    }

    @Test
    void rejectsHumanTokenForApplicationFromAnotherTenant() {
        TenantApplication application = application();
        when(activeTenants.isActive("tenant-a")).thenReturn(true);
        TenantApplicationClient client = new TenantApplicationClient(application.getId(), "sample-portal",
                TenantApplicationClient.Type.PUBLIC_BROWSER, List.of("openid"));
        when(clients.findByClientId("sample-portal")).thenReturn(Optional.of(client));
        when(applications.findById(application.getId())).thenReturn(Optional.of(application));

        assertThatThrownBy(() -> service.requireHumanClientTenant("sample-portal", "tenant-b"))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("tenant principal");
    }

    @Test
    void storesApprovedScopesAsJsonArrayValuesRatherThanAJsonEncodedString() throws NoSuchFieldException {
        Field scopes = TenantApplicationClient.class.getDeclaredField("allowedScopes");

        assertThat(scopes.getType()).isEqualTo(List.class);
        assertThat(scopes.getAnnotation(JdbcTypeCode.class).value()).isEqualTo(SqlTypes.JSON);
        TenantApplicationClient client = new TenantApplicationClient(application().getId(), "sample-worker",
                TenantApplicationClient.Type.CONFIDENTIAL_SERVICE, List.of("axiom.application.read"));
        assertThat(client.getAllowedScopes()).containsExactly("axiom.application.read");
    }

    @Test
    void rotatesOnlyConfidentialSecretAndReturnsPlaintextOnceWithRevisionGuard() {
        TenantApplication application = application();
        TenantApplicationClient client = serviceClient(application);
        RegisteredClient registered = registered("old-secret");
        authorizeTenant("tenant-a");
        when(applications.findByIdAndTenantId(application.getId(), "tenant-a")).thenReturn(Optional.of(application));
        when(clients.findByIdAndApplicationId(client.getId(), application.getId())).thenReturn(Optional.of(client));
        when(registeredClients.findByClientId("sample-worker")).thenReturn(registered);
        when(clients.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        CreatedTenantApplicationClientResponse rotated = service.rotateClientSecret("tenant-a", application.getId(),
                client.getId(), new RotateTenantApplicationClientSecretRequest(1L), null);

        assertThat(rotated.serviceSecret()).isNotBlank();
        assertThat(rotated.serviceSecret()).isNotEqualTo("old-secret");
        assertThat(passwordEncoder().matches(rotated.serviceSecret(), capturedRegisteredSecret(registered))).isFalse();
        verify(registeredClients).save(argThat(saved -> passwordEncoder().matches(rotated.serviceSecret(), saved.getClientSecret())
                && !passwordEncoder().matches("old-secret", saved.getClientSecret())));
        assertThat(rotated.client().revision()).isEqualTo(2);
        assertThatThrownBy(() -> service.rotateClientSecret("tenant-a", application.getId(), client.getId(),
                new RotateTenantApplicationClientSecretRequest(0L), null))
                .isInstanceOf(com.openwolf.iam.exception.ResourceConflictException.class)
                .hasMessageContaining("stale");
    }

    @Test
    void revocationDisablesServiceClientAndMakesStoredProtocolSecretUnusable() {
        TenantApplication application = application();
        TenantApplicationClient client = serviceClient(application);
        RegisteredClient registered = registered("old-secret");
        authorizeTenant("tenant-a");
        when(applications.findByIdAndTenantId(application.getId(), "tenant-a")).thenReturn(Optional.of(application));
        when(clients.findByIdAndApplicationId(client.getId(), application.getId())).thenReturn(Optional.of(client));
        when(registeredClients.findByClientId("sample-worker")).thenReturn(registered);
        when(clients.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        var revoked = service.revokeClientSecret("tenant-a", application.getId(), client.getId(),
                new RevokeTenantApplicationClientRequest(1L), null);

        assertThat(revoked.status()).isEqualTo(TenantApplicationClient.Status.DISABLED);
        assertThat(revoked.revision()).isEqualTo(2);
        assertThat(client.getStatus()).isEqualTo(TenantApplicationClient.Status.DISABLED);
        verify(registeredClients).save(argThat(saved -> !passwordEncoder().matches("old-secret", saved.getClientSecret())));
    }

    private TenantApplication application() {
        return new TenantApplication("tenant-a", "sample-portal", "Sample Portal", "", "sample-api");
    }

    private TenantApplicationClient serviceClient(TenantApplication application) {
        return new TenantApplicationClient(application.getId(), "sample-worker",
                TenantApplicationClient.Type.CONFIDENTIAL_SERVICE, List.of("axiom.application.read"));
    }

    private RegisteredClient registered(String secret) {
        return RegisteredClient.withId("registered-worker")
                .clientId("sample-worker").clientSecret(passwordEncoder().encode(secret))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("axiom.application.read").build();
    }

    private String capturedRegisteredSecret(RegisteredClient original) {
        return original.getClientSecret();
    }

    private BCryptPasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(); }

    private void authorizeTenant(String tenantId) {
        when(executionTenant.require()).thenReturn(tenantId);
        when(activeTenants.isActive(tenantId)).thenReturn(true);
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("admin", "", "ROLE_tenant_admin"));
    }
}
