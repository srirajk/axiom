package com.openwolf.iam.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.openwolf.iam.auth.ExecutionTenant;
import com.openwolf.iam.dto.CreateTenantApplicationClientRequest;
import com.openwolf.iam.dto.CreatedTenantApplicationClientResponse;
import com.openwolf.iam.dto.IdentityControlApplyResponse;
import com.openwolf.iam.dto.IdentityControlProposalRequest;
import com.openwolf.iam.dto.RotateIdentitySourceSecretRequest;
import com.openwolf.iam.dto.RotateTenantApplicationClientSecretRequest;
import com.openwolf.iam.entity.IdentityControlRequest;
import com.openwolf.iam.entity.TenantApplication;
import com.openwolf.iam.entity.TenantApplicationClient;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.repository.IdentityControlRequestRepository;
import com.openwolf.iam.repository.IdentitySourceRepository;
import com.openwolf.iam.repository.ScimProvisioningSourceRepository;
import com.openwolf.iam.repository.SigningKeyRepository;
import com.openwolf.iam.repository.TenantApplicationClientRepository;
import com.openwolf.iam.repository.TenantApplicationRepository;
import com.openwolf.iam.repository.TenantRepository;
import com.openwolf.iam.security.SecretProtector;
import com.openwolf.iam.tenancy.ActiveTenantDirectory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Operator-supplied confidential-client secrets: validation, storage, approval-gated rotation and redaction. */
class OperatorSuppliedClientSecretTest {
    private static final String TENANT = "tenant-a";
    private static final Instant NOW = Instant.parse("2026-10-02T12:00:00Z");
    private static final String SECRET = secret();
    private static final String RECOVERY_ID = secret();
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(4);
    private final ObjectMapper json = new ObjectMapper();

    private final TenantApplicationRepository applications = mock(TenantApplicationRepository.class);
    private final TenantApplicationClientRepository clients = mock(TenantApplicationClientRepository.class);
    private final ActiveTenantDirectory activeTenants = mock(ActiveTenantDirectory.class);
    private final RegisteredClientRepository registeredClients = mock(RegisteredClientRepository.class);
    private final ExecutionTenant executionTenant = mock(ExecutionTenant.class);
    private final AuditService audit = mock(AuditService.class);
    private final TenantApplicationService service = new TenantApplicationService(applications, clients,
            mock(TenantRepository.class), activeTenants, registeredClients, encoder, executionTenant, audit);

    @AfterEach
    void clearSecurity() { SecurityContextHolder.clearContext(); }

    // -- format ------------------------------------------------------------------------------------------------------

    @Test
    void acceptsOnly43To64Base64urlCharactersWithBasicDiversity() {
        assertThat(OperatorSuppliedClientSecrets.requireValid(SECRET)).isEqualTo(SECRET);
        assertThat(OperatorSuppliedClientSecrets.requireValid(SECRET + "abcdefghijklmnopqrstu")).hasSize(64);
        for (String bad : List.of(SECRET.substring(0, 42), SECRET + "abcdefghijklmnopqrstuv", "a".repeat(50),
                SECRET.substring(0, 42) + "+", SECRET.substring(0, 42) + "/", SECRET.substring(0, 42) + "=",
                SECRET.substring(0, 42) + "é", " " + SECRET, "abababababababababababababababababababababab")) {
            assertThatThrownBy(() -> OperatorSuppliedClientSecrets.requireValid(bad))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage(OperatorSuppliedClientSecrets.FORMAT_MESSAGE)
                    .satisfies(e -> assertThat(e.getMessage()).doesNotContain(bad.trim()));
        }
        assertThatThrownBy(() -> OperatorSuppliedClientSecrets.requireValid(null)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rotationPayloadIsEmptyOrHasASecretAndIndependentRecoveryId() {
        JsonNodeFactory f = JsonNodeFactory.instance;
        assertThat(OperatorSuppliedClientSecrets.fromRotationPayload(null)).isNull();
        assertThat(OperatorSuppliedClientSecrets.fromRotationPayload(f.objectNode())).isNull();
        var payload = f.objectNode().put("clientSecret", SECRET).put("recoveryId", RECOVERY_ID);
        assertThat(OperatorSuppliedClientSecrets.fromRotationPayload(payload)).isEqualTo(SECRET);
        assertThat(OperatorSuppliedClientSecrets.payloadHash(payload, payload.toString()))
                .isEqualTo(sha256Unchecked("client-secret-rotation:" + RECOVERY_ID))
                .isNotEqualTo(sha256Unchecked(payload.toString()));
        assertThatThrownBy(() -> OperatorSuppliedClientSecrets.fromRotationPayload(
                f.objectNode().put("clientSecret", SECRET))).hasMessage(OperatorSuppliedClientSecrets.PAYLOAD_MESSAGE);
        assertThatThrownBy(() -> OperatorSuppliedClientSecrets.fromRotationPayload(
                f.objectNode().put("clientSecret", SECRET).put("recoveryId", RECOVERY_ID).put("other", "x")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> OperatorSuppliedClientSecrets.fromRotationPayload(
                f.objectNode().put("clientSecret", 7).put("recoveryId", RECOVERY_ID)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> OperatorSuppliedClientSecrets.fromRotationPayload(
                f.objectNode().put("clientSecret", "short").put("recoveryId", RECOVERY_ID)))
                .hasMessage(OperatorSuppliedClientSecrets.FORMAT_MESSAGE);
        assertThatThrownBy(() -> OperatorSuppliedClientSecrets.fromRotationPayload(
                f.objectNode().put("clientSecret", SECRET).put("recoveryId", "short")))
                .hasMessage(OperatorSuppliedClientSecrets.RECOVERY_ID_MESSAGE);
        assertThatThrownBy(() -> OperatorSuppliedClientSecrets.fromRotationPayload(f.arrayNode()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    // -- create --------------------------------------------------------------------------------------------------------

    @Test
    void createStoresTheSuppliedSecretHashedAndNeverReturnsIt() {
        TenantApplication app = activeApplication();
        CreatedTenantApplicationClientResponse created = service.createClient(TENANT, app.getId(), confidential(SECRET), null);

        assertThat(created.serviceSecret()).isNull();
        ArgumentCaptor<RegisteredClient> saved = ArgumentCaptor.forClass(RegisteredClient.class);
        verify(registeredClients).save(saved.capture());
        assertThat(saved.getValue().getClientSecret()).isNotEqualTo(SECRET);
        assertThat(encoder.matches(SECRET, saved.getValue().getClientSecret())).isTrue();
        assertThat(saved.getValue().getAuthorizationGrantTypes()).contains(AuthorizationGrantType.CLIENT_CREDENTIALS);
        assertThat(created.toString()).doesNotContain(SECRET);
    }

    @Test
    void createWithoutASuppliedSecretStillGeneratesAndReturnsOnce() {
        TenantApplication app = activeApplication();
        CreatedTenantApplicationClientResponse created = service.createClient(TENANT, app.getId(),
                new CreateTenantApplicationClientRequest("svc-a", TenantApplicationClient.Type.CONFIDENTIAL_SERVICE,
                        List.of(), List.of(), List.of("axiom.application.read")), null);
        assertThat(created.serviceSecret()).matches("[A-Za-z0-9_-]{43}");
    }

    @Test
    void publicClientsAndMalformedSecretsAreRejectedBeforeAnythingIsStored() {
        TenantApplication app = activeApplication();
        assertThatThrownBy(() -> service.createClient(TENANT, app.getId(),
                new CreateTenantApplicationClientRequest("web-a", TenantApplicationClient.Type.PUBLIC_BROWSER,
                        List.of("https://portal.example/cb"), List.of(), List.of("openid"), SECRET), null))
                .isInstanceOf(IllegalArgumentException.class).hasMessageNotContaining(SECRET);
        assertThatThrownBy(() -> service.createClient(TENANT, app.getId(), confidential("too-short"), null))
                .hasMessage(OperatorSuppliedClientSecrets.FORMAT_MESSAGE);
        verify(registeredClients, never()).save(any());
        verify(clients, never()).save(any());
        verify(audit, never()).logRequired(any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void auditRecordOfACreateNeverContainsTheSecret() throws Exception {
        TenantApplication app = activeApplication();
        service.createClient(TENANT, app.getId(), confidential(SECRET), null);
        ArgumentCaptor<Object> after = ArgumentCaptor.forClass(Object.class);
        verify(audit).logRequired(eq(TENANT), any(), eq("CREATE_APPLICATION_CLIENT"), any(), any(), isNull(),
                after.capture(), any());
        assertThat(new ObjectMapper().findAndRegisterModules().writeValueAsString(after.getValue())).doesNotContain(SECRET);
    }

    // -- rotation --------------------------------------------------------------------------------------------------------

    @Test
    void rotationToASuppliedSecretReplacesTheHashAndReturnsNothing() {
        TenantApplication app = activeApplication();
        TenantApplicationClient client = new TenantApplicationClient(app.getId(), "svc-a",
                TenantApplicationClient.Type.CONFIDENTIAL_SERVICE, List.of("axiom.application.read"));
        when(clients.findByIdAndApplicationId(client.getId(), app.getId())).thenReturn(Optional.of(client));
        when(registeredClients.findByClientId("svc-a")).thenReturn(registered("old-secret"));

        CreatedTenantApplicationClientResponse rotated = service.rotateClientSecret(TENANT, app.getId(), client.getId(),
                new RotateTenantApplicationClientSecretRequest(client.getRevision()), SECRET, null);

        assertThat(rotated.serviceSecret()).isNull();
        ArgumentCaptor<RegisteredClient> saved = ArgumentCaptor.forClass(RegisteredClient.class);
        verify(registeredClients).save(saved.capture());
        assertThat(encoder.matches(SECRET, saved.getValue().getClientSecret())).isTrue();
        assertThat(encoder.matches("old-secret", saved.getValue().getClientSecret())).isFalse();
    }

    @Test
    void approvedRotationAppliesTheEscrowedSecretWithoutReturningIt() throws Exception {
        IdentityControlFixture f = new IdentityControlFixture();
        String canonical = json.writeValueAsString(json.createObjectNode().put("clientSecret", SECRET).put("recoveryId", RECOVERY_ID));
        IdentityControlRequest request = f.approvedRotation(canonical);
        when(f.applications.rotateClientSecret(eq(TENANT), eq(f.client.getApplicationId()), eq(f.client.getId()),
                any(), eq(SECRET), any())).thenReturn(new CreatedTenantApplicationClientResponse(null, null));

        IdentityControlApplyResponse applied = f.service.apply(TENANT, request.getId(), request.getRevision(), null);

        assertThat(applied.oneTimeSecret()).isNull();
        verify(f.applications).rotateClientSecret(eq(TENANT), any(), any(), any(), eq(SECRET), any());
        assertThat(applied.toString()).doesNotContain(SECRET);
    }

    @Test
    void approvedRotationWithAMalformedStoredPayloadNeverRotates() throws Exception {
        IdentityControlFixture f = new IdentityControlFixture();
        IdentityControlRequest request = f.approvedRotation(
                json.writeValueAsString(json.createObjectNode().put("clientSecret", "weak")));
        assertThatThrownBy(() -> f.service.apply(TENANT, request.getId(), request.getRevision(), null))
                .isInstanceOf(ResourceConflictException.class).hasMessageNotContaining("weak");
        verify(f.applications, never()).rotateClientSecret(any(), any(), any(), any(), any(), any());
        verify(f.applications, never()).rotateClientSecret(any(), any(), any(), any(), any());
    }

    @Test
    void unapprovedRotationWithASuppliedSecretIsNotApplied() throws Exception {
        IdentityControlFixture f = new IdentityControlFixture();
        String canonical = json.writeValueAsString(json.createObjectNode().put("clientSecret", SECRET).put("recoveryId", RECOVERY_ID));
        IdentityControlRequest pending = new IdentityControlRequest(TENANT,
                IdentityControlRequest.Action.ROTATE_APPLICATION_CLIENT_SECRET,
                IdentityControlRequest.TargetType.APPLICATION_CLIENT, f.client.getId(), sha256(canonical), "ciphertext",
                "alice", NOW, NOW.plusSeconds(900), f.client.getRevision());
        when(f.requests.findForUpdateByIdAndTenantId(pending.getId(), TENANT)).thenReturn(Optional.of(pending));
        assertThatThrownBy(() -> f.service.apply(TENANT, pending.getId(), pending.getRevision(), null))
                .isInstanceOf(ResourceConflictException.class).hasMessageContaining("not approved");
        verify(f.applications, never()).rotateClientSecret(any(), any(), any(), any(), any(), any());
    }

    @Test
    void proposalValidatesTheReplacementBeforeStoringIt() {
        IdentityControlRequestRepository requests = mock(IdentityControlRequestRepository.class);
        SecretProtector protector = mock(SecretProtector.class);
        when(executionTenant.require()).thenReturn(TENANT);
        when(protector.protect(anyString())).thenReturn("ciphertext");
        when(requests.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("alice", "", "ROLE_tenant_admin"));
        IdentityControlRequestService proposals = new IdentityControlRequestService(requests, executionTenant, audit,
                protector, json, mock(IdentityControlRequestExpiryService.class), Clock.fixed(NOW, ZoneOffset.UTC), 900);
        UUID target = UUID.randomUUID();

        assertThatThrownBy(() -> proposals.propose(TENANT, proposal(target,
                json.createObjectNode().put("clientSecret", "weak")), null)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> proposals.propose(TENANT, proposal(target,
                json.createObjectNode().put("clientSecret", SECRET).put("extra", true)), null))
                .isInstanceOf(IllegalArgumentException.class);
        verify(requests, never()).save(any());

        var accepted = proposals.propose(TENANT, proposal(target,
                json.createObjectNode().put("clientSecret", SECRET).put("recoveryId", RECOVERY_ID)), null);
        verify(protector).protect(org.mockito.ArgumentMatchers.contains(SECRET));
        assertThat(accepted.toString()).doesNotContain(SECRET);
    }

    // -- redaction -------------------------------------------------------------------------------------------------------

    @Test
    void secretBearingRecordsNeverPrintTheirSecrets() {
        assertThat(confidential(SECRET).toString()).doesNotContain(SECRET).contains("[REDACTED]");
        assertThat(new CreatedTenantApplicationClientResponse(null, SECRET).toString()).doesNotContain(SECRET);
        assertThat(new IdentityControlApplyResponse(null, "ref", SECRET).toString()).doesNotContain(SECRET);
        assertThat(new RotateIdentitySourceSecretRequest(SECRET).toString()).doesNotContain(SECRET);
        assertThat(proposal(UUID.randomUUID(), json.createObjectNode().put("clientSecret", SECRET)).toString())
                .doesNotContain(SECRET).contains("payloadFields=[clientSecret]");
    }

    @Test
    void clientSecretIsReadFromJsonButNeverWritten() throws Exception {
        CreateTenantApplicationClientRequest parsed = json.readValue("""
                {"clientId":"svc-a","clientType":"CONFIDENTIAL_SERVICE","scopes":["x"],"clientSecret":"%s"}
                """.formatted(SECRET), CreateTenantApplicationClientRequest.class);
        assertThat(parsed.clientSecret()).isEqualTo(SECRET);
        assertThat(json.writeValueAsString(parsed)).doesNotContain(SECRET).doesNotContain("clientSecret");
    }

    // -- fixtures --------------------------------------------------------------------------------------------------------

    private TenantApplication activeApplication() {
        TenantApplication app = new TenantApplication(TENANT, "svc-app", "Service App", "", "svc-api");
        when(executionTenant.require()).thenReturn(TENANT);
        when(activeTenants.isActive(TENANT)).thenReturn(true);
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("admin", "", "ROLE_tenant_admin"));
        when(applications.findByIdAndTenantId(app.getId(), TENANT)).thenReturn(Optional.of(app));
        when(registeredClients.findByClientId(any())).thenReturn(null);
        when(clients.findByClientId(any())).thenReturn(Optional.empty());
        when(clients.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
        return app;
    }

    private static CreateTenantApplicationClientRequest confidential(String secret) {
        return new CreateTenantApplicationClientRequest("svc-a", TenantApplicationClient.Type.CONFIDENTIAL_SERVICE,
                List.of(), List.of(), List.of("axiom.application.read"), secret);
    }

    private RegisteredClient registered(String secret) {
        return RegisteredClient.withId(UUID.randomUUID().toString()).clientId("svc-a").clientSecret(encoder.encode(secret))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).build();
    }

    private static IdentityControlProposalRequest proposal(UUID target, com.fasterxml.jackson.databind.JsonNode payload) {
        return new IdentityControlProposalRequest(IdentityControlRequest.Action.ROTATE_APPLICATION_CLIENT_SECRET,
                IdentityControlRequest.TargetType.APPLICATION_CLIENT, target, payload, 1L);
    }

    private static String secret() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        String value = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        return value.chars().distinct().count() >= 16 ? value : secret();
    }

    private static String sha256(String value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    }

    private static String sha256Unchecked(String value) {
        try { return sha256(value); } catch (Exception ex) { throw new AssertionError(ex); }
    }

    /** IdentityControlApplyService with an approved rotation of one active confidential client. */
    private final class IdentityControlFixture {
        final IdentityControlRequestRepository requests = mock(IdentityControlRequestRepository.class);
        final TenantApplicationClientRepository clientRepository = mock(TenantApplicationClientRepository.class);
        final TenantApplicationRepository applicationRepository = mock(TenantApplicationRepository.class);
        final TenantApplicationService applications = mock(TenantApplicationService.class);
        final SecretProtector protector = mock(SecretProtector.class);
        final IdentityControlRequestExpiryService expiry = mock(IdentityControlRequestExpiryService.class);
        final TenantApplication app = new TenantApplication(TENANT, "svc-app", "Service App", "", "svc-api");
        final TenantApplicationClient client = new TenantApplicationClient(app.getId(), "svc-a",
                TenantApplicationClient.Type.CONFIDENTIAL_SERVICE, List.of("axiom.application.read"));
        final IdentityControlApplyService service;

        IdentityControlFixture() {
            when(executionTenant.require()).thenReturn(TENANT);
            SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("bob", "", "ROLE_tenant_admin"));
            when(clientRepository.findByIdForUpdate(client.getId())).thenReturn(Optional.of(client));
            when(applicationRepository.findById(app.getId())).thenReturn(Optional.of(app));
            service = new IdentityControlApplyService(requests, expiry, mock(IdentitySourceRepository.class),
                    mock(ScimProvisioningSourceRepository.class), mock(SigningKeyRepository.class), clientRepository,
                    applicationRepository, mock(IdentitySourceService.class), mock(ScimSourceService.class),
                    mock(SigningKeyLifecycleService.class), applications, executionTenant, audit, protector, json,
                    Clock.fixed(NOW, ZoneOffset.UTC));
        }

        IdentityControlRequest approvedRotation(String canonicalPayload) throws Exception {
            IdentityControlRequest request = new IdentityControlRequest(TENANT,
                    IdentityControlRequest.Action.ROTATE_APPLICATION_CLIENT_SECRET,
                    IdentityControlRequest.TargetType.APPLICATION_CLIENT, client.getId(),
                    canonicalPayload.contains("recoveryId")
                            ? OperatorSuppliedClientSecrets.payloadHash(json.readTree(canonicalPayload), canonicalPayload)
                            : sha256(canonicalPayload),
                    "ciphertext", "alice", NOW, NOW.plusSeconds(900), client.getRevision());
            request.approve("bob", NOW);
            when(protector.reveal("ciphertext")).thenReturn(canonicalPayload);
            when(requests.findForUpdateByIdAndTenantId(request.getId(), TENANT)).thenReturn(Optional.of(request));
            return request;
        }
    }
}
