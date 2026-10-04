package com.openwolf.iam.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.openwolf.iam.auth.ExecutionTenant;
import com.openwolf.iam.dto.IdentityControlProposalRequest;
import com.openwolf.iam.entity.IdentityControlRequest;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.repository.IdentityControlRequestRepository;
import com.openwolf.iam.repository.IdentitySourceRepository;
import com.openwolf.iam.repository.ScimProvisioningSourceRepository;
import com.openwolf.iam.repository.SigningKeyRepository;
import com.openwolf.iam.repository.TenantApplicationClientRepository;
import com.openwolf.iam.repository.TenantApplicationRepository;
import com.openwolf.iam.security.ConfiguredAesGcmSecretProtector;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Gate 1 credential boundary: no identity-control action stores or returns a digest that lets a reader test guesses
 * of a submitted secret; every action rejects payloads it cannot use before anything is stored.
 */
class IdentityControlCredentialBoundaryTest {
    private static final String TENANT = "tenant-a";
    private static final Instant NOW = Instant.parse("2026-10-02T12:00:00Z");
    private final ObjectMapper json = new ObjectMapper();
    private final ConfiguredAesGcmSecretProtector protector = new ConfiguredAesGcmSecretProtector(key());
    private final IdentityControlRequestRepository requests = mock(IdentityControlRequestRepository.class);
    private final ExecutionTenant executionTenant = mock(ExecutionTenant.class);
    private final AuditService audit = mock(AuditService.class);

    @AfterEach
    void clear() { SecurityContextHolder.clearContext(); }

    // -- keyed digest --------------------------------------------------------------------------------------------

    @Test
    void keyedDigestIsDeterministicPurposeAndKeyBoundAndNotAPlainHash() throws Exception {
        String value = "{\"clientSecret\":\"password1\"}";
        String digest = protector.keyedDigest("identity-control-payload", value);
        assertThat(digest).matches("[0-9a-f]{64}");
        assertThat(protector.keyedDigest("identity-control-payload", value)).isEqualTo(digest);
        assertThat(protector.keyedDigest("other-purpose", value)).isNotEqualTo(digest);
        assertThat(new ConfiguredAesGcmSecretProtector(key()).keyedDigest("identity-control-payload", value)).isNotEqualTo(digest);
        assertThat(digest).isNotEqualTo(sha256(value));
        assertThatThrownBy(() -> protector.keyedDigest(" ", value)).isInstanceOf(IllegalArgumentException.class);
    }

    // -- per-action payload validation ---------------------------------------------------------------------------

    @Test
    void everyActionRejectsPayloadsItCannotUseWithConstantMessages() {
        var f = json.getNodeFactory();
        String weak = "hunter2";
        // identity-source rotation: exactly one non-blank clientSecret of at most 4096 characters
        for (JsonNode bad : List.<JsonNode>of(f.objectNode(), f.objectNode().put("clientSecret", " "),
                f.objectNode().put("clientSecret", "x".repeat(4097)), f.objectNode().put("clientSecret", 7),
                f.objectNode().put("clientSecret", weak).put("extra", true), f.objectNode().put("secret", weak),
                f.arrayNode())) {
            assertThatThrownBy(() -> IdentityControlPayloads.validate(IdentityControlRequest.Action.ROTATE_IDENTITY_SOURCE_SECRET, bad))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage(IdentityControlPayloads.IDENTITY_SOURCE_SECRET_MESSAGE)
                    .satisfies(e -> assertThat(e.getMessage()).doesNotContain(weak));
        }
        IdentityControlPayloads.validate(IdentityControlRequest.Action.ROTATE_IDENTITY_SOURCE_SECRET,
                f.objectNode().put("clientSecret", weak));
        // generated mutations take no payload at all
        for (IdentityControlRequest.Action action : List.of(IdentityControlRequest.Action.EMERGENCY_RETIRE_SIGNING_KEY,
                IdentityControlRequest.Action.DISABLE_IDENTITY_SOURCE, IdentityControlRequest.Action.REVOKE_APPLICATION_CLIENT_SECRET,
                IdentityControlRequest.Action.REVOKE_SCIM_SOURCE, IdentityControlRequest.Action.ROTATE_SCIM_SOURCE_CREDENTIAL)) {
            IdentityControlPayloads.validate(action, f.objectNode());
            IdentityControlPayloads.validate(action, null);
            assertThatThrownBy(() -> IdentityControlPayloads.validate(action, f.objectNode().put("clientSecret", weak)))
                    .hasMessage(IdentityControlPayloads.EMPTY_PAYLOAD_MESSAGE);
        }
        // supplied application-client rotations still require the independent recovery identifier
        assertThatThrownBy(() -> IdentityControlPayloads.validate(IdentityControlRequest.Action.ROTATE_APPLICATION_CLIENT_SECRET,
                f.objectNode().put("clientSecret", supplied()))).isInstanceOf(IllegalArgumentException.class);
    }

    // -- proposal and apply ---------------------------------------------------------------------------------------

    @Test
    void identitySourceRotationStoresAndReturnsOnlyAKeyedDigest() throws Exception {
        IdentityControlRequestService service = proposals();
        String weak = "Winter2026!";
        JsonNode payload = json.createObjectNode().put("clientSecret", weak);
        var response = service.propose(TENANT, new IdentityControlProposalRequest(
                IdentityControlRequest.Action.ROTATE_IDENTITY_SOURCE_SECRET, IdentityControlRequest.TargetType.IDENTITY_SOURCE,
                UUID.randomUUID(), payload, 1L), null);

        String canonical = "{\"clientSecret\":\"" + weak + "\"}";
        assertThat(response.payloadHash()).isEqualTo(protector.keyedDigest(IdentityControlPayloads.DIGEST_PURPOSE, canonical))
                .isNotEqualTo(sha256(canonical));
        ArgumentCaptor<IdentityControlRequest> stored = ArgumentCaptor.forClass(IdentityControlRequest.class);
        verify(requests).save(stored.capture());
        assertThat(stored.getValue().getPayloadHash()).isEqualTo(response.payloadHash());
        assertThat(stored.getValue().getPayloadCiphertext()).doesNotContain(weak);
        assertThat(protector.reveal(stored.getValue().getPayloadCiphertext())).isEqualTo(canonical);
        assertThat(response.toString()).doesNotContain(weak);
    }

    @Test
    void malformedProposalsStoreNothing() {
        IdentityControlRequestService service = proposals();
        var f = json.getNodeFactory();
        assertThatThrownBy(() -> service.propose(TENANT, new IdentityControlProposalRequest(
                IdentityControlRequest.Action.ROTATE_IDENTITY_SOURCE_SECRET, IdentityControlRequest.TargetType.IDENTITY_SOURCE,
                UUID.randomUUID(), f.objectNode().put("clientSecret", "x").put("debug", "y"), 1L), null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.propose(TENANT, new IdentityControlProposalRequest(
                IdentityControlRequest.Action.REVOKE_SCIM_SOURCE, IdentityControlRequest.TargetType.SCIM_SOURCE,
                UUID.randomUUID(), f.objectNode().put("note", "x"), 1L), null)).isInstanceOf(IllegalArgumentException.class);
        verify(requests, never()).save(any());
    }

    @Test
    void applyRefusesALegacyOrTamperedDigestWithoutRotating() throws Exception {
        String canonical = "{\"clientSecret\":\"Winter2026!\"}";
        IdentitySourceService identitySources = mock(IdentitySourceService.class);
        for (String stored : List.of(sha256(canonical), "legacy-unkeyed-digest-removed",
                protector.keyedDigest("other-purpose", canonical))) {
            UUID target = UUID.randomUUID();
            IdentityControlRequest request = new IdentityControlRequest(TENANT,
                    IdentityControlRequest.Action.ROTATE_IDENTITY_SOURCE_SECRET, IdentityControlRequest.TargetType.IDENTITY_SOURCE,
                    target, stored, protector.protect(canonical), "alice", NOW, NOW.plusSeconds(900), 1L);
            request.approve("bob", NOW);
            when(requests.findForUpdateByIdAndTenantId(request.getId(), TENANT)).thenReturn(Optional.of(request));
            authorize("bob");
            IdentityControlApplyService apply = new IdentityControlApplyService(requests,
                    mock(IdentityControlRequestExpiryService.class), mock(IdentitySourceRepository.class),
                    mock(ScimProvisioningSourceRepository.class), mock(SigningKeyRepository.class),
                    mock(TenantApplicationClientRepository.class), mock(TenantApplicationRepository.class), identitySources,
                    mock(ScimSourceService.class), mock(SigningKeyLifecycleService.class), mock(TenantApplicationService.class),
                    executionTenant, audit, protector, json, Clock.fixed(NOW, ZoneOffset.UTC));
            assertThatThrownBy(() -> apply.apply(TENANT, request.getId(), request.getRevision(), null))
                    .isInstanceOf(ResourceConflictException.class).hasMessageContaining("hash mismatch");
        }
        verify(identitySources, never()).rotateSecret(any(), any(), any(), any());
    }

    // -- helpers ----------------------------------------------------------------------------------------------------

    private IdentityControlRequestService proposals() {
        authorize("alice");
        when(executionTenant.require()).thenReturn(TENANT);
        when(requests.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
        return new IdentityControlRequestService(requests, executionTenant, audit, protector, json,
                mock(IdentityControlRequestExpiryService.class), Clock.fixed(NOW, ZoneOffset.UTC), 900);
    }

    private void authorize(String user) {
        when(executionTenant.require()).thenReturn(TENANT);
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken(user, "", "ROLE_tenant_admin"));
    }

    private static String key() {
        byte[] b = new byte[32];
        new SecureRandom().nextBytes(b);
        return Base64.getEncoder().encodeToString(b);
    }

    private static String supplied() {
        byte[] b = new byte[32];
        new SecureRandom().nextBytes(b);
        String v = Base64.getUrlEncoder().withoutPadding().encodeToString(b);
        return v.chars().distinct().count() >= 16 ? v : supplied();
    }

    private static String sha256(String value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    }
}
