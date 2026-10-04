package com.openwolf.iam.dto;

import com.openwolf.iam.entity.AgentWorkloadIdentity;
import com.openwolf.iam.entity.CustomerDelegationGrant;
import com.openwolf.iam.entity.CustomerIdentity;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

public final class CiamContracts {
    private CiamContracts() {}

    public record RegisterCustomerRequest(
            @Email @NotBlank String email,
            @NotBlank @Size(max = 200) String displayName,
            @NotBlank @Size(min = 12, max = 200) String password) {}

    /** Administrator provisioning: the identity starts pending verification; no code is returned to the operator. */
    public record ProvisionCustomerRequest(
            @Email @NotBlank String email,
            @NotBlank @Size(max = 200) String displayName,
            @NotBlank @Size(min = 12, max = 200) String initialPassword) {}

    public record ChallengeAction(String kind, String token, Instant expiresAt, String delivery) {}

    /** {@code codeDelivery} is QUEUED (provider) or LOCAL_DEMO; it never claims that a code was received. */
    public record RegistrationResponse(CustomerResponse customer, ChallengeAction localDemoAction, String codeDelivery) {}

    public record CustomerAuthenticationRequest(
            @Email @NotBlank String email,
            @NotBlank String password,
            @NotBlank @Size(max = 255) String clientId,
            @NotEmpty Set<@NotBlank @Size(max = 120) String> scopes) {}

    public record CustomerTokenResponse(String accessToken, String tokenType, long expiresIn,
                                        UUID customerId, String identityKind, String clientId,
                                        Set<String> scopes) {}

    public record TokenRequest(@NotBlank String token) {}

    public record RecoveryChallengeRequest(@Email @NotBlank String email) {}

    public record RecoveryChallengeResponse(boolean accepted, ChallengeAction localDemoAction, String codeDelivery) {}

    public record VerificationChallengeRequest(@Email @NotBlank String email) {}

    public record CompleteRecoveryRequest(
            @NotBlank String token,
            @NotBlank @Size(min = 12, max = 200) String newPassword) {}

    public record CustomerResponse(UUID customerId, String email, String displayName,
                                   CustomerIdentity.Status status, Instant emailVerifiedAt,
                                   Instant createdAt, long revision,
                                   CustomerIdentity.ProvisioningSource provisioningSource) {}

    public record RegisterAgentWorkloadRequest(
            @NotBlank @Size(max = 255) String workloadRef,
            @NotBlank @Size(max = 200) String name,
            @NotBlank @Size(max = 255) String oauthClientId) {}

    public record AgentWorkloadResponse(UUID id, String workloadRef, String name,
                                        String oauthClientId, AgentWorkloadIdentity.Status status,
                                        Instant createdAt, Instant revokedAt, long revision) {}

    public record AgentWorkloadConsentOption(UUID id, String workloadRef, String name,
                                             String audience, List<String> scopes) {}

    public record CreateDelegationGrantRequest(
            @NotNull UUID agentWorkloadId,
            @NotBlank @Size(max = 255) String audience,
            @NotEmpty Set<@NotBlank @Size(max = 120) String> scopes,
            @NotBlank @Size(max = 500) String purpose,
            @NotNull @Future Instant expiresAt,
            @Size(max = 64) String purposeCode) {}

    public record RevokeDelegationGrantRequest(@NotBlank @Size(max = 500) String reason) {}

    public record DelegationGrantResponse(
            UUID id, UUID customerId, UUID agentWorkloadId, String audience,
            List<String> scopes, String purpose, CustomerDelegationGrant.Status status,
            Instant consentRecordedAt, Instant expiresAt, Instant revokedAt,
            String revocationReason, long revision, String purposeCode, String consentSource) {}

    public record CiamLifecycleEventResponse(
            UUID id, String actorId, String eventType, String subjectType,
            String subjectId, String details, String correlationId, Instant occurredAt) {}
}
