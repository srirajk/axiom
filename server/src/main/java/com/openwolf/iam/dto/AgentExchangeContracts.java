package com.openwolf.iam.dto;

import com.openwolf.iam.entity.AgentExchangeRoute;
import com.openwolf.iam.entity.TrustedExchangeBroker;
import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

public final class AgentExchangeContracts {
    private AgentExchangeContracts() {}

    public record RegisterTrustedBrokerRequest(
            @NotBlank @Size(max = 255) String oauthClientId,
            @NotBlank @Size(max = 255) String gatewayAudience,
            @NotEmpty Set<@NotBlank @Size(max = 120) String> scopes) {}

    public record TrustedBrokerResponse(
            UUID id, String oauthClientId, String gatewayAudience, List<String> scopes,
            TrustedExchangeBroker.Status status, Instant createdAt, Instant revokedAt, long revision) {}

    public record CreateAgentExchangeRouteRequest(
            @NotNull UUID sourceWorkloadId,
            @NotNull AgentExchangeRoute.DestinationType destinationType,
            UUID destinationWorkloadId,
            @NotBlank @Size(max = 255) String audience,
            @NotEmpty Set<@NotBlank @Size(max = 120) String> scopes,
            @NotBlank @Size(max = 500) String purpose,
            @NotNull @Future Instant expiresAt) {}

    public record AgentExchangeRouteResponse(
            UUID id, UUID sourceWorkloadId, AgentExchangeRoute.DestinationType destinationType,
            UUID destinationWorkloadId, String audience, List<String> scopes, String purpose,
            AgentExchangeRoute.Status status, Instant createdAt, Instant expiresAt,
            Instant revokedAt, long revision) {}
}
