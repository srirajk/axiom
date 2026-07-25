package com.openwolf.iam.dto;

import com.openwolf.iam.entity.IdentitySource;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** Redacted control-plane view; it deliberately contains no client secret or ciphertext. */
public record IdentitySourceResponse(
        UUID id, String tenantId, String displayName, String issuer, String discoveryUri,
        String authorizationEndpoint, String tokenEndpoint, String userinfoEndpoint, String jwksUri,
        String clientId, List<String> requestedScopes, List<String> allowedSigningAlgorithms,
        List<String> requiredClaims, List<String> requiredAcrValues, IdentitySource.Status status,
        long revision, Instant lastValidatedAt, Instant createdAt, Instant updatedAt) {}
