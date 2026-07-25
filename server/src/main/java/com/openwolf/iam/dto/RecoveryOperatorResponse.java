package com.openwolf.iam.dto;

import com.openwolf.iam.entity.RecoveryOperator;

import java.time.Instant;
import java.util.UUID;

public record RecoveryOperatorResponse(UUID id, String tenantId, String principalId,
                                       RecoveryOperator.Status status, long revision,
                                       Instant createdAt, Instant updatedAt,
                                       String initiatorPrincipalId, String activationActorId, Instant activationAt,
                                       String oneTimeCredential) {}
