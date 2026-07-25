package com.openwolf.iam.dto;

import com.openwolf.iam.entity.IdentityControlRequest;

import java.time.Instant;
import java.util.UUID;

public record IdentityControlRequestResponse(UUID id, String tenantId, IdentityControlRequest.Action action,
                                             IdentityControlRequest.TargetType targetType, UUID targetId,
                                             String payloadHash, String initiatorPrincipalId, Instant createdAt,
                                             Instant expiresAt, Long expectedTargetRevision,
                                             IdentityControlRequest.Status status, String approverPrincipalId,
                                             Instant approvedAt, String applicationResultReference, long revision) {}
