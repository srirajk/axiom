package com.openwolf.iam.dto;

import com.openwolf.iam.entity.IamSession;

import java.time.Instant;
import java.util.UUID;

public record IamSessionResponse(UUID id, String tenantId, String principalId, UUID applicationId, String clientId,
                                 Instant issuedAt, Instant lastSeenAt, Instant expiresAt,
                                 IamSession.Status status, long revision,
                                 boolean recoveryMarked, String recoveryScope) {}
