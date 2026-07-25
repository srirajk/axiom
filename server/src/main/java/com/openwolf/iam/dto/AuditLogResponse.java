package com.openwolf.iam.dto;

import java.time.Instant;
import java.util.UUID;

public record AuditLogResponse(
        UUID id,
        String tenantId,
        String actorId,
        String clientId,
        String action,
        String resourceType,
        String resourceId,
        Object beforeState,
        Object afterState,
        String sourceIp,
        Instant occurredAt
) {}
