package com.openwolf.iam.dto;

import java.time.Instant;
import java.util.UUID;

public record ScimSourceResponse(UUID id, String tenantId, String displayName, UUID identitySourceId,
                                 String selector, String status, long revision, Instant createdAt, Instant updatedAt,
                                 String bearerCredential) {}
