package com.openwolf.iam.dto;

import com.openwolf.iam.entity.TenantApplication;
import java.time.Instant;
import java.util.UUID;

public record TenantApplicationResponse(UUID id, String tenantId, String applicationKey, String displayName,
                                        String description, String audience, TenantApplication.Status status,
                                        long revision, Instant createdAt, Instant updatedAt) {}
