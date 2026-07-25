package com.openwolf.iam.dto;

import java.time.Instant;
import java.util.UUID;

public record PolicyResponse(
        UUID id,
        String name,
        String resourceType,
        String content,
        String status,
        Instant createdAt,
        Instant updatedAt
) {}
