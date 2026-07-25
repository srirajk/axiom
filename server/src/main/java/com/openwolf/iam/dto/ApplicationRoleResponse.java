package com.openwolf.iam.dto;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public record ApplicationRoleResponse(
        UUID id,
        String roleKey,
        String displayName,
        String description,
        List<String> permissions,
        Map<String, String> permissionEffects,
        Instant createdAt,
        Instant updatedAt) {}
