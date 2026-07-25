package com.openwolf.iam.dto;

import java.util.List;
import java.util.UUID;

public record GroupResponse(
        UUID id,
        String name,
        String domainId,
        String description,
        int memberCount,
        String tenantId,
        List<String> defaultRoles,
        List<String> segments,
        List<String> allowedDomains
) {}
