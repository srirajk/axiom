package com.openwolf.iam.dto;

import jakarta.validation.constraints.NotBlank;

import java.util.List;

public record CreateGroupRequest(
        @NotBlank(message = "name is required") String name,
        String domainId,
        String description,
        List<String> defaultRoles,
        List<String> segments,
        List<String> allowedDomains
) {}
