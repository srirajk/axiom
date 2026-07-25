package com.openwolf.iam.dto;

import jakarta.validation.constraints.NotBlank;

public record CreatePolicyRequest(
        @NotBlank(message = "name is required") String name,
        String resourceType,
        @NotBlank(message = "content is required") String content
) {}
