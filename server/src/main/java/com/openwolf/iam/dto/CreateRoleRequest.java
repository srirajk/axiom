package com.openwolf.iam.dto;

import jakarta.validation.constraints.NotBlank;

import java.util.List;

public record CreateRoleRequest(
        @NotBlank(message = "name is required") String name,
        String description,
        List<String> permissions
) {}
