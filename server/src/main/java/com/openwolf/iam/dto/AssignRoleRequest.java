package com.openwolf.iam.dto;

import jakarta.validation.constraints.NotBlank;

public record AssignRoleRequest(
        @NotBlank(message = "roleId is required") String roleId
) {}
