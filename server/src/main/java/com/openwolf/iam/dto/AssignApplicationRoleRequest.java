package com.openwolf.iam.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record AssignApplicationRoleRequest(
        @NotNull UUID roleId,
        @NotBlank String assignmentSource) {}
