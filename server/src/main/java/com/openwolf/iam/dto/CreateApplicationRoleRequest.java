package com.openwolf.iam.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

import java.util.List;
import java.util.Map;

public record CreateApplicationRoleRequest(
        @NotBlank @Pattern(regexp = "[a-z][a-z0-9_:-]{1,98}") String roleKey,
        @NotBlank String displayName,
        String description,
        List<@NotBlank String> permissions,
        Map<@NotBlank String, @NotBlank String> permissionEffects) {}
