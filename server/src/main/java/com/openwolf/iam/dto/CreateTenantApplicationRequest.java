package com.openwolf.iam.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/** AXP-1 tenant-owned application registration; application access assignments arrive in AXP-2. */
public record CreateTenantApplicationRequest(
        @NotBlank @Pattern(regexp = "[a-z][a-z0-9-]{1,62}") String applicationKey,
        @NotBlank String displayName,
        String description,
        @NotBlank @Pattern(regexp = "[a-z][a-z0-9.-]{1,127}") String audience) {}
