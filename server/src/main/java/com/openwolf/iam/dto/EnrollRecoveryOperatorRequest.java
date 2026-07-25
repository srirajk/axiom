package com.openwolf.iam.dto;

import jakarta.validation.constraints.NotBlank;

public record EnrollRecoveryOperatorRequest(@NotBlank String principalId) {}
