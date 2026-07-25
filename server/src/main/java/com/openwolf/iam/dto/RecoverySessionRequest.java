package com.openwolf.iam.dto;

import jakarta.validation.constraints.NotBlank;

public record RecoverySessionRequest(@NotBlank String tenantId,
                                     @NotBlank String firstOperatorPrincipalId,
                                     @NotBlank String firstCredential,
                                     @NotBlank String secondOperatorPrincipalId,
                                     @NotBlank String secondCredential) {}
