package com.openwolf.iam.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PositiveOrZero;

/** The caller's view of the client revision being rotated. */
public record RotateTenantApplicationClientSecretRequest(
        @NotNull @PositiveOrZero Long expectedRevision) {}
