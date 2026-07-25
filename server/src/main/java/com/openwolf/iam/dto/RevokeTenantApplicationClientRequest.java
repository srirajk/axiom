package com.openwolf.iam.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PositiveOrZero;

/** The caller's view of the client revision being emergency-revoked. */
public record RevokeTenantApplicationClientRequest(
        @NotNull @PositiveOrZero Long expectedRevision) {}
