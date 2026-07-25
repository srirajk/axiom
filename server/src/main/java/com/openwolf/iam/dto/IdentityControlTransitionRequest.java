package com.openwolf.iam.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PositiveOrZero;

public record IdentityControlTransitionRequest(@NotNull @PositiveOrZero Long expectedRevision) {}
