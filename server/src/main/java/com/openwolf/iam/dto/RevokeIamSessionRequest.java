package com.openwolf.iam.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PositiveOrZero;

public record RevokeIamSessionRequest(@NotNull @PositiveOrZero Long expectedRevision) {}
