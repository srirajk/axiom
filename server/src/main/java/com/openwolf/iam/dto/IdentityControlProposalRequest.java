package com.openwolf.iam.dto;

import com.fasterxml.jackson.databind.JsonNode;
import com.openwolf.iam.entity.IdentityControlRequest;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PositiveOrZero;

import java.util.UUID;

public record IdentityControlProposalRequest(
        @NotNull IdentityControlRequest.Action action,
        @NotNull IdentityControlRequest.TargetType targetType,
        @NotNull UUID targetId,
        JsonNode payload,
        @PositiveOrZero Long expectedTargetRevision) {}
