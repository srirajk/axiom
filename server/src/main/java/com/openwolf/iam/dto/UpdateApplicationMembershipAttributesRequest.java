package com.openwolf.iam.dto;

import jakarta.validation.constraints.NotNull;

import java.util.Map;

public record UpdateApplicationMembershipAttributesRequest(
        @NotNull Map<String, Object> attributes) {}
