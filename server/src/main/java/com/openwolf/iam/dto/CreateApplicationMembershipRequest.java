package com.openwolf.iam.dto;

import jakarta.validation.constraints.NotBlank;

public record CreateApplicationMembershipRequest(
        @NotBlank String principalId,
        @NotBlank String assignmentSource) {}
