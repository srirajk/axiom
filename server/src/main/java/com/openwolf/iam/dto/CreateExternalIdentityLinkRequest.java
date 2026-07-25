package com.openwolf.iam.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.UUID;

public record CreateExternalIdentityLinkRequest(
        @NotNull UUID sourceId,
        @NotBlank String issuer,
        @NotBlank String subject,
        @NotBlank String principalId) {}
