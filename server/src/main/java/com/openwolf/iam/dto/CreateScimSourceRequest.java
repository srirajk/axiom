package com.openwolf.iam.dto;

import jakarta.validation.constraints.NotBlank;
import java.util.UUID;

public record CreateScimSourceRequest(@NotBlank String displayName, UUID identitySourceId) {}
