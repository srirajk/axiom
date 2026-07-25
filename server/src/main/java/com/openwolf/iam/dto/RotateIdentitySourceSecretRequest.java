package com.openwolf.iam.dto;

import jakarta.validation.constraints.NotBlank;

public record RotateIdentitySourceSecretRequest(@NotBlank String clientSecret) {}
