package com.openwolf.iam.dto;

import jakarta.validation.constraints.NotBlank;

public record RotateIdentitySourceSecretRequest(@NotBlank String clientSecret) {
    @Override
    public String toString() {
        return "RotateIdentitySourceSecretRequest[clientSecret=[REDACTED]]";
    }
}
