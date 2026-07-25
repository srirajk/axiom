package com.openwolf.iam.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import jakarta.validation.constraints.NotBlank;

public record ImpersonateRequest(
        @JsonAlias("user_id")
        @NotBlank(message = "userId is required")
        String userId
) {}
