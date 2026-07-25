package com.openwolf.iam.dto;

import jakarta.validation.constraints.NotBlank;

public record AddMemberRequest(
        @NotBlank(message = "userId is required") String userId
) {}
