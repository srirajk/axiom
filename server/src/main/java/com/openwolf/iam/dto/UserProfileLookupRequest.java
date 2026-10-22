package com.openwolf.iam.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import java.util.List;

public record UserProfileLookupRequest(
        @NotEmpty @Size(max = 200) List<@NotBlank String> subjects) {}
