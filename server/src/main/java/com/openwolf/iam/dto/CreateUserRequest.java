package com.openwolf.iam.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

import java.util.Map;

public record CreateUserRequest(
        @NotBlank(message = "id is required") String id,
        @NotBlank(message = "username is required") String username,
        @Email(message = "email must be valid") String email,
        @NotBlank(message = "password is required") String password,
        Map<String, Object> attributes
) {}
