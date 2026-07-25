package com.openwolf.iam.dto;

import java.util.Map;

/**
 * All fields are nullable — only provided fields are updated (PATCH semantics via PUT).
 */
public record UpdateUserRequest(
        String email,
        Boolean isActive,
        Map<String, Object> attributes
) {}
