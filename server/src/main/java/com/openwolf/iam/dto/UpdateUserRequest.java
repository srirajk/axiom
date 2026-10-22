package com.openwolf.iam.dto;

import java.util.Map;

/**
 * All fields are nullable — only provided fields are updated (PATCH semantics via PUT).
 */
public record UpdateUserRequest(
        String email,
        Boolean isActive,
        Map<String, Object> attributes,
        String givenName,
        String familyName,
        String name
) {
    public UpdateUserRequest(String email, Boolean isActive, Map<String, Object> attributes) {
        this(email, isActive, attributes, null, null, null);
    }
}
