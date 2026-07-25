package com.openwolf.iam.dto;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Public user representation — password_hash is NEVER included.
 *
 * <p>{@code segments} is the ABAC per-segment clearance MAP {@code {segment -> data tier}}
 * (see AUTHZ-SPEC §1). Each key is a business segment the principal belongs to; each value is
 * the data-classification ceiling they hold <em>in that segment</em>. This mirrors exactly what
 * {@code OidcClaimEnricher} bakes into the access-token {@code segments} claim, so the admin
 * console can round-trip (render → edit → save) the same shape the gateway authorizes against.
 */
public record UserResponse(
        String id,
        String username,
        String email,
        boolean isActive,
        List<String> roles,
        Map<String, String> segments,
        String classification,
        List<String> adminDomains,
        Instant createdAt
) {}
