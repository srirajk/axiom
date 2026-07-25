package com.openwolf.iam.dto;

import com.openwolf.iam.entity.TenantApplicationMembership;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public record ApplicationMembershipResponse(
        UUID id,
        String principalId,
        TenantApplicationMembership.Status status,
        Map<String, Object> attributes,
        List<String> roles,
        String assignmentSource,
        String assignedBy,
        long entitlementRevision,
        Instant createdAt,
        Instant updatedAt) {}
