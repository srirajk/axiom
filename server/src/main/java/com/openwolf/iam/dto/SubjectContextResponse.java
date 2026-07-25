package com.openwolf.iam.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/** Frozen v1 application-bound live subject context. */
public record SubjectContextResponse(
        @JsonProperty("contract_version") String contractVersion,
        @JsonProperty("request_id") String requestId,
        @JsonProperty("subject_id") String subjectId,
        @JsonProperty("tenant_id") String tenantId,
        boolean active,
        List<String> roles,
        List<String> domains,
        Map<String, Object> attributes,
        @JsonProperty("entitlement_revision") String entitlementRevision,
        @JsonProperty("resolved_at") Instant resolvedAt) {
}
