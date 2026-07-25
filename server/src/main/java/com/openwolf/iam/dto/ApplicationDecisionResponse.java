package com.openwolf.iam.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record ApplicationDecisionResponse(
        @JsonProperty("contract_version") String contractVersion,
        @JsonProperty("request_id") String requestId,
        @JsonProperty("tenant_id") String tenantId,
        @JsonProperty("subject_id") String subjectId,
        @JsonProperty("entitlement_revision") String entitlementRevision,
        @JsonProperty("policy_bundle_id") String policyBundleId,
        @JsonProperty("evaluated_at") Instant evaluatedAt,
        List<Result> results) {
    public record Result(
            @JsonProperty("decision_key") String decisionKey,
            String outcome,
            boolean allowed,
            String effect,
            @JsonProperty("reason_codes") List<String> reasonCodes,
            @JsonProperty("call_id") UUID callId) {
    }
}
