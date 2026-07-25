package com.openwolf.iam.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/** Frozen v1 service subject-context request; authentication context is correlation evidence only. */
@JsonIgnoreProperties(ignoreUnknown = false)
public record SubjectContextRequest(
        @JsonProperty("contract_version") @NotBlank String contractVersion,
        @JsonProperty("request_id") @NotBlank String requestId,
        @JsonProperty("subject_id") @NotBlank String subjectId,
        @JsonProperty("tenant_id") @NotBlank String tenantId,
        @JsonProperty("authentication_context") @NotNull @Valid AuthenticationContext authenticationContext) {
    @JsonIgnoreProperties(ignoreUnknown = false)
    public record AuthenticationContext(@NotBlank String issuer,
                                        @JsonProperty("authenticated_at") @NotBlank String authenticatedAt,
                                        @JsonProperty("token_fingerprint") @NotBlank String tokenFingerprint) {}
}
