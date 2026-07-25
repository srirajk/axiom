package com.openwolf.iam.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;

import java.util.List;

/** Version-one, service-only application-access decision input. */
@JsonIgnoreProperties(ignoreUnknown = false)
public record ApplicationDecisionBatchRequest(
        @JsonProperty("contract_version") @NotBlank String contractVersion,
        @JsonProperty("tenant_id") @NotBlank String tenantId,
        @JsonProperty("subject_id") @NotBlank String subjectId,
        @JsonProperty("request_id") @NotBlank @Size(max = 128) String requestId,
        @JsonProperty("decisions") @NotEmpty @Size(max = 200) List<@Valid ApplicationDecisionItem> decisions) {
}
