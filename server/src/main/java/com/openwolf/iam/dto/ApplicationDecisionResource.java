package com.openwolf.iam.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.Map;

/** Frozen v1 resource envelope. Application resources stay owned by the calling application. */
@JsonIgnoreProperties(ignoreUnknown = false)
public record ApplicationDecisionResource(
        @NotBlank String kind,
        @NotBlank String id,
        @JsonProperty("tenant_id") @NotBlank String tenantId,
        @JsonProperty("domain") String domain,
        @JsonProperty("owner_subject_id") String ownerSubjectId,
        @NotNull Map<String, Object> attributes,
        @JsonProperty("disclosure_class") @NotBlank String disclosureClass) {
}
