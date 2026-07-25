package com.openwolf.iam.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.Map;

/** Caller correlation stays opaque; permission strings are exact registered application-role permissions. */
@JsonIgnoreProperties(ignoreUnknown = false)
public record ApplicationDecisionItem(
        @JsonProperty("decision_key") @NotBlank String decisionKey,
        @NotBlank String permission,
        @NotNull @Valid ApplicationDecisionResource resource,
        @NotNull Map<String, Object> context) {
}
