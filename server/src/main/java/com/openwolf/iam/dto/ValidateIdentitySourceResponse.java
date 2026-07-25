package com.openwolf.iam.dto;

import java.util.List;

public record ValidateIdentitySourceResponse(
        String issuer, String authorizationEndpoint, String tokenEndpoint, String userinfoEndpoint,
        String jwksUri, List<String> supportedSigningAlgorithms, List<String> supportedClaims,
        List<String> supportedAcrValues) {}
