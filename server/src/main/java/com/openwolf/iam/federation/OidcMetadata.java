package com.openwolf.iam.federation;

import java.net.URI;
import java.util.List;

public record OidcMetadata(
        String issuer, URI authorizationEndpoint, URI tokenEndpoint, URI userinfoEndpoint, URI jwksUri,
        List<String> idTokenSigningAlgorithms, List<String> scopes, List<String> claims,
        List<String> acrValues) {}
