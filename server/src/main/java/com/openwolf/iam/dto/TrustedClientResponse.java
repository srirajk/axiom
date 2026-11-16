package com.openwolf.iam.dto;
import com.openwolf.iam.entity.TenantApplicationClient;
import java.util.*;
public record TrustedClientResponse(UUID id, String clientId, String internalClientId, List<String> redirectUris, String tokenEndpointAuthMethod,
        List<String> scopes, boolean refreshTokens, Long refreshTokenTtlSeconds,
        TenantApplicationClient.Population population, TenantApplicationClient.Status status, long revision, String displayName,
        long accessTokenTtlSeconds, Map<String, List<String>> applications) {}
