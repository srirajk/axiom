package com.openwolf.iam.dto;

import com.openwolf.iam.entity.TenantApplicationClient;
import jakarta.validation.constraints.*;
import java.util.List;

public record TrustedClientRequest(@NotBlank @Size(max=2048) String clientId,
        @NotEmpty @Size(max=32) List<String> redirectUris,
        @NotBlank @Pattern(regexp="none|private_key_jwt") String tokenEndpointAuthMethod,
        List<String> scopes, Boolean refreshTokens, Long refreshTokenTtlSeconds,
        TenantApplicationClient.Population population, @Size(max=80) String displayName,
        Long accessTokenTtlSeconds, Long expectedRevision) {}
