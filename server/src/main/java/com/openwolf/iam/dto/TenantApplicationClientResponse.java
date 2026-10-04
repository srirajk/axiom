package com.openwolf.iam.dto;

import com.openwolf.iam.entity.TenantApplicationClient;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** Deliberately contains no service secret, stored client-secret hash or key material beyond public key ids. */
public record TenantApplicationClientResponse(UUID id, String clientId, TenantApplicationClient.Type clientType,
                                              TenantApplicationClient.Status status, List<String> scopes,
                                              List<String> redirectUris, List<String> postLogoutRedirectUris,
                                              List<String> grantTypes, boolean pkceRequired, long revision,
                                              Instant createdAt, Instant updatedAt,
                                              TenantApplicationClient.Population population,
                                              List<String> tokenEndpointAuthMethods,
                                              long accessTokenTtlSeconds, Long refreshTokenTtlSeconds,
                                              boolean consentRequired, List<String> publicKeyIds) {

    public TenantApplicationClientResponse(UUID id, String clientId, TenantApplicationClient.Type clientType,
                                           TenantApplicationClient.Status status, List<String> scopes,
                                           List<String> redirectUris, List<String> postLogoutRedirectUris,
                                           List<String> grantTypes, boolean pkceRequired, long revision,
                                           Instant createdAt, Instant updatedAt) {
        this(id, clientId, clientType, status, scopes, redirectUris, postLogoutRedirectUris, grantTypes, pkceRequired,
                revision, createdAt, updatedAt, TenantApplicationClient.Population.WORKFORCE, List.of(), 0, null,
                false, List.of());
    }
}
