package com.openwolf.iam.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.openwolf.iam.entity.TenantApplicationClient;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import java.util.List;
import java.util.Map;

/**
 * {@code clientSecret} is optional and only for confidential service clients: the operator-supplied secret, which the
 * caller escrows before the request. It is accepted on input only (never serialized) and never printed.
 *
 * <p>Optional IDP-baseline settings (all validated server-side; absent means the deployment default):
 * {@code population} (interactive clients: {@code WORKFORCE} or {@code CUSTOMER}), {@code accessTokenTtlSeconds}
 * (interactive clients), {@code refreshTokenTtlSeconds} (confidential web clients), {@code requireConsent}
 * (interactive clients: show the OAuth consent page), {@code tokenEndpointAuthMethod} ({@code client_secret_basic}
 * or, for confidential service clients, {@code private_key_jwt}) and {@code jwks} (the public keys for
 * {@code private_key_jwt}; private key material is refused).</p>
 */
public record CreateTenantApplicationClientRequest(
        @NotBlank @Pattern(regexp = "[a-z][a-z0-9-]{1,98}") String clientId,
        @NotNull TenantApplicationClient.Type clientType,
        List<String> redirectUris,
        List<String> postLogoutRedirectUris,
        List<String> scopes,
        @JsonProperty(access = JsonProperty.Access.WRITE_ONLY) String clientSecret,
        TenantApplicationClient.Population population,
        Long accessTokenTtlSeconds,
        Long refreshTokenTtlSeconds,
        Boolean requireConsent,
        String tokenEndpointAuthMethod,
        Map<String, Object> jwks) {

    public CreateTenantApplicationClientRequest(String clientId, TenantApplicationClient.Type clientType,
                                                List<String> redirectUris, List<String> postLogoutRedirectUris,
                                                List<String> scopes) {
        this(clientId, clientType, redirectUris, postLogoutRedirectUris, scopes, null);
    }

    public CreateTenantApplicationClientRequest(String clientId, TenantApplicationClient.Type clientType,
                                                List<String> redirectUris, List<String> postLogoutRedirectUris,
                                                List<String> scopes, String clientSecret) {
        this(clientId, clientType, redirectUris, postLogoutRedirectUris, scopes, clientSecret,
                null, null, null, null, null, null);
    }

    @Override
    public String toString() {
        return "CreateTenantApplicationClientRequest[clientId=" + clientId + ", clientType=" + clientType
                + ", population=" + population + ", redirectUris=" + redirectUris
                + ", postLogoutRedirectUris=" + postLogoutRedirectUris + ", scopes=" + scopes
                + ", tokenEndpointAuthMethod=" + tokenEndpointAuthMethod
                + ", clientSecret=" + (clientSecret == null ? "absent" : "[REDACTED]") + "]";
    }
}
