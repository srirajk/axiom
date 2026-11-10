package com.openwolf.iam.dto;

import com.openwolf.iam.entity.TenantApplicationClient;
import jakarta.validation.constraints.Size;
import java.util.List;

/**
 * Partial update of a tenant application client: an absent field is left unchanged. Mutable: {@code scopes},
 * {@code redirectUris} and {@code postLogoutRedirectUris} (browser clients), {@code displayName} and {@code enabled}.
 * {@code clientId} and {@code clientType} are accepted only to be checked against the stored values; they are immutable,
 * and so is the tenant and application binding. {@code expectedRevision}, when given, must match the stored revision.
 */
public record UpdateTenantApplicationClientRequest(
        String clientId,
        TenantApplicationClient.Type clientType,
        @Size(min = 1, max = 200) String displayName,
        List<String> scopes,
        List<String> redirectUris,
        List<String> postLogoutRedirectUris,
        Boolean enabled,
        Long expectedRevision) {}
