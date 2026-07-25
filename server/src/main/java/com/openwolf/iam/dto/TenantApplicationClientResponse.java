package com.openwolf.iam.dto;

import com.openwolf.iam.entity.TenantApplicationClient;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** Deliberately contains no service secret or stored client-secret hash. */
public record TenantApplicationClientResponse(UUID id, String clientId, TenantApplicationClient.Type clientType,
                                              TenantApplicationClient.Status status, List<String> scopes,
                                              List<String> redirectUris, List<String> postLogoutRedirectUris,
                                              List<String> grantTypes, boolean pkceRequired, long revision,
                                              Instant createdAt, Instant updatedAt) {}
