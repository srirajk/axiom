package com.openwolf.iam.dto;

/** The service secret is populated only for create/rotation responses and is never persisted in this DTO. */
public record CreatedTenantApplicationClientResponse(TenantApplicationClientResponse client, String serviceSecret) {}
