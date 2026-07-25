package com.openwolf.iam.dto;

import com.openwolf.iam.entity.TenantApplicationClient;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import java.util.List;

public record CreateTenantApplicationClientRequest(
        @NotBlank @Pattern(regexp = "[a-z][a-z0-9-]{1,98}") String clientId,
        @NotNull TenantApplicationClient.Type clientType,
        List<String> redirectUris,
        List<String> postLogoutRedirectUris,
        List<String> scopes) {}
