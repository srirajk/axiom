package com.openwolf.iam.controller;

import com.openwolf.iam.dto.RevokeTenantApplicationClientRequest;
import com.openwolf.iam.dto.RotateTenantApplicationClientSecretRequest;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;

import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;

/** Keeps the credential lifecycle routes tenant/platform-admin protected and explicit. */
class TenantApplicationCredentialControllerTest {
    @Test
    void rotationAndRevocationAreProtectedMutationRoutes() throws Exception {
        Method rotate = TenantApplicationController.class.getMethod("rotateSecret", String.class,
                java.util.UUID.class, java.util.UUID.class, RotateTenantApplicationClientSecretRequest.class,
                HttpServletRequest.class);
        Method revoke = TenantApplicationController.class.getMethod("revokeSecret", String.class,
                java.util.UUID.class, java.util.UUID.class, RevokeTenantApplicationClientRequest.class,
                HttpServletRequest.class);

        assertThat(rotate.getAnnotation(PreAuthorize.class).value()).isEqualTo("hasAnyRole('platform_admin','tenant_admin')");
        assertThat(revoke.getAnnotation(PreAuthorize.class).value()).isEqualTo("hasAnyRole('platform_admin','tenant_admin')");
        assertThat(rotate.getAnnotation(PostMapping.class).value()).containsExactly("/{applicationId}/clients/{clientId}/rotate-secret");
        assertThat(revoke.getAnnotation(PostMapping.class).value()).containsExactly("/{applicationId}/clients/{clientId}/revoke");
        assertThat(rotate.getReturnType()).isEqualTo(ResponseEntity.class);
        assertThat(revoke.getReturnType()).isEqualTo(ResponseEntity.class);
    }
}
