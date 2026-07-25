package com.openwolf.iam.controller;

import org.junit.jupiter.api.Test;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;

import static org.assertj.core.api.Assertions.assertThat;

class IdentityControlRequestControllerTest {
    @Test
    void mutationRoutesRemainTenantOrPlatformAdminGated() throws Exception {
        assertThat(IdentityControlRequestController.class.getAnnotation(PreAuthorize.class).value())
                .isEqualTo("hasAnyRole('platform_admin','tenant_admin')");
        assertThat(IdentityControlRequestController.class.getMethod("approve", String.class, java.util.UUID.class,
                com.openwolf.iam.dto.IdentityControlTransitionRequest.class, jakarta.servlet.http.HttpServletRequest.class)
                .getAnnotation(PostMapping.class).value())
                .containsExactly("/{requestId}/approve");
        assertThat(IdentityControlRequestController.class.getMethod("apply", String.class, java.util.UUID.class,
                com.openwolf.iam.dto.IdentityControlTransitionRequest.class, jakarta.servlet.http.HttpServletRequest.class)
                .getAnnotation(PostMapping.class).value())
                .containsExactly("/{requestId}/apply");
    }
}
