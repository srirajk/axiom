package com.openwolf.iam.controller;

import org.junit.jupiter.api.Test;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class IamSessionControllerTest {
    @Test
    void adminInventoryAndRevocationHaveAdminGates() throws Exception {
        var list = IamSessionController.class.getMethod("list", String.class, String.class, String.class,
                com.openwolf.iam.entity.IamSession.Status.class, int.class, int.class);
        var revoke = IamSessionController.class.getMethod("revoke", String.class, UUID.class,
                com.openwolf.iam.dto.RevokeIamSessionRequest.class, jakarta.servlet.http.HttpServletRequest.class);
        assertThat(list.getAnnotation(PreAuthorize.class).value()).isEqualTo("hasAnyRole('platform_admin','tenant_admin')");
        assertThat(revoke.getAnnotation(PreAuthorize.class).value()).isEqualTo("hasAnyRole('platform_admin','tenant_admin')");
        assertThat(list.getAnnotation(GetMapping.class).value()).containsExactly("/admin/tenants/{tenantId}/sessions");
        assertThat(revoke.getAnnotation(PostMapping.class).value()).containsExactly("/admin/tenants/{tenantId}/sessions/{sessionId}/revoke");
    }
}
