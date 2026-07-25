package com.openwolf.iam.controller;

import org.junit.jupiter.api.Test;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.GetMapping;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class RecoveryControllerContractTest {
    @Test
    void enrollmentIsAdminGatedAndSessionIssuanceHasDedicatedRoute() throws Exception {
        assertThat(RecoveryOperatorController.class.getAnnotation(PreAuthorize.class).value())
                .isEqualTo("hasAnyRole('platform_admin','tenant_admin')");
        assertThat(RecoverySessionController.class.getMethod("issue",
                com.openwolf.iam.dto.RecoverySessionRequest.class, jakarta.servlet.http.HttpServletRequest.class)
                .getAnnotation(PostMapping.class).value()).containsExactly("/auth/recovery/session");
        assertThat(new RecoverySessionController(mock(com.openwolf.iam.service.RecoverySessionService.class))).isNotNull();
        assertThat(RecoveryOperatorSelfController.class.getMethod("list").getAnnotation(GetMapping.class)).isNotNull();
    }
}
