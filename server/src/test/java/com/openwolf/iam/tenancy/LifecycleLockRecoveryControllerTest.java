package com.openwolf.iam.tenancy;

import org.junit.jupiter.api.Test;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/** Verifies the protected recovery surface derives identity and tenant from the verified principal. */
class LifecycleLockRecoveryControllerTest {

    @Test
    void operatorAndApproverCallsUseAuthenticatedTenantAndActor() {
        LifecycleLockRecoveryService recovery = mock(LifecycleLockRecoveryService.class);
        LifecycleLockRecoveryController controller = new LifecycleLockRecoveryController(recovery);
        Authentication operator = authentication("operator-a");
        Authentication approver = authentication("approver-b");
        LifecycleLockRecoveryService.RecoveryResponse response = new LifecycleLockRecoveryService.RecoveryResponse(
                "corr-a", "evidence-hash", "owner-a", Instant.now().minusSeconds(60), false, 0,
                List.of(), "disk", "runtime-hash", "audit-hash");
        when(recovery.request("tenant-a", "operator-a")).thenReturn(response);
        when(recovery.approve("tenant-a", "corr-a", "approver-b")).thenReturn(response);

        assertThat(controller.request(operator).getBody()).isSameAs(response);
        assertThat(controller.approve("corr-a", approver).getBody()).isSameAs(response);
        verify(recovery).request("tenant-a", "operator-a");
        verify(recovery).approve("tenant-a", "corr-a", "approver-b");
    }

    @Test
    void endpointsKeepDistinctAxiomRoleGates() throws Exception {
        PreAuthorize requestGate = LifecycleLockRecoveryController.class
                .getMethod("request", Authentication.class).getAnnotation(PreAuthorize.class);
        PreAuthorize approvalGate = LifecycleLockRecoveryController.class
                .getMethod("approve", String.class, Authentication.class).getAnnotation(PreAuthorize.class);
        assertThat(requestGate.value()).isEqualTo("hasRole('platform_admin')");
        assertThat(approvalGate.value()).isEqualTo("hasAnyRole('security_reviewer', 'policy_approver')");
    }

    private static Authentication authentication(String actor) {
        Authentication auth = mock(Authentication.class);
        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .subject(actor)
                .claim("tenant_id", "tenant-a")
                .issuedAt(Instant.now().minusSeconds(5))
                .expiresAt(Instant.now().plusSeconds(300))
                .build();
        when(auth.getPrincipal()).thenReturn(jwt);
        when(auth.getName()).thenReturn(actor);
        return auth;
    }
}
