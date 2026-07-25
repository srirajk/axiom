package com.openwolf.iam.controller;

import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.service.IdentitySourceService;
import com.openwolf.iam.service.ScimReconciliationService;
import com.openwolf.iam.service.ScimSourceService;
import com.openwolf.iam.service.SigningKeyLifecycleService;
import com.openwolf.iam.service.TenantApplicationService;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class IdentityControlNoBypassTest {
    private static final String TENANT = "tenant-a";
    private static final UUID ID = UUID.randomUUID();

    @Test
    void signingKeyEmergencyRetireRequiresApprovedRequest() {
        var controller = new SigningKeyController(mock(SigningKeyLifecycleService.class));
        assertThatThrownBy(() -> controller.emergencyRetire(TENANT, ID, null))
                .isInstanceOf(ResourceConflictException.class).hasMessageContaining("approval required");
    }

    @Test
    void identitySourceDangerousMutationsRequireApprovedRequest() {
        var controller = new IdentitySourceController(mock(IdentitySourceService.class));
        assertThatThrownBy(() -> controller.disable(TENANT, ID, null))
                .isInstanceOf(ResourceConflictException.class);
        assertThatThrownBy(() -> controller.rotateSecret(TENANT, ID, null, null))
                .isInstanceOf(ResourceConflictException.class);
    }

    @Test
    void applicationClientDangerousMutationsRequireApprovedRequest() {
        var controller = new TenantApplicationController(mock(TenantApplicationService.class));
        assertThatThrownBy(() -> controller.rotateSecret(TENANT, ID, ID, null, null))
                .isInstanceOf(ResourceConflictException.class);
        assertThatThrownBy(() -> controller.revokeSecret(TENANT, ID, ID, null, null))
                .isInstanceOf(ResourceConflictException.class);
    }

    @Test
    void scimCredentialDangerousMutationsRequireApprovedRequest() {
        var controller = new ScimSourceController(mock(ScimSourceService.class), mock(ScimReconciliationService.class));
        assertThatThrownBy(() -> controller.rotate(TENANT, ID, null))
                .isInstanceOf(ResourceConflictException.class);
        assertThatThrownBy(() -> controller.revoke(TENANT, ID, null))
                .isInstanceOf(ResourceConflictException.class);
    }
}
