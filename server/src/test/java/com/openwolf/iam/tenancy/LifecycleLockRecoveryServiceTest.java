package com.openwolf.iam.tenancy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.openwolf.iam.entity.AuditLog;
import com.openwolf.iam.policystudio.lifecycle.PolicyBundleRepository;
import com.openwolf.iam.policystudio.lifecycle.PromotedBundleLoader;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/** Focused proof that recovery is based on server-observed artifacts and cannot issue false approval. */
class LifecycleLockRecoveryServiceTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private TenantLifecycleLockStore locks;
    private ActiveTenantDirectory directory;
    private TenantNamespaceAdapter namespaces;
    private AuditPartitionAdapter audit;
    private PolicyBundleRepository bundles;
    private PromotedBundleLoader runtime;
    private LifecycleLockRecoveryService service;

    @BeforeEach
    void setUp() {
        locks = mock(TenantLifecycleLockStore.class);
        directory = mock(ActiveTenantDirectory.class);
        namespaces = mock(TenantNamespaceAdapter.class);
        audit = mock(AuditPartitionAdapter.class);
        bundles = mock(PolicyBundleRepository.class);
        runtime = mock(PromotedBundleLoader.class);
        service = new LifecycleLockRecoveryService(locks, directory, namespaces, audit, bundles, runtime, mapper);
        when(locks.inspect("tenant-a")).thenReturn(Optional.of(
                new TenantLifecycleLockStore.LockObservation("owner-a", Instant.now().minusSeconds(60))));
        when(directory.find("tenant-a")).thenReturn(Optional.empty());
        when(namespaces.namespaceExists("tenant-a")).thenReturn(false);
        when(audit.export("tenant-a")).thenReturn(List.of());
        when(bundles.findByTenantIdOrderByCreatedAtDesc("tenant-a")).thenReturn(List.of());
        when(runtime.snapshot()).thenReturn(new PromotedBundleLoader.RuntimeStoreSnapshot(
                "disk", 0, "runtime-inventory", List.of()));
    }

    @Test
    void requestPersistsRuntimeAndAuditInventoryEvidence() throws Exception {
        LifecycleLockRecoveryService.RecoveryResponse response = service.request("tenant-a", "operator-a");

        ArgumentCaptor<String> payload = ArgumentCaptor.forClass(String.class);
        verify(audit).recordLifecycleLockRecoveryEvent(eq("tenant-a"), eq("operator-a"),
                eq(LifecycleLockRecoveryService.REQUESTED), anyString(), payload.capture());
        JsonNode envelope = mapper.readTree(payload.getValue());
        JsonNode evidence = envelope.path("evidence");
        assertThat(evidence.path("runtime_verified").asBoolean()).isTrue();
        assertThat(evidence.path("runtime_backend").asText()).isEqualTo("disk");
        assertThat(evidence.path("runtime_inventory_hash").asText()).isEqualTo("runtime-inventory");
        assertThat(evidence.path("audit_inventory_hash").asText()).isNotBlank();
        assertThat(evidence.path("directory_verified").asBoolean()).isTrue();
        assertThat(response.runtimeInventoryHash()).isEqualTo("runtime-inventory");
    }

    @Test
    void runtimeStoreFailureFailsClosedBeforeRecoveryRequest() {
        when(runtime.snapshot()).thenThrow(new ProvisioningException("runtime unavailable"));

        assertThatThrownBy(() -> service.request("tenant-a", "operator-a"))
                .isInstanceOf(ProvisioningException.class)
                .hasMessageContaining("runtime unavailable");
        verify(audit, never()).recordLifecycleLockRecoveryEvent(anyString(), anyString(), anyString(),
                anyString(), anyString());
    }

    @Test
    void approvalCannotBeRecordedWhenGuardedClearDoesNotCommit() throws Exception {
        LifecycleLockRecoveryService.RecoveryResponse requested = service.request("tenant-a", "operator-a");
        ArgumentCaptor<String> requestPayload = ArgumentCaptor.forClass(String.class);
        verify(audit).recordLifecycleLockRecoveryEvent(eq("tenant-a"), eq("operator-a"),
                eq(LifecycleLockRecoveryService.REQUESTED), eq(requested.correlationId()), requestPayload.capture());
        AuditLog request = new AuditLog("tenant-a", "operator-a", "system",
                LifecycleLockRecoveryService.REQUESTED, "tenant", "tenant-a", null,
                requestPayload.getValue(), null, requested.correlationId());
        when(audit.export("tenant-a")).thenReturn(List.of(request));
        when(locks.reconcileStale(eq("tenant-a"), eq("owner-a"), any())).thenReturn(false);

        assertThatThrownBy(() -> service.approve("tenant-a", requested.correlationId(), "approver-b"))
                .isInstanceOf(ProvisioningException.class)
                .hasMessageContaining("did not clear");
        verify(audit, never()).recordLifecycleLockRecoveryEvent(eq("tenant-a"), eq("approver-b"),
                eq(LifecycleLockRecoveryService.APPROVED), anyString(), anyString());
    }
}
