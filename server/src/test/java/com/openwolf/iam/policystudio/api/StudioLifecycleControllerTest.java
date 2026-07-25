package com.openwolf.iam.policystudio.api;

import com.openwolf.iam.policystudio.lifecycle.AuditIntegrityException;
import com.openwolf.iam.policystudio.lifecycle.BundleTestMetadata;
import com.openwolf.iam.policystudio.lifecycle.ExaminerChain;
import com.openwolf.iam.policystudio.lifecycle.ExaminerChainService;
import com.openwolf.iam.policystudio.lifecycle.PolicyBundleRecord;
import com.openwolf.iam.policystudio.lifecycle.PolicyBundleRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.lang.reflect.Field;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * C5 lifecycle READ endpoints: the immutable bundle history (tenant-scoped from the claim, cross-tenant
 * bundle ⇒ 404) and the zero-LLM examiner chain (a broken join ⇒ 422). All reads require a studio role.
 */
@WebMvcTest(controllers = StudioLifecycleController.class)
@Import(StudioTestSecurityConfig.class)
class StudioLifecycleControllerTest {

    @Autowired MockMvc mvc;
    @MockitoBean PolicyBundleRepository bundles;
    @MockitoBean ExaminerChainService examiner;

    /** Build a REAL PolicyBundleRecord (an @Entity, not mockable as a value type) via reflection. */
    private static PolicyBundleRecord record(String bundleId, String tenant) {
        try {
            var ctor = PolicyBundleRecord.class.getDeclaredConstructor();
            ctor.setAccessible(true);
            PolicyBundleRecord r = ctor.newInstance();
            set(r, "bundleId", bundleId);
            set(r, "tenantId", tenant);
            set(r, "gitCommit", "abc123");
            set(r, "fixtureSetHash", "fs-1");
            set(r, "testCount", 42);
            set(r, "testOracle", "oracle");
            set(r, "pdpSourceId", "cerbos-0.53.0");
            set(r, "canonicalContent", "content");
            set(r, "createdAt", Instant.parse("2026-07-01T00:00:00Z"));
            return r;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static void set(Object target, String field, Object value) throws Exception {
        Field f = PolicyBundleRecord.class.getDeclaredField(field);
        f.setAccessible(true);
        f.set(target, value);
    }

    @Test
    void listBundlesReturnsTenantHistory() throws Exception {
        when(bundles.findByTenantIdOrderByCreatedAtDesc("meridian"))
                .thenReturn(List.of(record("b_9", "meridian")));
        mvc.perform(get("/admin/studio/bundles").with(StudioMvc.principal("d", "meridian", "policy_author")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].bundleId").value("b_9"))
                .andExpect(jsonPath("$[0].tenantId").value("meridian"))
                .andExpect(jsonPath("$[0].testCount").value(42));
    }

    @Test
    void getBundleFromAnotherTenantIs404() throws Exception {
        when(bundles.findById("b_x")).thenReturn(Optional.of(record("b_x", "acme")));
        mvc.perform(get("/admin/studio/bundles/b_x").with(StudioMvc.principal("d", "meridian", "policy_approver")))
                .andExpect(status().isNotFound());
    }

    @Test
    void examinerReturnsReconstructedChain() throws Exception {
        ExaminerChain chain = new ExaminerChain("txn-1", "meridian", "call-1", "b_9", "EFFECT_ALLOW", "kind", "read",
                "b_9", "abc123", new BundleTestMetadata("fs-1", 42, "oracle", "cerbos-0.53.0"),
                "approver-bob", "crh-1", true, true);
        when(examiner.reconstruct("call-1")).thenReturn(chain);
        mvc.perform(get("/admin/studio/examiner/call-1").with(StudioMvc.principal("d", "meridian", "policy_approver")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.cerbosCallId").value("call-1"))
                .andExpect(jsonPath("$.tenantId").value("meridian"))
                .andExpect(jsonPath("$.complete").value(true))
                .andExpect(jsonPath("$.approverId").value("approver-bob"));
    }

    @Test
    void examinerFromAnotherTenantIsDenied403() throws Exception {
        ExaminerChain chain = new ExaminerChain("txn-1", "acme", "call-cross", "b_9", "EFFECT_ALLOW",
                "kind", "read", "b_9", "abc123",
                new BundleTestMetadata("fs-1", 42, "oracle", "cerbos-0.53.0"),
                "approver-bob", "crh-1", true, true);
        when(examiner.reconstruct("call-cross")).thenReturn(chain);

        mvc.perform(get("/admin/studio/examiner/call-cross")
                        .with(StudioMvc.principal("d", "meridian", "policy_approver")))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("tenant_scope_violation"));
    }

    @Test
    void examinerChainWithoutTenantIsDenied403() throws Exception {
        ExaminerChain chain = new ExaminerChain("txn-1", null, "call-missing", "b_9", "EFFECT_ALLOW",
                "kind", "read", "b_9", "abc123",
                new BundleTestMetadata("fs-1", 42, "oracle", "cerbos-0.53.0"),
                "approver-bob", "crh-1", true, true);
        when(examiner.reconstruct("call-missing")).thenReturn(chain);

        mvc.perform(get("/admin/studio/examiner/call-missing")
                        .with(StudioMvc.principal("d", "meridian", "policy_approver")))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("tenant_scope_violation"));
    }

    @Test
    void examinerBrokenJoinIs422() throws Exception {
        when(examiner.reconstruct("bad")).thenThrow(new AuditIntegrityException("no audit entry"));
        mvc.perform(get("/admin/studio/examiner/bad").with(StudioMvc.principal("d", "meridian", "policy_approver")))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error").value("audit_integrity"));
    }

    @Test
    void nonStudioRoleIsDenied403() throws Exception {
        mvc.perform(get("/admin/studio/bundles").with(StudioMvc.principal("rm", "meridian", "chat_user")))
                .andExpect(status().isForbidden());
    }
}
