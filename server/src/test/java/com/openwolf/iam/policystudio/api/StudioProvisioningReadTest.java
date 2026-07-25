package com.openwolf.iam.policystudio.api;

import com.openwolf.iam.controller.TenantProvisioningController;
import com.openwolf.iam.tenancy.ActiveTenantDirectory;
import com.openwolf.iam.tenancy.TenantProvisioningService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * B4 provisioning READ endpoints (the newly added {@code GET /admin/tenants} list + {@code GET
 * /admin/tenants/{id}} status). Platform-admin only; the status is derived from the active directory
 * (present ⇒ active with its live policy version; absent ⇒ fail-closed inactive).
 */
@WebMvcTest(controllers = TenantProvisioningController.class)
@Import(StudioTestSecurityConfig.class)
class StudioProvisioningReadTest {

    @Autowired MockMvc mvc;
    @MockitoBean TenantProvisioningService provisioningService;
    @MockitoBean ActiveTenantDirectory directory;

    private void directoryHas() {
        Map<String, String> map = new LinkedHashMap<>();
        map.put("meridian", "pv-1");
        map.put("acme", "pv-2");
        when(directory.snapshot()).thenReturn(new ActiveTenantDirectory.Snapshot(7L, map));
    }

    @Test
    void listReturnsActiveTenantsSortedWithDirectoryVersion() throws Exception {
        directoryHas();
        mvc.perform(get("/admin/tenants").with(StudioMvc.principal("root", "platform", "platform_admin")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.directoryVersion").value(7))
                .andExpect(jsonPath("$.tenants[0].tenantId").value("acme"))
                .andExpect(jsonPath("$.tenants[0].active").value(true))
                .andExpect(jsonPath("$.tenants[0].policyVersion").value("pv-2"))
                .andExpect(jsonPath("$.tenants[1].tenantId").value("meridian"));
    }

    @Test
    void statusPresentIsActive() throws Exception {
        directoryHas();
        mvc.perform(get("/admin/tenants/meridian").with(StudioMvc.principal("root", "platform", "platform_admin")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tenantId").value("meridian"))
                .andExpect(jsonPath("$.active").value(true))
                .andExpect(jsonPath("$.policyVersion").value("pv-1"));
    }

    @Test
    void statusAbsentFailsClosedInactive() throws Exception {
        directoryHas();
        mvc.perform(get("/admin/tenants/ghost").with(StudioMvc.principal("root", "platform", "platform_admin")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tenantId").value("ghost"))
                .andExpect(jsonPath("$.active").value(false));
    }

    @Test
    void nonPlatformAdminIsDenied403() throws Exception {
        mvc.perform(get("/admin/tenants").with(StudioMvc.principal("rm", "meridian", "chat_user")))
                .andExpect(status().isForbidden());
    }
}
