package com.openwolf.iam.policystudio.api;

import com.openwolf.iam.policystudio.GeneratedPolicyValidator;
import com.openwolf.iam.policystudio.BaseCeiling;
import com.openwolf.iam.policystudio.ManifestVocabulary;
import com.openwolf.iam.policystudio.PolicyIR;
import com.openwolf.iam.policystudio.TenantScope;
import com.openwolf.iam.policystudio.breakglass.BreakGlassAllowlist;
import com.openwolf.iam.policystudio.breakglass.BreakGlassArtifact;
import com.openwolf.iam.policystudio.breakglass.BreakGlassAuthoringService;
import com.openwolf.iam.policystudio.breakglass.BreakGlassGrant;
import com.openwolf.iam.policystudio.breakglass.BreakGlassIssuanceService;
import com.openwolf.iam.policystudio.breakglass.BreakGlassTrustRootProvider;
import com.openwolf.iam.policystudio.breakglass.BreakGlassSodException;
import com.openwolf.iam.policystudio.breakglass.BreakGlassValidator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * C6 break-glass surface. Two-person by construction: a drafter authors (requester = verified sub), a
 * different approver issues (the service enforces requester≠approver + the approver role). The TTL is
 * stamped from the SERVER clock and clamped to (0, 60] minutes; the grant scope must be the caller's tenant.
 */
@WebMvcTest(controllers = StudioBreakGlassController.class)
@Import(StudioTestSecurityConfig.class)
class StudioBreakGlassControllerTest {

    @Autowired MockMvc mvc;
    @MockitoBean BreakGlassAuthoringService authoring;
    @MockitoBean BreakGlassIssuanceService issuance;
    @MockitoBean BreakGlassTrustRootProvider trustRoots;
    @MockitoBean StudioSessionStore store;

    private static String body(String scope, long ttl) {
        return """
                {
                  "scope":"%s","resourceKind":"agent","action":"break","role":"desk",
                  "ttlMinutes":%d,"justification":"incident 42"
                }
                """.formatted(scope, ttl);
    }

    private static BreakGlassTrustRootProvider.TrustRoots roots() {
        return new BreakGlassTrustRootProvider.TrustRoots(
                new ManifestVocabulary("agent", Set.of("break"), Set.of(), Set.of(), Set.of("desk"), Set.of()),
                new BaseCeiling("agent", Set.of(new BaseCeiling.Tuple("break", "desk")), true, Set.of()),
                new BreakGlassAllowlist(Set.of("agent"), Set.of("break")));
    }

    /** A REAL admissible artifact (BreakGlassArtifact is a record — not mockable as a value type). */
    private static BreakGlassArtifact admissibleArtifact(String requester) {
        Instant now = Instant.now();
        BreakGlassGrant grant = new BreakGlassGrant(TenantScope.of("meridian"), "agent", "break", "desk",
                now, now.plus(30, ChronoUnit.MINUTES), "incident 42", requester);
        PolicyIR ir = new PolicyIR("api.cerbos.dev/v1", "b1", "agent", "meridian",
                "SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS", List.of(), List.of());
        return new BreakGlassArtifact(grant, ir, "canonical: yaml\n",
                new BreakGlassValidator.Result(true, List.of()),
                new GeneratedPolicyValidator.Result(true, List.of()));
    }

    private StudioSessionStore.PendingGrant pending(String requester, boolean issued) {
        return new StudioSessionStore.PendingGrant("bg-1", "meridian", requester,
                admissibleArtifact(requester), issued, Instant.now());
    }

    private StudioSessionStore.PendingGrant expiredPending(String requester) {
        Instant now = Instant.now();
        BreakGlassGrant grant = new BreakGlassGrant(TenantScope.of("meridian"), "agent", "break", "desk",
                now.minus(31, ChronoUnit.MINUTES), now.minus(1, ChronoUnit.MINUTES),
                "incident 42", requester);
        PolicyIR ir = new PolicyIR("api.cerbos.dev/v1", "b1", "agent", "meridian",
                "SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS", List.of(), List.of());
        BreakGlassArtifact artifact = new BreakGlassArtifact(grant, ir, "canonical: yaml\n",
                new BreakGlassValidator.Result(true, List.of()),
                new GeneratedPolicyValidator.Result(true, List.of()));
        return new StudioSessionStore.PendingGrant("bg-expired", "meridian", requester,
                artifact, false, Instant.now());
    }

    @Test
    void drafterAuthorsAdmissibleGrant() throws Exception {
        when(trustRoots.resolve("meridian", "agent")).thenReturn(roots());
        when(authoring.author(any(), any(), any())).thenReturn(admissibleArtifact("drafter-dan"));
        when(store.putGrant(eq("meridian"), eq("drafter-dan"), any())).thenReturn(pending("drafter-dan", false));

        mvc.perform(post("/admin/studio/break-glass")
                        .with(StudioMvc.principal("drafter-dan", "meridian", "policy_author"))
                        .contentType(MediaType.APPLICATION_JSON).content(body("meridian", 30)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.grantId").value("bg-1"))
                .andExpect(jsonPath("$.admissible").value(true))
                .andExpect(jsonPath("$.issued").value(false));
    }

    @Test
    void callerSuppliedTrustRootsAreRejectedAndNeverResolvedOrUsed() throws Exception {
        String spoofed = body("meridian", 30).replace(
                "\"ttlMinutes\":30",
                "\"ttlMinutes\":30,\"vocabulary\":{},\"baseCeiling\":{},\"allowlist\":{}");

        mvc.perform(post("/admin/studio/break-glass")
                        .with(StudioMvc.principal("drafter-dan", "meridian", "policy_author"))
                        .contentType(MediaType.APPLICATION_JSON).content(spoofed))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("bad_request"));

        verifyNoInteractions(trustRoots, authoring);
    }

    @Test
    void ttlBeyondSixtyMinutesIsRejected400() throws Exception {
        mvc.perform(post("/admin/studio/break-glass")
                        .with(StudioMvc.principal("drafter-dan", "meridian", "policy_author"))
                        .contentType(MediaType.APPLICATION_JSON).content(body("meridian", 120)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("bad_request"));
        verifyNoInteractions(authoring);
    }

    @Test
    void grantScopeInAnotherTenantIsRejected403() throws Exception {
        mvc.perform(post("/admin/studio/break-glass")
                        .with(StudioMvc.principal("drafter-dan", "meridian", "policy_author"))
                        .contentType(MediaType.APPLICATION_JSON).content(body("acme", 30)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("tenant_scope_violation"));
        verifyNoInteractions(authoring);
    }

    @Test
    void authoringRequiresDrafterRole403() throws Exception {
        mvc.perform(post("/admin/studio/break-glass")
                        .with(StudioMvc.principal("bob", "meridian", "policy_approver"))
                        .contentType(MediaType.APPLICATION_JSON).content(body("meridian", 30)))
                .andExpect(status().isForbidden());
        verifyNoInteractions(authoring);
    }

    @Test
    void approverIssuesGrant() throws Exception {
        when(store.getGrant("meridian", "bg-1"))
                .thenReturn(Optional.of(pending("drafter-dan", false)))
                .thenReturn(Optional.of(pending("drafter-dan", true)));
        mvc.perform(post("/admin/studio/break-glass/bg-1/approve")
                        .with(StudioMvc.principal("approver-bob", "meridian", "policy_approver")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.grantId").value("bg-1"))
                .andExpect(jsonPath("$.issued").value(true));

        verify(issuance).issue(any(), eq("approver-bob"), any(), anyString());
        verify(store).markIssued(any());
    }

    @Test
    void failedPromotionDoesNotRecordIssuedAuditOrMarkGrantIssued() throws Exception {
        when(store.getGrant("meridian", "bg-1")).thenReturn(Optional.of(pending("drafter-dan", false)));
        doThrow(new IllegalStateException("runtime promotion failed"))
                .when(issuance).issue(any(), eq("approver-bob"), any(), anyString());

                mvc.perform(post("/admin/studio/break-glass/bg-1/approve")
                        .with(StudioMvc.principal("approver-bob", "meridian", "policy_approver")))
                .andExpect(status().isUnprocessableEntity());

        verify(store, never()).markIssued(any());
    }

    @Test
    void selfApprovalIsRejected409() throws Exception {
        when(store.getGrant("meridian", "bg-1")).thenReturn(Optional.of(pending("drafter-dan", false)));
        doThrow(new BreakGlassSodException("requester may not approve"))
                .when(issuance).issue(any(), anyString(), any(), anyString());

        mvc.perform(post("/admin/studio/break-glass/bg-1/approve")
                        .with(StudioMvc.principal("drafter-dan", "meridian", "policy_approver")))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("separation_of_duties"));
    }

    @Test
    void approveRequiresApproverRole403() throws Exception {
        mvc.perform(post("/admin/studio/break-glass/bg-1/approve")
                        .with(StudioMvc.principal("dan", "meridian", "policy_author")))
                .andExpect(status().isForbidden());
        verifyNoInteractions(issuance);
    }

    @Test
    void expiredGrantIsRejectedImmediatelyBeforeIssuance() throws Exception {
        when(store.getGrant("meridian", "bg-expired"))
                .thenReturn(Optional.of(expiredPending("drafter-dan")));

        mvc.perform(post("/admin/studio/break-glass/bg-expired/approve")
                        .with(StudioMvc.principal("approver-bob", "meridian", "policy_approver")))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("expired")));
        verifyNoInteractions(issuance);
        verify(store, never()).markIssued(any());
    }

    @Test
    void listIncludesPendingRequestsForApproverHandoff() throws Exception {
        when(store.visibleGrants("meridian")).thenReturn(List.of(
                pending("drafter-dan", false), pending("drafter-dan", true)));
        mvc.perform(get("/admin/studio/break-glass")
                        .with(StudioMvc.principal("approver-bob", "meridian", "policy_approver")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].grantId").value("bg-1"))
                .andExpect(jsonPath("$[0].issued").value(false))
                .andExpect(jsonPath("$[1].issued").value(true));
        verify(store).visibleGrants("meridian");
    }
}
