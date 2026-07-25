package com.openwolf.iam.policystudio.api;

import com.openwolf.iam.policystudio.BaseCeiling;
import com.openwolf.iam.policystudio.ManifestVocabulary;
import com.openwolf.iam.policystudio.PolicyAuthoringRequest;
import com.openwolf.iam.policystudio.PolicyStudioGenerationService;
import com.openwolf.iam.policystudio.StudioGenerationResult;
import com.openwolf.iam.policystudio.StudioGroundingProvider;
import com.openwolf.iam.policystudio.StudioGroundingSnapshot;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * C2 authoring endpoint ({@code POST /admin/studio/drafts}). The author scope is derived from the
 * principal's {@code tenant_id} claim (not the body); requires {@code policy_author}. A rejected proposal
 * is a normal 200 with violations, not an error.
 *
 * <p><b>S2 trusted inputs.</b> The grounding — the closed {@code vocabulary} and the immutable {@code
 * baseCeiling} — is derived server-side from the tenant's manifest via {@link StudioGroundingProvider};
 * it is NOT accepted from the body. A caller that smuggles a widened vocabulary / relaxed ceiling into
 * the JSON is ignored, and the server-derived grounding is what reaches the generation service.
 */
@WebMvcTest(controllers = StudioAuthoringController.class)
@Import(StudioTestSecurityConfig.class)
class StudioAuthoringControllerTest {

    @Autowired MockMvc mvc;
    @MockitoBean PolicyStudioGenerationService generation;
    @MockitoBean StudioGroundingProvider grounding;

    /** A clean request: only intent + the subscopes flag. Grounding is server-derived. */
    private static final String BODY = """
            {
              "intent":"allow read for the desk",
              "resourceKind":"iam-resource",
              "subscopesEnabled":false
            }
            """;

    /**
     * A poisoned request: the caller ALSO smuggles a widened vocabulary + a relaxed (backstop-off)
     * ceiling into the body. These fields no longer exist on the payload and must be ignored — the
     * server-derived grounding must be what reaches the generation service.
     */
    private static final String POISON_BODY = """
            {
              "intent":"allow read for the desk",
              "subscopesEnabled":false,
              "resourceKind":"iam-resource",
              "vocabulary":{"resourceKind":"iam-resource","actions":["exfiltrate"],"classifications":[],
                            "attributes":[],"roles":["attacker"],"approvedImports":[]},
              "baseCeiling":{"resourceKind":"iam-resource","tuples":[{"action":"exfiltrate","role":"attacker"}],
                             "carriesTenantEqualityBackstop":false,"reservedIdentities":[]}
            }
            """;

    /** The server-derived grounding for tenant {@code tenant-a}: the trusted vocabulary + ceiling. */
    private static StudioGroundingSnapshot serverGrounding() {
        ManifestVocabulary vocabulary = new ManifestVocabulary(
                "iam-resource", Set.of("read"), Set.of(), Set.of("tenant_id"),
                Set.of("platform_admin"), Set.of("business_derived_roles"));
        BaseCeiling ceiling = new BaseCeiling(
                "iam-resource", Set.of(new BaseCeiling.Tuple("read", "platform_admin")),
                true, Set.of("iam-resource@"));
        return new StudioGroundingSnapshot("tenant-a", vocabulary, ceiling, null, null, List.of());
    }

    @Test
    void drafterGeneratesAcceptedCanonicalYaml() throws Exception {
        when(grounding.snapshot("tenant-a", "iam-resource")).thenReturn(serverGrounding());
        when(generation.generate(any()))
                .thenReturn(StudioGenerationResult.accepted("canonical: yaml\n",
                        StudioGenerationResult.Stage.ACCEPTED));

        mvc.perform(post("/admin/studio/drafts")
                        .with(StudioMvc.principal("drafter-dan", "tenant-a", "policy_author"))
                        .contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.draftId").exists())
                .andExpect(jsonPath("$.tenantId").value("tenant-a"))
                .andExpect(jsonPath("$.authorId").value("drafter-dan"))
                .andExpect(jsonPath("$.accepted").value(true))
                .andExpect(jsonPath("$.canonicalYaml").value("canonical: yaml\n"))
                .andExpect(jsonPath("$.validation.ok").value(true))
                .andExpect(jsonPath("$.validation.stage").value("ACCEPTED"));
    }

    @Test
    void rejectedProposalIsA200WithViolations() throws Exception {
        when(grounding.snapshot("tenant-a", "iam-resource")).thenReturn(serverGrounding());
        when(generation.generate(any()))
                .thenReturn(StudioGenerationResult.rejected(
                        StudioGenerationResult.Stage.VALIDATE, List.of("rule escapes author scope")));

        mvc.perform(post("/admin/studio/drafts")
                        .with(StudioMvc.principal("drafter-dan", "tenant-a", "policy_author"))
                        .contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accepted").value(false))
                .andExpect(jsonPath("$.validation.ok").value(false))
                .andExpect(jsonPath("$.validation.violations[0]").value("rule escapes author scope"))
                .andExpect(jsonPath("$.validation.stage").value("VALIDATE"));
    }

    /**
     * The lockdown proof: a caller-supplied vocabulary/ceiling in the body cannot influence the outcome.
     * The generation service is invoked with the SERVER-derived grounding (tenant {@code tenant-a}'s
     * trusted vocabulary + backstop-on ceiling), never the poisoned body values.
     */
    @Test
    void callerSuppliedVocabularyAndCeilingAreIgnored() throws Exception {
        when(grounding.snapshot("tenant-a", "iam-resource")).thenReturn(serverGrounding());
        when(generation.generate(any()))
                .thenReturn(StudioGenerationResult.accepted("canonical: yaml\n",
                        StudioGenerationResult.Stage.ACCEPTED));

        mvc.perform(post("/admin/studio/drafts")
                        .with(StudioMvc.principal("drafter-dan", "tenant-a", "policy_author"))
                        .contentType(MediaType.APPLICATION_JSON).content(POISON_BODY))
                .andExpect(status().isOk());

        ArgumentCaptor<PolicyAuthoringRequest> captor = ArgumentCaptor.forClass(PolicyAuthoringRequest.class);
        verify(generation).generate(captor.capture());
        PolicyAuthoringRequest used = captor.getValue();

        // Server-derived vocabulary reached the gate — the poisoned "exfiltrate"/"attacker" did not.
        assertThat(used.vocabulary().actions()).containsExactly("read");
        assertThat(used.vocabulary().actions()).doesNotContain("exfiltrate");
        assertThat(used.vocabulary().roles()).containsExactly("platform_admin");
        // Server ceiling keeps the tenant-equality backstop ON — the poisoned backstop-off is ignored.
        assertThat(used.baseCeiling().carriesTenantEqualityBackstop()).isTrue();
        assertThat(used.baseCeiling().tuples())
                .containsExactly(new BaseCeiling.Tuple("read", "platform_admin"));
        // The author scope is the principal's own tenant, never a body field.
        assertThat(used.authorScope().value()).isEqualTo("tenant-a");
    }

    @Test
    void nonDrafterIsDenied403() throws Exception {
        mvc.perform(post("/admin/studio/drafts")
                        .with(StudioMvc.principal("bob", "tenant-a", "policy_approver"))
                        .contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isForbidden());
        verifyNoInteractions(generation, grounding);
    }
}
