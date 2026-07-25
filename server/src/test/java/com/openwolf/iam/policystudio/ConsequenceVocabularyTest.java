package com.openwolf.iam.policystudio;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * C4.3 — consequences are rendered over the tenant's MANIFEST entity vocabulary (World B). Every
 * business-consequence string names the manifest resource kind, a manifest action, and a manifest
 * role — none of which is a hardcoded domain literal in the diff service; they flow from
 * {@link ManifestVocabulary} and the fixture cell. Onboarding a new entity type is a manifest edit,
 * never a code change.
 */
class ConsequenceVocabularyTest {

    @Test
    void deltasUseManifestEntityTerms() {
        ManifestVocabulary vocab = C4ConsequenceFixtures.vocab();
        ConsequenceReview review = C4ConsequenceFixtures.diffService().computeReview(
                C4ConsequenceFixtures.TENANT, vocab,
                C4ConsequenceFixtures.bundle(C4ConsequenceFixtures.currentBody()),
                C4ConsequenceFixtures.bundle(C4ConsequenceFixtures.candidateBody()),
                C4ConsequenceFixtures.matrix(), C4ConsequenceFixtures.localPdp());

        // The review is phrased over the manifest resource kind.
        assertThat(review.resourceKind()).isEqualTo(vocab.resourceKind());

        assertThat(review.deltas()).isNotEmpty().allSatisfy(d -> {
            String prose = d.businessConsequence();
            // resource kind comes from the manifest vocabulary
            assertThat(prose).contains(vocab.resourceKind());
            // the action is a manifest-declared action
            assertThat(prose).contains(d.cell().action());
            assertThat(vocab.actions()).contains(d.cell().action());
            // at least one named role is a manifest-declared role
            assertThat(d.cell().principalRoles()).isSubsetOf(vocab.roles());
            assertThat(vocab.roles()).anySatisfy(role -> assertThat(prose).contains(role));
        });
    }
}
