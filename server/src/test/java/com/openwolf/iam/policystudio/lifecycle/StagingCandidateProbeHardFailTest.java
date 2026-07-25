package com.openwolf.iam.policystudio.lifecycle;

import com.openwolf.iam.policystudio.CerbosCompileGate;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Axiom H2 — the {@link StagingCandidateProbe} compile step is MANDATORY. When the pinned Cerbos is
 * unavailable the probe HARD-FAILS the promotion instead of degrading to version-stamp-only. This is the
 * deterministic (no-Docker) proof: a compile gate reporting {@code isAvailable() == false} forces a refusal
 * even for a correctly version-stamped candidate.
 */
class StagingCandidateProbeHardFailTest {

    /** A compile gate that reports Cerbos as unavailable, regardless of the host. */
    private static CerbosCompileGate unavailableGate() {
        return new CerbosCompileGate(com.openwolf.iam.test.AxiomTestPolicyRoot.cerbosImage(), 60) {
            @Override
            public boolean isAvailable() {
                return false;
            }
        };
    }

    @Test
    void probeHardFailsWhenCerbosUnavailable() {
        StagingCandidateProbe probe = new StagingCandidateProbe(unavailableGate(),
                com.openwolf.iam.test.AxiomTestPolicyRoot.policies().toString());

        // A well-formed, correctly version-stamped candidate — the version-stamp invariants pass, so the
        // ONLY thing that can stop it is the mandatory compile probe.
        PolicyBundle candidate = C5LifecycleFixtures.bundle(
                C5LifecycleFixtures.candidateBody(), C5LifecycleFixtures.matrixHash());

        assertThatThrownBy(() -> probe.verify(candidate))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("MANDATORY")
                .hasMessageContaining("never version-stamp-only");
    }
}
