package com.openwolf.iam.policystudio;

import java.util.ArrayList;
import java.util.List;

/**
 * The ordered, immutable principal×resource×action matrix the consequence diff is evaluated over
 * (Axiom Story C4), plus its content-addressed {@code fixtureSetHash}. Both immutable bundle
 * snapshots are asked every cell, and the two real PDP answers are diffed.
 *
 * <p><b>Reuses the C3 eval set.</b> The canonical way to build the matrix is
 * {@link #fromExpectationSet(TestExpectationSet)} — it takes a C3 {@link TestExpectationSet} (the
 * independent intent oracle + its mechanically-injected cross-tenant / wrong-segment /
 * missing-attribute probes, i.e. the same matrix the B3 invariant suite exercises) and drops the
 * expected effect, because C4 asks what each bundle DECIDES, never what it should decide.
 *
 * <p>The {@code fixtureSetHash} binds the review to the exact matrix it was computed over: if the
 * sampled matrix changes, the review hash changes and any approval signed against it is invalidated
 * (C4.6).
 */
public record ConsequenceFixtureMatrix(List<FixtureCell> cells, String fixtureSetHash) {

    public ConsequenceFixtureMatrix {
        cells = List.copyOf(cells);
    }

    public static ConsequenceFixtureMatrix of(List<FixtureCell> cells) {
        return new ConsequenceFixtureMatrix(cells, hashOf(cells));
    }

    /**
     * Build the matrix from a C3 oracle+probe expectation set, dropping each expectation's expected
     * effect. Every distinct input tuple becomes one cell (dedup on the canonical key, so a matrix
     * derived from many intents does not double-count the same question).
     */
    public static ConsequenceFixtureMatrix fromExpectationSet(TestExpectationSet expectations) {
        List<FixtureCell> cells = new ArrayList<>();
        java.util.Set<String> seen = new java.util.HashSet<>();
        for (Expectation e : expectations.expectations()) {
            FixtureCell cell = new FixtureCell(
                    e.principalRoles(),
                    e.principalTenant(),
                    java.util.Map.of(),
                    e.resourceTenant(),
                    e.resourceAttrs(),
                    e.action(),
                    e.label());
            if (seen.add(cell.canonicalKey())) {
                cells.add(cell);
            }
        }
        return of(cells);
    }

    private static String hashOf(List<FixtureCell> cells) {
        StringBuilder sb = new StringBuilder();
        // Sort by canonical key so the hash is independent of insertion order.
        cells.stream().map(FixtureCell::canonicalKey).sorted().forEach(k -> sb.append(k).append('\n'));
        return StudioHashing.sha256Hex(sb.toString());
    }
}
