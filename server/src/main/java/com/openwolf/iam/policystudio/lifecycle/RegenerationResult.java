package com.openwolf.iam.policystudio.lifecycle;

import com.openwolf.iam.policystudio.ConsequenceReview;

/**
 * The output of a regeneration (Axiom Story C5.2): a NEW immutable candidate bundle plus the C4
 * consequence review (the reviewed diff) against the current bundle. Regeneration is pure — it never
 * mutates the stored or active bundle; the live YAML is untouched until a separate authorized promotion.
 *
 * @param candidate the new immutable candidate (a different {@code bundleId} than the current bundle)
 * @param diff      the C4 consequence review between the current and candidate bundles
 */
public record RegenerationResult(PolicyBundle candidate, ConsequenceReview diff) {
}
