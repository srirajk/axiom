package com.openwolf.iam.policystudio;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static com.openwolf.iam.policystudio.C3TestGenFixtures.CHAT_USER;
import static com.openwolf.iam.policystudio.C3TestGenFixtures.DOMAIN_ADMIN;
import static com.openwolf.iam.policystudio.C3TestGenFixtures.PLATFORM_ADMIN;
import static com.openwolf.iam.policystudio.C3TestGenFixtures.RELATIONSHIP_MANAGER;
import static com.openwolf.iam.policystudio.C3TestGenFixtures.allow;
import static com.openwolf.iam.policystudio.C3TestGenFixtures.deny;
import static com.openwolf.iam.policystudio.C3TestGenFixtures.spec;

/**
 * The hand-reviewed known-bad corpus for Axiom Story C3.2 — 31 (intent, known-bad-policy) pairs across
 * the seven bad-policy classes. Each item's {@link IntentSpec} is authored FROM THE INTENT STRING
 * ALONE; the paired {@code badYaml} is what a naive or compromised generator might emit. The corpus is
 * the headline evidence artifact and is checked in (see {@code docs/implementation/evidence/studio/c3}).
 *
 * <p>{@code expectedLayer} pins the layer that must catch each item, so a regression (a bad policy that
 * starts slipping) turns the catch-rate test red rather than silently lowering the rate.
 */
final class C3Corpus {

    private C3Corpus() {}

    /**
     * @param id            stable corpus id (e.g. {@code CT-01})
     * @param category      one of the seven bad-policy classes
     * @param request       the authoring context (its {@code intent()} keys the oracle)
     * @param intent        the intent spec the oracle replays (authored from the intent, NOT the YAML)
     * @param badYaml       the known-bad candidate policy
     * @param expectedLayer the layer that must catch it ({@code ORACLE} ⇒ moat-critical)
     * @param note          the hand-review rationale
     */
    record Item(
            String id,
            String category,
            PolicyAuthoringRequest request,
            C3TestGenFixtures.IntentSpec intent,
            String badYaml,
            CatchLayer expectedLayer,
            String note) {}

    /** A generic, valid data-plane intent used where the bug is purely structural (validator-caught). */
    private static C3TestGenFixtures.IntentSpec structuralIntent() {
        return spec(allow(Set.of(CHAT_USER), "invoke", "internal"));
    }

    static List<Item> items() {
        return List.of(
                // ── Class A: cross-tenant grants (must be 100% caught; all break tenant structure) ──
                new Item("CT-01", C3TestGenFixtures.CAT_CROSS_TENANT,
                        C3TestGenFixtures.acmeRequest("CT-01: keep acme agents inside tenant acme."),
                        structuralIntent(), PolicyStudioFixtures.rootScopeRewrite(), CatchLayer.VALIDATOR,
                        "Root-scope rewrite edits the shared ceiling instead of narrowing a tenant child — cross-tenant blast radius."),
                new Item("CT-02", C3TestGenFixtures.CAT_CROSS_TENANT,
                        C3TestGenFixtures.acmeRequest("CT-02: acme child must require parental consent."),
                        structuralIntent(), C3TestGenFixtures.postureOverrideParent(), CatchLayer.VALIDATOR,
                        "scopePermissions=OVERRIDE_PARENT lets the child grant beyond the base ceiling — drops the inherited tenant-equality backstop."),
                new Item("CT-03", C3TestGenFixtures.CAT_CROSS_TENANT,
                        C3TestGenFixtures.acmeRequest("CT-03: acme author may only touch tenant acme."),
                        structuralIntent(), PolicyStudioFixtures.scopeEscapeToTenantB(), CatchLayer.VALIDATOR,
                        "Targets sibling tenant 'beta' — a cross-tenant escape from the author's subtree."),
                new Item("CT-04", C3TestGenFixtures.CAT_CROSS_TENANT,
                        C3TestGenFixtures.acmeRequestNoBackstop("CT-04: acme child must inherit the tenant-equality backstop."),
                        structuralIntent(), C3TestGenFixtures.compliant("acme"), CatchLayer.VALIDATOR,
                        "The base ceiling lacks the tenant-equality backstop, so this otherwise-clean child would allow cross-tenant."),
                new Item("CT-05", C3TestGenFixtures.CAT_CROSS_TENANT,
                        C3TestGenFixtures.acmeRequest("CT-05: acme author (subscopes disabled) may target only tenant acme."),
                        structuralIntent(), C3TestGenFixtures.compliant("acme.eu"), CatchLayer.VALIDATOR,
                        "Targets descendant acme.eu with subscopes disabled — an out-of-subtree grant."),

                // ── Class D: wildcard action/resource (must be 100% caught) ──────────────────────────
                new Item("WC-01", C3TestGenFixtures.CAT_WILDCARD,
                        C3TestGenFixtures.acmeRequest("WC-01: acme agents enumerate finite actions only."),
                        structuralIntent(), PolicyStudioFixtures.wildcardGrant(), CatchLayer.VALIDATOR,
                        "actions:['*'] + roles:['*'] — a total wildcard grant."),
                new Item("WC-02", C3TestGenFixtures.CAT_WILDCARD,
                        C3TestGenFixtures.acmeRequest("WC-02: platform_admin actions must be enumerated."),
                        structuralIntent(), C3TestGenFixtures.wildcardActionForRole(PLATFORM_ADMIN), CatchLayer.VALIDATOR,
                        "actions:['*'] for platform_admin — unbounded action surface."),
                new Item("WC-03", C3TestGenFixtures.CAT_WILDCARD,
                        C3TestGenFixtures.acmeRequest("WC-03: domain_admin actions must be enumerated."),
                        structuralIntent(), C3TestGenFixtures.wildcardInOneRule(), CatchLayer.VALIDATOR,
                        "A wildcard smuggled into an otherwise-finite rule (actions:['invoke','*'])."),
                new Item("WC-04", C3TestGenFixtures.CAT_WILDCARD,
                        C3TestGenFixtures.acmeRequest("WC-04: no role wildcard may receive a grant."),
                        structuralIntent(), C3TestGenFixtures.wildcardRoleAllow(), CatchLayer.VALIDATOR,
                        "roles:['*'] on an ALLOW — a wildcard principal grant."),
                new Item("WC-05", C3TestGenFixtures.CAT_WILDCARD,
                        C3TestGenFixtures.acmeRequest("WC-05: chat_user actions must be enumerated."),
                        structuralIntent(), C3TestGenFixtures.wildcardActionForRole(CHAT_USER), CatchLayer.VALIDATOR,
                        "actions:['*'] for chat_user — unbounded data-plane surface."),

                // ── Class B: wrong role/segment (moat — validator-clean, oracle-caught) ──────────────
                new Item("WR-01", C3TestGenFixtures.CAT_WRONG_ROLE_SEGMENT,
                        C3TestGenFixtures.acmeRequest("WR-01: acme chat_user may invoke internal agents but must NOT probe membership."),
                        spec(allow(Set.of(CHAT_USER), "invoke", "internal"), deny(Set.of(CHAT_USER), "invoke_membership")),
                        C3TestGenFixtures.compliant("acme"), CatchLayer.ORACLE,
                        "Leaves chat_user invoke_membership ALLOW; a co-generated test would assert ALLOW and pass. Independent oracle asserts DENY."),
                new Item("WR-02", C3TestGenFixtures.CAT_WRONG_ROLE_SEGMENT,
                        C3TestGenFixtures.acmeRequest("WR-02: acme relationship_manager may invoke internal agents but must NOT probe membership."),
                        spec(allow(Set.of(RELATIONSHIP_MANAGER), "invoke", "internal"), deny(Set.of(RELATIONSHIP_MANAGER), "invoke_membership")),
                        C3TestGenFixtures.rmMembershipGrant(), CatchLayer.ORACLE,
                        "Explicitly grants relationship_manager invoke_membership the intent excluded."),
                new Item("WR-03", C3TestGenFixtures.CAT_WRONG_ROLE_SEGMENT,
                        C3TestGenFixtures.acmeRequest("WR-03: only platform_admin may deregister acme agents; domain_admin must NOT."),
                        spec(allow(Set.of(CHAT_USER), "invoke", "internal"), deny(Set.of(DOMAIN_ADMIN), "deregister")),
                        C3TestGenFixtures.compliant("acme"), CatchLayer.ORACLE,
                        "Leaves domain_admin deregister ALLOW; wrong role holds a destructive action."),
                new Item("WR-04", C3TestGenFixtures.CAT_WRONG_ROLE_SEGMENT,
                        C3TestGenFixtures.acmeRequest("WR-04: only platform_admin may register acme agents; domain_admin must NOT."),
                        spec(allow(Set.of(CHAT_USER), "invoke", "internal"), deny(Set.of(DOMAIN_ADMIN), "register")),
                        C3TestGenFixtures.daRegisterGrant(), CatchLayer.ORACLE,
                        "Leaves domain_admin register ALLOW against the intent."),
                new Item("WR-05", C3TestGenFixtures.CAT_WRONG_ROLE_SEGMENT,
                        C3TestGenFixtures.acmeRequest("WR-05: acme relationship_manager may probe membership but must NOT invoke."),
                        spec(allow(Set.of(CHAT_USER), "invoke", "internal"), deny(Set.of(RELATIONSHIP_MANAGER), "invoke")),
                        C3TestGenFixtures.compliant("acme"), CatchLayer.ORACLE,
                        "Leaves relationship_manager invoke ALLOW against a membership-only intent."),
                new Item("WR-06", C3TestGenFixtures.CAT_WRONG_ROLE_SEGMENT,
                        C3TestGenFixtures.acmeRequest("WR-06: acme chat_user may probe membership but must NOT invoke."),
                        spec(allow(Set.of(RELATIONSHIP_MANAGER), "invoke", "internal"), deny(Set.of(CHAT_USER), "invoke")),
                        C3TestGenFixtures.compliant("acme"), CatchLayer.ORACLE,
                        "Leaves chat_user invoke ALLOW against a membership-only intent."),

                // ── Class C: omitted / wrong conditions (moat) ───────────────────────────────────────
                new Item("OC-01", C3TestGenFixtures.CAT_OMITTED_CONDITION,
                        C3TestGenFixtures.acmeRequest("OC-01: acme chat_user may invoke ONLY internal-classified agents."),
                        spec(allow(Set.of(CHAT_USER), "invoke", "internal")),
                        C3TestGenFixtures.compliant("acme"), CatchLayer.ORACLE,
                        "Grants chat_user invoke unconditionally — omits the classification guard, so confidential-pii agents are exposed."),
                new Item("OC-02", C3TestGenFixtures.CAT_OMITTED_CONDITION,
                        C3TestGenFixtures.acmeRequest("OC-02: acme relationship_manager may invoke ONLY confidential-classified agents."),
                        spec(allow(Set.of(RELATIONSHIP_MANAGER), "invoke", "confidential")),
                        C3TestGenFixtures.compliant("acme"), CatchLayer.ORACLE,
                        "Grants relationship_manager invoke unconditionally — omits the classification guard."),
                new Item("OC-03", C3TestGenFixtures.CAT_OMITTED_CONDITION,
                        C3TestGenFixtures.acmeRequest("OC-03: acme chat_user may invoke ONLY internal-classified agents (guarded)."),
                        spec(allow(Set.of(CHAT_USER), "invoke", "internal")),
                        C3TestGenFixtures.wrongClassificationCondition(), CatchLayer.ORACLE,
                        "Guards on the WRONG classification (confidential-pii) — the exact inverse of the intent."),
                new Item("OC-04", C3TestGenFixtures.CAT_OMITTED_CONDITION,
                        C3TestGenFixtures.acmeRequest("OC-04: acme relationship_manager may invoke ONLY internal-classified agents."),
                        spec(allow(Set.of(RELATIONSHIP_MANAGER), "invoke", "internal")),
                        C3TestGenFixtures.compliant("acme"), CatchLayer.ORACLE,
                        "Grants relationship_manager invoke unconditionally — omits the classification guard."),

                // ── Class E: missing-attribute fail-open (moat) ──────────────────────────────────────
                new Item("MA-01", C3TestGenFixtures.CAT_MISSING_ATTRIBUTE,
                        C3TestGenFixtures.acmeRequest("MA-01: acme chat_user invoke requires a present data_classification (fail-closed)."),
                        spec(allow(Set.of(CHAT_USER), "invoke", "internal")),
                        C3TestGenFixtures.compliant("acme"), CatchLayer.ORACLE,
                        "Unconditional grant fails OPEN on a resource with no classification — the missing-attribute probe demands DENY."),
                new Item("MA-02", C3TestGenFixtures.CAT_MISSING_ATTRIBUTE,
                        C3TestGenFixtures.acmeRequest("MA-02: acme relationship_manager invoke requires a present data_classification."),
                        spec(allow(Set.of(RELATIONSHIP_MANAGER), "invoke", "confidential")),
                        C3TestGenFixtures.compliant("acme"), CatchLayer.ORACLE,
                        "Unconditional grant fails OPEN on a missing classification."),
                new Item("MA-03", C3TestGenFixtures.CAT_MISSING_ATTRIBUTE,
                        C3TestGenFixtures.acmeRequest("MA-03: acme chat_user invoke must guard classification presence with has()."),
                        spec(allow(Set.of(CHAT_USER), "invoke", "internal")),
                        C3TestGenFixtures.unguardedCondition(), CatchLayer.ORACLE,
                        "Condition references data_classification without a has() guard — errors on absence and falls through to the base ALLOW (fail-open)."),

                // ── Class F: incomplete child restriction / fall-through (validator totality) ─────────
                new Item("FT-01", C3TestGenFixtures.CAT_INCOMPLETE_FALLTHROUGH,
                        C3TestGenFixtures.acmeRequest("FT-01: acme child must have an explicit opinion on every base tuple."),
                        structuralIntent(), PolicyStudioFixtures.omitsBaseTuple(), CatchLayer.VALIDATOR,
                        "Drops (register/deregister, domain_admin) — those tuples fall through to the parent ALLOW (invisible fail-open)."),
                new Item("FT-02", C3TestGenFixtures.CAT_INCOMPLETE_FALLTHROUGH,
                        C3TestGenFixtures.acmeRequest("FT-02: acme child must cover every chat_user base tuple."),
                        structuralIntent(), C3TestGenFixtures.omitsChatUser(), CatchLayer.VALIDATOR,
                        "Omits chat_user entirely — its base tuples fall through."),
                new Item("FT-03", C3TestGenFixtures.CAT_INCOMPLETE_FALLTHROUGH,
                        C3TestGenFixtures.acmeRequest("FT-03: acme child must cover every relationship_manager base tuple."),
                        structuralIntent(), C3TestGenFixtures.omitsRelationshipManager(), CatchLayer.VALIDATOR,
                        "Omits relationship_manager coverage — fall-through hole."),
                new Item("FT-04", C3TestGenFixtures.CAT_INCOMPLETE_FALLTHROUGH,
                        C3TestGenFixtures.acmeRequest("FT-04: acme child must cover platform_admin deregister."),
                        structuralIntent(), C3TestGenFixtures.omitsPlatformAdminDeregister(), CatchLayer.VALIDATOR,
                        "Drops deregister for platform_admin — that tuple falls through."),

                // ── Class G: scope-boundary confusion (validator scope containment) ──────────────────
                new Item("SB-01", C3TestGenFixtures.CAT_SCOPE_BOUNDARY,
                        C3TestGenFixtures.acmeSubRequest("SB-01: author acme.a may target only tenant acme.a."),
                        structuralIntent(), C3TestGenFixtures.compliant("acme.ab"), CatchLayer.VALIDATOR,
                        "Targets acme.ab — a string-prefix look-alike of acme.a that is a different tenant (segment 'ab' != 'a')."),
                new Item("SB-02", C3TestGenFixtures.CAT_SCOPE_BOUNDARY,
                        C3TestGenFixtures.acmeSubRequest("SB-02: author acme.a (subscopes disabled) may not target descendants."),
                        structuralIntent(), C3TestGenFixtures.compliant("acme.a.london"), CatchLayer.VALIDATOR,
                        "Targets descendant acme.a.london with subscopes disabled."),
                new Item("SB-03", C3TestGenFixtures.CAT_SCOPE_BOUNDARY,
                        C3TestGenFixtures.acmeSubRequest("SB-03: author acme.a may not target unrelated tenants."),
                        structuralIntent(), C3TestGenFixtures.compliant("acmex"), CatchLayer.VALIDATOR,
                        "Targets acmex — not in the author's subtree at all."),
                new Item("SB-04", C3TestGenFixtures.CAT_SCOPE_BOUNDARY,
                        C3TestGenFixtures.acmeSubRequest("SB-04: author acme.a may not rewrite the root ceiling."),
                        structuralIntent(), C3TestGenFixtures.compliant(""), CatchLayer.VALIDATOR,
                        "Targets the root ceiling scope — edits the base, not a tenant child.")
        );
    }

    /** The seeded oracle built from the corpus: intent-string → intent spec (unique keys enforced). */
    static C3TestGenFixtures.SeededIntentOracle oracle() {
        Map<String, C3TestGenFixtures.IntentSpec> byIntent = items().stream()
                .collect(Collectors.toMap(i -> i.request().intent(), C3Corpus.Item::intent));
        return new C3TestGenFixtures.SeededIntentOracle(byIntent);
    }
}
