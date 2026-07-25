package com.openwolf.iam.policystudio;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The remaining deterministic-gate rejection classes that back the adversarial corpus (Axiom Story
 * C2): parser-level rejections (aliases, custom tags, wrong document shape) and validator-level
 * rejections (wildcard grant, root-scope rewrite, identity collision, missing backstop).
 */
class GeneratedPolicyGateTest {

    private final PolicyYamlParser parser = new PolicyYamlParser();
    private final GeneratedPolicyValidator validator = new GeneratedPolicyValidator();

    private PolicyAuthoringRequest acme() {
        return PolicyStudioFixtures.request("Restrict acme agents.", TenantScope.of("acme"), false);
    }

    @Test
    void parserRejectsYamlAliases() {
        assertThatThrownBy(() -> parser.parse(PolicyStudioFixtures.aliasVector()))
                .isInstanceOf(PolicyParseException.class)
                .hasMessageContaining("alias");
    }

    @Test
    void parserRejectsCustomTags() {
        assertThatThrownBy(() -> parser.parse(PolicyStudioFixtures.customTag()))
                .isInstanceOf(PolicyParseException.class);
    }

    @Test
    void parserRejectsNonResourcePolicyShape() {
        assertThatThrownBy(() -> parser.parse(PolicyStudioFixtures.derivedRolesDocument()))
                .isInstanceOf(PolicyParseException.class)
                .hasMessageContaining("derivedRoles");
    }

    @Test
    void validatorRejectsWildcardGrant() {
        PolicyIR ir = parser.parse(PolicyStudioFixtures.wildcardGrant());
        GeneratedPolicyValidator.Result result = validator.validate(ir, acme());
        assertThat(result.accepted()).isFalse();
        assertThat(result.violations())
                .anyMatch(v -> v.contains("wildcard action"))
                .anyMatch(v -> v.contains("wildcard grant"));
    }

    @Test
    void validatorRejectsRootScopeRewrite() {
        PolicyIR ir = parser.parse(PolicyStudioFixtures.rootScopeRewrite());
        GeneratedPolicyValidator.Result result = validator.validate(ir, acme());
        assertThat(result.accepted()).isFalse();
        assertThat(result.violations()).anyMatch(v -> v.contains("root ceiling scope"));
    }

    @Test
    void validatorRejectsIdentityCollision() {
        // A candidate whose identity equals an existing base policy (agent@acme reserved).
        BaseCeiling collidingCeiling = new BaseCeiling(
                "agent", PolicyStudioFixtures.agentCeiling().tuples(), true,
                java.util.Set.of("agent@", "agent@acme"));
        PolicyAuthoringRequest req = new PolicyAuthoringRequest(
                "Restrict acme agents.", PolicyStudioFixtures.agentVocab(),
                TenantScope.of("acme"), false, collidingCeiling);

        PolicyIR ir = parser.parse(PolicyStudioFixtures.compliantAcme());
        GeneratedPolicyValidator.Result result = validator.validate(ir, req);
        assertThat(result.accepted()).isFalse();
        assertThat(result.violations()).anyMatch(v -> v.contains("collides with an existing base-bundle policy"));
    }

    @Test
    void validatorRejectsWhenBaseCeilingLacksBackstop() {
        BaseCeiling noBackstop = new BaseCeiling(
                "agent", PolicyStudioFixtures.agentCeiling().tuples(),
                /* carriesTenantEqualityBackstop */ false, java.util.Set.of("agent@"));
        PolicyAuthoringRequest req = new PolicyAuthoringRequest(
                "Restrict acme agents.", PolicyStudioFixtures.agentVocab(),
                TenantScope.of("acme"), false, noBackstop);

        PolicyIR ir = parser.parse(PolicyStudioFixtures.compliantAcme());
        GeneratedPolicyValidator.Result result = validator.validate(ir, req);
        assertThat(result.accepted()).isFalse();
        assertThat(result.violations()).anyMatch(v -> v.contains("tenant-equality backstop"));
    }
}
