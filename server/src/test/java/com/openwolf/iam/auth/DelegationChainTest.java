package com.openwolf.iam.auth;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DelegationChainTest {
    private static Map<String, Object> actor(String sub, String client, String workload, Object nested) {
        Map<String, Object> act = new LinkedHashMap<>();
        act.put("sub", sub);
        act.put("client_id", client);
        act.put("workload_id", workload);
        if (nested != null) act.put("act", nested);
        return act;
    }

    private static Map<String, Object> chain(int levels) {
        Map<String, Object> act = null;
        for (int i = levels; i >= 1; i--) act = actor("w" + i, "c" + i, "id" + i, act);
        return act;
    }

    @Test
    void aSubjectWithoutAnActorGetsOneLevel() {
        assertThat(DelegationChain.build(null, "workload:a", "a", "id-a"))
                .isEqualTo(Map.of("sub", "workload:a", "client_id", "a", "workload_id", "id-a"));
    }

    @Test
    void anActorChangeNestsTheWholePriorChainVerbatim() {
        Map<String, Object> prior = actor("workload:a", "a", "id-a", actor("workload:z", "z", "id-z", null));
        prior.put("extra", List.of("kept"));
        Map<String, Object> act = DelegationChain.build(prior, "workload:b", "b", "id-b");
        assertThat(act).containsEntry("sub", "workload:b").containsEntry("client_id", "b").containsEntry("workload_id", "id-b");
        assertThat(act.get("act")).as("the exact prior object, unchanged").isSameAs(prior);
        assertThat(DelegationChain.depth(act)).isEqualTo(3);
    }

    @Test
    void theSameActorKeepsThePriorChainUnchangedAndAddsNoLevel() {
        Map<String, Object> earlier = actor("workload:z", "z", "id-z", null);
        Map<String, Object> prior = actor("workload:a", "a", "id-a", earlier);
        Map<String, Object> act = DelegationChain.build(prior, "workload:a", "a", "id-a");
        assertThat(act.get("act")).isSameAs(earlier);
        assertThat(DelegationChain.depth(act)).isEqualTo(2);
        Map<String, Object> flat = DelegationChain.build(actor("workload:a", "a", "id-a", null), "workload:a", "a", "id-a");
        assertThat(flat).doesNotContainKey("act");
    }

    @Test
    void sameSubButDifferentVerifiedIdentityIsAnActorChange() {
        Map<String, Object> prior = actor("workload:a", "a", "id-a", null);
        assertThat(DelegationChain.build(prior, "workload:a", "a", "id-other")).containsKey("act");
        assertThat(DelegationChain.build(prior, "workload:a", "other", "id-a")).containsKey("act");
    }

    @Test
    void fiveLevelsAreAllowedASixthIsRefusedNeverTruncated() {
        assertThat(DelegationChain.depth(DelegationChain.build(chain(4), "w0", "c0", "id0"))).isEqualTo(5);
        assertThatThrownBy(() -> DelegationChain.build(chain(5), "w0", "c0", "id0"))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(e -> assertThat(((OAuth2AuthenticationException) e).getError().getErrorCode()).isEqualTo("invalid_grant"));
        assertThat(DelegationChain.depth(DelegationChain.build(chain(5), "w1", "c1", "id1"))).as("same actor, no new level")
                .isEqualTo(5);
        assertThatThrownBy(() -> DelegationChain.build(chain(6), "w1", "c1", "id1"))
                .as("an over-deep subject chain is refused even without a new level")
                .isInstanceOf(OAuth2AuthenticationException.class);
    }

    @Test
    void malformedChainsAreRefused() {
        Map<String, Object> blankSub = new HashMap<>(Map.of("sub", " ", "client_id", "a"));
        Map<String, Object> numericClient = new HashMap<>(Map.of("sub", "a", "client_id", 7));
        Map<String, Object> nestedString = new HashMap<>(Map.of("sub", "a", "client_id", "a", "act", "b"));
        Map<String, Object> nestedNoSub = new HashMap<>(Map.of("sub", "a", "client_id", "a",
                "act", Map.of("client_id", "z")));
        for (Object bad : List.of("a string", List.of(), Map.of("client_id", "a"), blankSub, numericClient, nestedString,
                nestedNoSub, Map.of("sub", 5))) {
            assertThatThrownBy(() -> DelegationChain.build(bad, "workload:b", "b", "id-b")).as(String.valueOf(bad))
                    .isInstanceOf(OAuth2AuthenticationException.class);
        }
        assertThatThrownBy(() -> DelegationChain.build(null, " ", "b", "id-b")).isInstanceOf(OAuth2AuthenticationException.class);
    }

    private static Map<String, Object> subject(String kind, String sub, Object act) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("identity_kind", kind);
        claims.put("sub", sub);
        if (act != null) claims.put("act", act);
        return claims;
    }

    @Test
    void aWorkloadActingForItselfHasNoActorEvenAfterSelfExchange() {
        // RFC 8693 section 4.1: act names a distinct party acting for sub; a service acting only for itself has none.
        assertThat(DelegationChain.forSubject(subject("workload", "a", null), "workload:a", "a", "id-a")).isNull();
    }

    @Test
    void anotherWorkloadTakingOverAServiceSubjectIsTheOnlyActor() {
        assertThat(DelegationChain.forSubject(subject("workload", "a", null), "workload:b", "b", "id-b"))
                .isEqualTo(Map.of("sub", "workload:b", "client_id", "b", "workload_id", "id-b"));
        // A later actor change nests B under C as usual.
        Map<String, Object> b = actor("workload:b", "b", "id-b", null);
        assertThat(DelegationChain.forSubject(subject("workload", "a", b), "workload:c", "c", "id-c").get("act"))
                .isSameAs(b);
    }

    @Test
    void onlyAWorkloadSubjectCanBeItsOwnActor() {
        // A person (or customer) whose id happens to equal the acting client still gets an actor.
        assertThat(DelegationChain.forSubject(subject("workforce", "a", null), "workload:a", "a", "id-a"))
                .isEqualTo(Map.of("sub", "workload:a", "client_id", "a", "workload_id", "id-a"));
        assertThat(DelegationChain.forSubject(subject("customer", "a", null), "workload:a", "a", "id-a")).isNotNull();
        assertThat(DelegationChain.forSubject(subject(null, "a", null), "workload:a", "a", "id-a")).isNotNull();
    }

    @Test
    void aServiceSubjectWithAMalformedOrOverDeepChainIsStillRefused() {
        assertThatThrownBy(() -> DelegationChain.forSubject(subject("workload", "a", "x"), "workload:a", "a", "id-a"))
                .isInstanceOf(OAuth2AuthenticationException.class);
        assertThatThrownBy(() -> DelegationChain.forSubject(subject("workload", "a", chain(5)), "workload:b", "b", "id-b"))
                .isInstanceOf(OAuth2AuthenticationException.class);
    }
}
