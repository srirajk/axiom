package com.openwolf.iam.authority.approval;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Phase 3.7 canonical action form: a known-answer vector (computed independently) and the rejection rules. */
class ActionCanonicalizerTest {
    private final ObjectMapper json = new ObjectMapper();

    @Test
    void matchesAnIndependentlyComputedKnownAnswer() throws Exception {
        // Computed with Python: json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + SHA-256.
        var action = json.readTree("{\"payee\":\"ACME-GB-001\",\"invoice\":\"INV-1001\",\"amount\":{\"minor\":12500,"
                + "\"currency\":\"GBP\"},\"memo\":\"Pay \\\"now\\\"\",\"urgent\":true,\"lines\":[2,1]}");
        var canonical = ActionCanonicalizer.canonicalize("payment.execute", "payments:t:1", action);
        assertThat(canonical.json()).isEqualTo("{\"action\":{\"amount\":{\"currency\":\"GBP\",\"minor\":12500},"
                + "\"invoice\":\"INV-1001\",\"lines\":[2,1],\"memo\":\"Pay \\\"now\\\"\",\"payee\":\"ACME-GB-001\","
                + "\"urgent\":true},\"audience\":\"payments:t:1\",\"type\":\"payment.execute\"}");
        assertThat(canonical.digest()).isEqualTo("650da7d898772c25813c8f448cea40d9d1a82b94a0c1bfd174c6f63c89aab556");
    }

    @Test
    void keyOrderDoesNotMatterButEveryValueAudienceAndTypeDoes() throws Exception {
        var a = ActionCanonicalizer.canonicalize("payment.execute", "aud", json.readTree("{\"a\":1,\"b\":\"x\"}"));
        var b = ActionCanonicalizer.canonicalize("payment.execute", "aud", json.readTree("{\"b\":\"x\",\"a\":1}"));
        assertThat(a).isEqualTo(b);
        assertThat(ActionCanonicalizer.canonicalize("payment.execute", "aud", json.readTree("{\"a\":2,\"b\":\"x\"}"))
                .digest()).isNotEqualTo(a.digest());
        assertThat(ActionCanonicalizer.canonicalize("payment.refund", "aud", json.readTree("{\"a\":1,\"b\":\"x\"}"))
                .digest()).isNotEqualTo(a.digest());
        assertThat(ActionCanonicalizer.canonicalize("payment.execute", "other", json.readTree("{\"a\":1,\"b\":\"x\"}"))
                .digest()).isNotEqualTo(a.digest());
    }

    @Test
    void rejectsAmbiguousValues() {
        assertThatThrownBy(() -> ActionCanonicalizer.canonicalize("t.x", "aud", json.readTree("{\"amount\":1.5}")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ActionCanonicalizer.canonicalize("t.x", "aud", json.readTree("{\"payee\":null}")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ActionCanonicalizer.canonicalize("t.x", "aud", json.readTree("{}")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ActionCanonicalizer.canonicalize("t.x", "aud", json.readTree("[1]")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ActionCanonicalizer.canonicalize("t.x", "aud",
                json.readTree("{\"a\":{\"b\":{\"c\":{\"d\":{\"e\":{\"f\":1}}}}}}"))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ActionCanonicalizer.canonicalize("t.x", "aud",
                json.readTree("{\"n\":99999999999999999999999}"))).isInstanceOf(IllegalArgumentException.class);
    }
}
