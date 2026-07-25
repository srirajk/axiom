package com.openwolf.iam.policystudio;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ProductionPdpDecisionSourceTest {

    @Test
    void failsClosedWhenPinnedCerbosIsUnavailable() {
        CerbosBatchDecisionSource cerbos = mock(CerbosBatchDecisionSource.class);
        when(cerbos.isAvailable()).thenReturn(false);
        ProductionPdpDecisionSource source = new ProductionPdpDecisionSource(cerbos);

        assertThatThrownBy(() -> source.evaluate(mock(BundleSnapshot.class), List.of()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("refusing to compute")
                .hasMessageContaining("approximation");
    }
}
