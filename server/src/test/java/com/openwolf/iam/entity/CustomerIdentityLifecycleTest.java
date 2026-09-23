package com.openwolf.iam.entity;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CustomerIdentityLifecycleTest {
    private static final Instant NOW = Instant.parse("2026-09-19T10:00:00Z");

    @Test
    void verificationRecoveryAndSuspensionAreExplicitStateTransitions() {
        CustomerIdentity customer = new CustomerIdentity("tenant-1", "customer@example.com",
                "Customer", "encoded-1", NOW);

        assertThat(customer.getStatus()).isEqualTo(CustomerIdentity.Status.PENDING_VERIFICATION);
        customer.verify(NOW.plusSeconds(1));
        assertThat(customer.getStatus()).isEqualTo(CustomerIdentity.Status.ACTIVE);
        assertThat(customer.getTokenVersion()).isEqualTo(1);

        customer.recoverCredential("encoded-2", NOW.plusSeconds(2));
        assertThat(customer.getPasswordHash()).isEqualTo("encoded-2");
        assertThat(customer.getTokenVersion()).isEqualTo(2);

        customer.suspend(NOW.plusSeconds(3));
        assertThat(customer.getStatus()).isEqualTo(CustomerIdentity.Status.SUSPENDED);
        assertThat(customer.getTokenVersion()).isEqualTo(3);
        assertThatThrownBy(() -> customer.recoverCredential("encoded-3", NOW.plusSeconds(4)))
                .isInstanceOf(IllegalStateException.class);

        customer.reactivate(NOW.plusSeconds(5));
        assertThat(customer.getStatus()).isEqualTo(CustomerIdentity.Status.ACTIVE);
        assertThat(customer.getTokenVersion()).isEqualTo(4);
    }
}
