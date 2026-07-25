package com.openwolf.iam.tenancy;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ProvisioningOperationRepositoryContractTest {

    @Test
    void postgresVoidAdvisoryLockResultIsNotCoercedToAnInteger() throws NoSuchMethodException {
        assertThat(ProvisioningOperationRepository.class
                .getMethod("lockIdempotencyKey", String.class)
                .getReturnType())
                .isEqualTo(void.class);
    }
}
