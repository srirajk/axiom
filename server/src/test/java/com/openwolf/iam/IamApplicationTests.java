package com.openwolf.iam;

import org.junit.jupiter.api.Test;

/**
 * Placeholder test class.
 * <p>
 * A full context smoke test requires a PostgreSQL database (or Testcontainers).
 * To run integration tests: add {@code org.testcontainers:postgresql} and use
 * {@code @Testcontainers} + {@code @SpringBootTest}.
 * <p>
 * H2 is intentionally not used for context load tests because the entities
 * use PostgreSQL-native column definitions (JSONB) that H2 does not support.
 * </p>
 */
class IamApplicationTests {

    @Test
    void placeholder() {
        // Add Testcontainers integration test here when running with Docker available.
        // Example: spin up PostgreSQL, run the full context, assert /health returns 200.
    }
}
