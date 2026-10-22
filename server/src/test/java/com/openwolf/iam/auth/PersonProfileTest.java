package com.openwolf.iam.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;

class PersonProfileTest {
    @Test
    void derivesFullNameWithoutInventingMissingParts() {
        assertThat(PersonProfile.claims(Map.of("given_name", "John", "family_name", "Smith")))
                .containsEntry("name", "John Smith")
                .containsEntry("given_name", "John")
                .containsEntry("family_name", "Smith");
        assertThat(PersonProfile.claims(Map.of())).isEmpty();
    }

    @Test
    void explicitDisplayNameAndScimStructuredNameArePreserved() {
        assertThat(PersonProfile.claims(Map.of("given_name", "Rita", "family_name", "Lopez",
                "display_name", "Dr. Rita Lopez")))
                .containsEntry("name", "Dr. Rita Lopez");
        assertThat(PersonProfile.claims(Map.of("name", Map.of("givenName", "Ravi", "familyName", "Kumar"))))
                .containsEntry("name", "Ravi Kumar")
                .containsEntry("given_name", "Ravi")
                .containsEntry("family_name", "Kumar");
    }
}
