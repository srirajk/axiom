package com.openwolf.iam.auth;

import java.util.List;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class ApplicationResourceUrisTest {
    @Test void exactAndPrefixHaveDifferentBoundaries() {
        assertThat(ApplicationResourceUris.matches("https://edge.example.test/exact", List.of("https://edge.example.test/exact"))).isTrue();
        assertThat(ApplicationResourceUris.matches("https://edge.example.test/exact/child", List.of("https://edge.example.test/exact"))).isFalse();
        assertThat(ApplicationResourceUris.matches("https://edge.example.test/tools/crm", List.of("https://edge.example.test/tools/"))).isTrue();
        assertThat(ApplicationResourceUris.matches("https://edge.example.test/toolsmith", List.of("https://edge.example.test/tools/"))).isFalse();
    }

    @Test void registrationRequiresSafeHttpsUri() {
        for (String uri : List.of("http://edge.example.test/", "https://edge.example.test/frag#x",
                "https://user@edge.example.test/", "https://edge.example.test/tools/../admin", "/relative")) {
            assertThatThrownBy(() -> ApplicationResourceUris.validate(List.of(uri))).isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test void overlappingRegistrationsCanBeDetectedAcrossApplications() {
        assertThat(ApplicationResourceUris.overlaps("https://edge.example.test/tools/", "https://edge.example.test/tools/crm")).isTrue();
        assertThat(ApplicationResourceUris.overlaps("https://edge.example.test/tools/", "https://edge.example.test/other/")).isFalse();
    }
}
