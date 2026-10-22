package com.openwolf.iam.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.openwolf.iam.entity.Principal;
import com.openwolf.iam.repository.PrincipalRepository;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

class OidcClaimEnricherProfileTest {
    @Test
    void scopesSeparateProfileAndEmail() {
        PrincipalRepository repository = mock(PrincipalRepository.class);
        Principal john = new Principal("john", "tenant-a", "john_login", "john@example.test",
                "encoded", true, "{\"given_name\":\"John\",\"family_name\":\"Smith\"}");
        when(repository.findById("john")).thenReturn(Optional.of(john));
        OidcClaimEnricher enricher = new OidcClaimEnricher(repository, new ObjectMapper());

        assertThat(enricher.enrichIdToken("john", Set.of("profile")))
                .containsEntry("name", "John Smith")
                .containsEntry("given_name", "John")
                .containsEntry("family_name", "Smith")
                .containsEntry("preferred_username", "john_login")
                .doesNotContainKey("email");
        assertThat(enricher.enrichIdToken("john", Set.of("email")))
                .containsEntry("email", "john@example.test")
                .doesNotContainKey("email_verified")
                .doesNotContainKey("name");
        assertThat(enricher.enrichIdToken("john", Set.of())).isEmpty();
    }
}
