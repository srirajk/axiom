package com.openwolf.iam.scim;

import com.openwolf.iam.entity.ScimProvisioningSource;
import com.openwolf.iam.repository.ScimProvisioningSourceRepository;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ScimCredentialServiceTest {
    @Test
    void authenticatesSelectorAndSecretWithoutPersistingBearerSecret() {
        ScimProvisioningSourceRepository repository = mock(ScimProvisioningSourceRepository.class);
        ScimCredentialService service = new ScimCredentialService(repository);
        ScimCredentialService.Credential issued = service.issue();
        ScimProvisioningSource source = new ScimProvisioningSource("tenant-a", null, "Directory",
                issued.selector(), issued.secretHash());
        when(repository.findBySelector(issued.selector())).thenReturn(Optional.of(source));

        assertThat(service.authenticate(issued.bearer())).isSameAs(source);
        assertThat(source.getSecretHash()).doesNotContain(issued.secret());
        source.revoke();
        assertThatThrownBy(() -> service.authenticate(issued.bearer())).isInstanceOf(ScimException.class);
    }
}
