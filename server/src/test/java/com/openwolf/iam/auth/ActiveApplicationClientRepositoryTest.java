package com.openwolf.iam.auth;

import com.openwolf.iam.service.TenantApplicationService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ActiveApplicationClientRepositoryTest {

    private final RegisteredClientRepository delegate = mock(RegisteredClientRepository.class);
    private final TenantApplicationService applications = mock(TenantApplicationService.class);
    @SuppressWarnings("unchecked")
    private final ObjectProvider<TenantApplicationService> provider = mock(ObjectProvider.class);
    private final ActiveApplicationClientRepository repository =
            new ActiveApplicationClientRepository(delegate, provider);

    @Test
    void activeOrSystemClientIsResolved() {
        when(provider.getIfAvailable()).thenReturn(applications);
        RegisteredClient client = client("tenant-svc");
        when(delegate.findByClientId("tenant-svc")).thenReturn(client);
        when(applications.knownButDisabled("tenant-svc")).thenReturn(false);

        assertThat(repository.findByClientId("tenant-svc")).isSameAs(client);
    }

    @Test
    void inactiveTenantApplicationClientIsNotResolvableByClientId() {
        when(provider.getIfAvailable()).thenReturn(applications);
        when(delegate.findByClientId("tenant-svc")).thenReturn(client("tenant-svc"));
        when(applications.knownButDisabled("tenant-svc")).thenReturn(true);

        assertThat(repository.findByClientId("tenant-svc")).isNull();
    }

    @Test
    void unknownClientStaysUnknownWithoutConsultingApplications() {
        when(provider.getIfAvailable()).thenReturn(applications);

        assertThat(repository.findByClientId("missing")).isNull();
        verify(applications, never()).knownButDisabled("missing");
    }

    @Test
    void findByIdAndSaveDelegateUnfiltered() {
        RegisteredClient client = client("tenant-svc");
        when(delegate.findById("id-tenant-svc")).thenReturn(client);

        assertThat(repository.findById("id-tenant-svc")).isSameAs(client);
        repository.save(client);
        verify(delegate).save(client);
        verify(provider, never()).getIfAvailable();
    }

    private static RegisteredClient client(String clientId) {
        return RegisteredClient.withId("id-" + clientId).clientId(clientId)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).build();
    }
}
