package com.openwolf.iam.config;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

class LocalDemoBrowserTokenLifetimeTest {

    @Test
    void defersOverrideUntilConsumerRegistersItsBrowserClient() {
        RegisteredClientRepository clients = mock(RegisteredClientRepository.class);
        when(clients.findByClientId("probata-console")).thenReturn(null);
        LocalDemoBrowserTokenLifetime reconciler =
                new LocalDemoBrowserTokenLifetime(clients, "probata-console", 28_800);

        reconciler.run(null);

        verify(clients).findByClientId("probata-console");
        verifyNoMoreInteractions(clients);
    }
}
