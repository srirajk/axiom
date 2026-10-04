package com.openwolf.iam.auth;

import com.openwolf.iam.service.TenantApplicationService;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

/**
 * Authorization-server view of registered clients: a tenant application client that is no longer active (client
 * disabled, application disabled, or tenant inactive) is not found by client id.
 *
 * <p>Spring Authorization Server resolves clients by id for client authentication (confidential and public), the
 * authorization endpoint and consent, so an inactive client fails there with the standard OAuth errors
 * ({@code invalid_client} at the token endpoint; {@code invalid_request} for {@code client_id} at the authorization
 * endpoint) before any token is generated. Platform system clients have no tenant application row and are unaffected.
 *
 * <p>{@link #findById} is deliberately not filtered: it resolves the client of an existing authorization (for example
 * during introspection), and those flows have their own session and authority checks.
 */
public class ActiveApplicationClientRepository implements RegisteredClientRepository {

    private final RegisteredClientRepository delegate;
    private final ObjectProvider<TenantApplicationService> applications;

    public ActiveApplicationClientRepository(RegisteredClientRepository delegate,
                                             ObjectProvider<TenantApplicationService> applications) {
        this.delegate = delegate;
        this.applications = applications;
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        delegate.save(registeredClient);
    }

    @Override
    public RegisteredClient findById(String id) {
        return delegate.findById(id);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        RegisteredClient client = delegate.findByClientId(clientId);
        if (client == null) return null;
        TenantApplicationService service = applications.getIfAvailable();
        if (service != null && service.knownButDisabled(clientId)) return null;
        return client;
    }
}
