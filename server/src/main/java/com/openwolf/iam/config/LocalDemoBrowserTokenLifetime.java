package com.openwolf.iam.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Local-demo-only browser-session override.
 *
 * <p>The secure production default remains the one-hour token lifetime stored with each client.
 * This reconciler is disabled unless the local Compose stack explicitly names one public PKCE
 * client and supplies a bounded lifetime.</p>
 */
@Component
@ConditionalOnProperty(name = "iam.local-demo.browser-client-id")
public final class LocalDemoBrowserTokenLifetime implements ApplicationRunner {
    private static final long MIN_SECONDS = 3_600;
    private static final long MAX_SECONDS = 86_400;

    private final RegisteredClientRepository clients;
    private final String clientId;
    private final long lifetimeSeconds;

    public LocalDemoBrowserTokenLifetime(
            RegisteredClientRepository clients,
            @Value("${iam.local-demo.browser-client-id}") String clientId,
            @Value("${iam.local-demo.browser-token-ttl-seconds:3600}") long lifetimeSeconds) {
        this.clients = clients;
        this.clientId = clientId;
        this.lifetimeSeconds = lifetimeSeconds;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (clientId == null || clientId.isBlank()) {
            throw new IllegalStateException("local-demo browser client id is required");
        }
        if (lifetimeSeconds < MIN_SECONDS || lifetimeSeconds > MAX_SECONDS) {
            throw new IllegalStateException("local-demo browser token lifetime must be within 3600-86400 seconds");
        }
        RegisteredClient current = clients.findByClientId(clientId);
        if (current == null) {
            // Consumer applications register their browser clients through Axiom's API after the
            // first runtime startup. The deployment restarts Axiom after registration so this
            // optional local-demo override can reconcile the newly created client.
            return;
        }
        if (!current.getClientAuthenticationMethods().equals(java.util.Set.of(ClientAuthenticationMethod.NONE))
                || !current.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE)
                || current.getClientSecret() != null) {
            throw new IllegalStateException("local-demo token override requires the exact public PKCE client posture");
        }
        Duration desired = Duration.ofSeconds(lifetimeSeconds);
        if (desired.equals(current.getTokenSettings().getAccessTokenTimeToLive())) {
            return;
        }
        clients.save(RegisteredClient.from(current)
                .tokenSettings(TokenSettings.withSettings(current.getTokenSettings().getSettings())
                        .accessTokenTimeToLive(desired)
                        .build())
                .build());
    }
}
