package com.openwolf.iam.service;

import com.openwolf.iam.exception.EntityNotFoundException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * A customer's view of the OAuth consents they granted to customer-facing applications (the standard Spring
 * Authorization Server consent records), and the customer's own withdrawal. Withdrawal removes the consent (the next
 * sign-in asks again when the client requires consent) and ends every session the customer holds with that client, so
 * its refresh tokens, access tokens and exchanged descendants stop at once for online checks. Only the customer may
 * withdraw; operators end sessions through the session administration API instead.
 */
@Service
@Transactional
public class CustomerOAuthConsentService {
    public record ConsentResponse(String clientId, List<String> scopes, boolean consentRecorded) {}

    private final JdbcTemplate jdbc;
    private final RegisteredClientRepository registeredClients;
    private final OAuth2AuthorizationConsentService consents;
    private final TenantApplicationService applications;
    private final IamSessionService sessions;
    private final CiamLifecycleAuditService audit;

    public CustomerOAuthConsentService(JdbcTemplate jdbc, RegisteredClientRepository registeredClients,
                                       OAuth2AuthorizationConsentService consents, TenantApplicationService applications,
                                       IamSessionService sessions, CiamLifecycleAuditService audit) {
        this.jdbc = jdbc;
        this.registeredClients = registeredClients;
        this.consents = consents;
        this.applications = applications;
        this.sessions = sessions;
        this.audit = audit;
    }

    @Transactional(readOnly = true)
    public List<ConsentResponse> list(String tenantId, UUID customerId) {
        return jdbc.query("SELECT registered_client_id, authorities FROM oauth2_authorization_consent WHERE principal_name = ?",
                        (row, n) -> Map.entry(row.getString(1), row.getString(2)), customerId.toString()).stream()
                .map(entry -> registeredClients.findById(entry.getKey()))
                .filter(client -> client != null && customerClientOf(tenantId, client.getClientId()))
                .map(client -> response(client, consents.findById(client.getId(), customerId.toString())))
                .toList();
    }

    public ConsentResponse withdraw(String tenantId, UUID customerId, String clientId, String correlationId) {
        if (!customerClientOf(tenantId, clientId)) throw EntityNotFoundException.forId("Customer application client", clientId);
        RegisteredClient client = registeredClients.findByClientId(clientId);
        if (client == null) throw EntityNotFoundException.forId("Customer application client", clientId);
        OAuth2AuthorizationConsent consent = consents.findById(client.getId(), customerId.toString());
        if (consent != null) consents.remove(consent);
        int ended = sessions.revokeAllForPrincipalAndClient(tenantId, customerId.toString(), clientId,
                "customer withdrew application consent");
        audit.record(tenantId, customerId.toString(), "CUSTOMER_OAUTH_CONSENT_WITHDRAWN", "application_client", clientId,
                Map.of("consentRecordRemoved", consent != null, "endedSessions", ended), correlationId);
        return new ConsentResponse(clientId, List.of(), false);
    }

    private boolean customerClientOf(String tenantId, String clientId) {
        return applications.activeAuthority(clientId)
                .filter(TenantApplicationService.ClientAuthority::customerSignIn)
                .filter(authority -> authority.tenantId().equals(tenantId)).isPresent();
    }

    private static ConsentResponse response(RegisteredClient client, OAuth2AuthorizationConsent consent) {
        List<String> scopes = consent == null ? List.of() : consent.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).filter(value -> value.startsWith("SCOPE_"))
                .map(value -> value.substring("SCOPE_".length())).sorted().toList();
        return new ConsentResponse(client.getClientId(), scopes, consent != null);
    }
}
