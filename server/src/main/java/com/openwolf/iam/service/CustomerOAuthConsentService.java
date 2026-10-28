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
    public record ConsentResponse(String clientId, List<String> scopes, boolean consentRecorded, String consentId, String applicationId) {
        public ConsentResponse(String clientId, List<String> scopes, boolean consentRecorded) { this(clientId, scopes, consentRecorded, null, null); }
    }

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
                .filter(client -> client != null && customerAuthority(tenantId, client).isPresent())
                .map(client -> response(client, consents.findById(client.getId(), customerId.toString()), customerAuthority(tenantId, client).orElseThrow().applicationId()))
                .toList();
    }

    public ConsentResponse withdraw(String tenantId, UUID customerId, String clientId, String correlationId) {
        // The legacy path remains for ordinary client ids. Shared CIMD URLs use the opaque registration id below.
        if (clientId.startsWith("https://")) throw EntityNotFoundException.forId("Customer application client", clientId);
        RegisteredClient client = registeredClients.findByClientId(clientId);
        if (client == null) throw EntityNotFoundException.forId("Customer application client", clientId);
        return withdrawRegistration(tenantId, customerId, client.getId(), correlationId);
    }

    public ConsentResponse withdrawRegistration(String tenantId, UUID customerId, String registeredClientId, String correlationId) {
        RegisteredClient client = registeredClients.findById(registeredClientId);
        var authority = client == null ? null : customerAuthority(tenantId, client).orElse(null);
        if (authority == null) throw EntityNotFoundException.forId("Customer application consent", registeredClientId);
        OAuth2AuthorizationConsent consent = consents.findById(client.getId(), customerId.toString());
        boolean cimd = client.getClientSettings().getSetting(com.openwolf.iam.auth.CimdRegisteredClientRepository.CLIENT_ID) != null;
        if (cimd && consent == null) throw EntityNotFoundException.forId("Customer application consent", registeredClientId);
        if (consent != null) consents.remove(consent);
        int ended = cimd ? sessions.revokeAllForPrincipalAndApplicationClient(tenantId, customerId.toString(), authority.applicationId(), client.getClientId(),
                "customer withdrew application consent") : sessions.revokeAllForPrincipalAndClient(tenantId, customerId.toString(), client.getClientId(),
                "customer withdrew application consent");
        audit.record(tenantId, customerId.toString(), "CUSTOMER_OAUTH_CONSENT_WITHDRAWN", "application_client", client.getClientId(),
                Map.of("consentRecordRemoved", consent != null, "endedSessions", ended, "applicationId", authority.applicationId().toString(),
                        "consentId", registeredClientId), correlationId);
        return new ConsentResponse(client.getClientId(), List.of(), false, client.getId(), authority.applicationId().toString());
    }

    private java.util.Optional<TenantApplicationService.ClientAuthority> customerAuthority(String tenantId, RegisteredClient client) {
        var resolved = client.getClientSettings().getSetting(com.openwolf.iam.auth.CimdRegisteredClientRepository.CLIENT_ID) != null
                ? applications.activeAuthorityByRegisteredClientId(client.getId()) : applications.activeAuthority(client.getClientId());
        return resolved.filter(TenantApplicationService.ClientAuthority::customerSignIn).filter(authority -> authority.tenantId().equals(tenantId));
    }

    private static ConsentResponse response(RegisteredClient client, OAuth2AuthorizationConsent consent, UUID applicationId) {
        List<String> scopes = consent == null ? List.of() : consent.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).filter(value -> value.startsWith("SCOPE_"))
                .map(value -> value.substring("SCOPE_".length())).sorted().toList();
        return new ConsentResponse(client.getClientId(), scopes, consent != null, client.getId(), applicationId.toString());
    }
}
