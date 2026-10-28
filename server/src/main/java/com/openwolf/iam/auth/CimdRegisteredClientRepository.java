package com.openwolf.iam.auth;

import com.openwolf.iam.repository.TenantApplicationClientRepository;
import com.openwolf.iam.service.*;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.client.*;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import java.util.*;
import java.util.function.Consumer;

/** All repository lookups are storage-only. Metadata validation and assertion-key loading are explicit boundaries. */
public final class CimdRegisteredClientRepository implements RegisteredClientRepository {
    public static final String CLIENT_ID = "settings.client.axiom.cimd-client-id";
    public static final String DOCUMENT_NAME = "settings.client.axiom.cimd-document-name";
    private final RegisteredClientRepository stored;
    private final ObjectProvider<TenantApplicationService> applications;
    private final TenantApplicationClientRepository clients;
    private final CimdDocuments documents;
    private final ObjectProvider<AuditService> audit;
    public CimdRegisteredClientRepository(RegisteredClientRepository stored, ObjectProvider<TenantApplicationService> applications,
            TenantApplicationClientRepository clients, CimdDocuments documents, ObjectProvider<AuditService> audit) {
        this.stored = stored; this.applications = applications; this.clients = clients; this.documents = documents; this.audit = audit;
    }
    public RegisteredClient storedByClientId(String id) { return stored.findByClientId(id); }
    public RegisteredClient storedById(String id) { return stored.findById(id); }
    public void evictMetadata(String url) { documents.evict(url); }
    @Override public void save(RegisteredClient client) {
        String url = client.getClientSettings().getSetting(CLIENT_ID);
        if (url != null && url.equals(client.getClientId())) throw new IllegalArgumentException("CIMD views cannot be persisted");
        stored.save(client);
    }
    @Override public RegisteredClient findById(String id) {
        var binding = CimdClientContext.current();
        if (binding != null && id.equals(binding.registeredClientId()) && binding.validatedClient() != null) return binding.validatedClient();
        return view(stored.findById(id));
    }
    @Override public RegisteredClient findByClientId(String clientId) {
        if (clientId == null) return null;
        if (clientId.startsWith("https://")) {
            var binding = CimdClientContext.current();
            if (binding == null || !clientId.equals(binding.clientId())) return null;
            return findById(binding.registeredClientId());
        }
        RegisteredClient client = stored.findByClientId(clientId);
        if (client != null && client.getClientSettings().getSetting(CLIENT_ID) != null) return null;
        return client;
    }
    private RegisteredClient view(RegisteredClient client) {
        if (client == null) return null;
        String url = client.getClientSettings().getSetting(CLIENT_ID);
        if (url == null) return client;
        if (applications.getObject().activeAuthority(client.getClientId()).isEmpty() || clients.findByClientId(client.getClientId())
                .filter(row -> url.equals(row.getExternalClientId())).isEmpty()) return null;
        return RegisteredClient.from(client).clientId(url).build();
    }
    private Consumer<String> failureAudit(RegisteredClient client) {
        var row = stored.findById(client.getId());
        var authority = row == null ? null : applications.getObject().activeAuthority(row.getClientId()).orElse(null);
        if (authority == null) throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        return reason -> audit.getObject().logRequired(authority.tenantId(), "system", "CIMD_FETCH_FAILURE", "application_client", client.getClientId(),
                null, Map.of("applicationId", authority.applicationId().toString(), "reason", reason), null);
    }
    private CimdDocuments.Document document(RegisteredClient client, boolean assertion) {
        var metadata = assertion ? documents.forAuthentication(client.getClientId(), failureAudit(client))
                : documents.get(client.getClientId(), failureAudit(client));
        if (!client.getClientAuthenticationMethods().equals(Set.of(new ClientAuthenticationMethod(metadata.authenticationMethod())))) {
            throw new IllegalArgumentException("CIMD authentication method changed");
        }
        return metadata;
    }
    /** Called only for a fresh authorization request, before redirect/scope validation and consent. */
    public RegisteredClient validateAuthorization(RegisteredClient client) {
        var metadata = document(client, false);
        Set<String> effective = new LinkedHashSet<>();
        for (String allowed : client.getRedirectUris()) {
            if (metadata.redirects().stream().anyMatch(uri -> LoopbackRedirects.matches(allowed, uri))) effective.add(allowed);
        }
        if (effective.isEmpty()) throw new IllegalArgumentException("no redirect is approved by both document and administrator");
        var result = RegisteredClient.from(client)
                .redirectUris(uris -> { uris.clear(); uris.addAll(effective); })
                .clientSettings(ClientSettings.withSettings(client.getClientSettings().getSettings())
                        .setting(DOCUMENT_NAME, metadata.name()).build());
        if (metadata.scopes() != null) result.scopes(scopes -> scopes.retainAll(metadata.scopes()));
        if (!metadata.grants().contains("refresh_token")) {
            result.authorizationGrantTypes(grants -> grants.remove(AuthorizationGrantType.REFRESH_TOKEN));
            result.scopes(scopes -> scopes.remove(OfflineAccess.SCOPE));
        }
        return result.build();
    }
    /** Called only while verifying a private-key assertion; never by introspection, logout or consent management. */
    public RegisteredClient assertionClient(RegisteredClient client, String kid) {
        var metadata = document(client, true);
        var keys = documents.keys(metadata, kid, failureAudit(client));
        return RegisteredClient.from(client).clientSettings(ClientSettings.withSettings(client.getClientSettings().getSettings())
                .setting(ClientAssertionKeys.SETTING, keys.json()).tokenEndpointAuthenticationSigningAlgorithm(keys.algorithm()).build()).build();
    }
}
