package com.openwolf.iam.service;

import com.openwolf.iam.auth.ExecutionTenant;
import com.openwolf.iam.auth.ApplicationScopes;
import com.openwolf.iam.dto.CreatedTenantApplicationClientResponse;
import com.openwolf.iam.dto.CreateTenantApplicationClientRequest;
import com.openwolf.iam.dto.CreateTenantApplicationRequest;
import com.openwolf.iam.dto.TenantApplicationClientResponse;
import com.openwolf.iam.dto.TenantApplicationResponse;
import com.openwolf.iam.dto.RevokeTenantApplicationClientRequest;
import com.openwolf.iam.dto.RotateTenantApplicationClientSecretRequest;
import com.openwolf.iam.entity.TenantApplication;
import com.openwolf.iam.entity.TenantApplicationClient;
import com.openwolf.iam.exception.EntityNotFoundException;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.repository.TenantApplicationClientRepository;
import com.openwolf.iam.repository.TenantApplicationRepository;
import com.openwolf.iam.repository.TenantRepository;
import com.openwolf.iam.tenancy.ActiveTenantDirectory;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import com.openwolf.iam.auth.TokenExchangeConstants;
import com.openwolf.iam.auth.BusinessScopeRegistry;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.URI;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/** AXP-1 product registry. It never exposes Spring's client rows or stored secrets directly. */
@Service
@Transactional
public class TenantApplicationService {
    private static final Set<String> PUBLIC_SCOPES = Set.of(OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL, "roles");
    /** Customers are a separate population: no workforce roles scope. */
    private static final Set<String> CUSTOMER_SCOPES = Set.of(OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL);
    /** OIDC Core section 11: requesting it (and being granted it) is what makes a refresh token issuable. */
    public static final String OFFLINE_ACCESS = "offline_access";
    private static final Set<String> SERVICE_SCOPES = Set.of(
            ApplicationScopes.APPLICATION_READ,
            ApplicationScopes.SUBJECT_CONTEXT_READ,
            ApplicationScopes.PLATFORM_AUTHZ_DECIDE,
            ApplicationScopes.USERS_READ_PROFILE);
    private static final SecureRandom SECRET_RANDOM = new SecureRandom();

    private final TenantApplicationRepository applications;
    private final TenantApplicationClientRepository clients;
    private final TenantRepository tenants;
    private final ActiveTenantDirectory activeTenants;
    private final RegisteredClientRepository registeredClients;
    private final PasswordEncoder passwordEncoder;
    private final ExecutionTenant executionTenant;
    private final AuditService audit;
    private final BusinessScopeRegistry businessScopes;
    private final TenantClientLookup clientLookup;

    @Autowired
    public TenantApplicationService(TenantApplicationRepository applications, TenantApplicationClientRepository clients,
                                    TenantRepository tenants, ActiveTenantDirectory activeTenants, RegisteredClientRepository registeredClients,
                                    PasswordEncoder passwordEncoder,
                                    ExecutionTenant executionTenant, AuditService audit,
                                    BusinessScopeRegistry businessScopes) {
        this.applications = applications; this.clients = clients; this.tenants = tenants; this.activeTenants = activeTenants;
        this.registeredClients = registeredClients; this.passwordEncoder = passwordEncoder;
        this.executionTenant = executionTenant; this.audit = audit; this.businessScopes = businessScopes;
        this.clientLookup = new TenantClientLookup(clients);
    }

    /** Focused-test constructor with no deployment-approved business scopes. */
    public TenantApplicationService(TenantApplicationRepository applications, TenantApplicationClientRepository clients,
                                    TenantRepository tenants, ActiveTenantDirectory activeTenants, RegisteredClientRepository registeredClients,
                                    PasswordEncoder passwordEncoder, ExecutionTenant executionTenant, AuditService audit) {
        this(applications, clients, tenants, activeTenants, registeredClients, passwordEncoder, executionTenant, audit,
                new BusinessScopeRegistry(""));
    }

    @Transactional(readOnly = true)
    public List<TenantApplicationResponse> list(String tenantId) {
        requireTenantAdmin(tenantId);
        requireActiveTenant(tenantId);
        return applications.findByTenantIdOrderByApplicationKey(tenantId).stream().map(this::applicationResponse).toList();
    }

    @Transactional(readOnly = true)
    public TenantApplicationResponse get(String tenantId, UUID applicationId) {
        return applicationResponse(applicationForTenant(tenantId, applicationId));
    }

    public TenantApplicationResponse create(String tenantId, CreateTenantApplicationRequest request, HttpServletRequest httpRequest) {
        requireTenantAdmin(tenantId);
        requireActiveTenant(tenantId);
        if (tenants.findById(tenantId).isEmpty()) throw EntityNotFoundException.forId("Tenant", tenantId);
        if (com.openwolf.iam.auth.AxiomApiJwtValidator.isReservedAudience(request.audience())) {
            throw new IllegalArgumentException("Application audience is reserved for the Axiom platform API");
        }
        if (applications.existsByTenantIdAndApplicationKey(tenantId, request.applicationKey())) {
            throw new ResourceConflictException("Application key already exists for this tenant");
        }
        TenantApplication application = applications.save(new TenantApplication(tenantId, request.applicationKey(),
                request.displayName(), request.description(), request.audience()));
        TenantApplicationResponse response = applicationResponse(application);
        audit.logRequired(tenantId, audit.currentActor(), "CREATE_APPLICATION", "application",
                application.getId().toString(), null, response, correlation(httpRequest));
        return response;
    }

    @Transactional(readOnly = true)
    public List<TenantApplicationClientResponse> listClients(String tenantId, UUID applicationId) {
        TenantApplication app = applicationForTenant(tenantId, applicationId);
        return clients.findByApplicationIdOrderByClientId(app.getId()).stream().filter(c -> c.getExternalClientId() == null).map(this::clientResponse).toList();
    }

    public CreatedTenantApplicationClientResponse createClient(String tenantId, UUID applicationId,
                                                                 CreateTenantApplicationClientRequest request,
                                                                 HttpServletRequest httpRequest) {
        TenantApplication app = applicationForTenant(tenantId, applicationId);
        if (app.getStatus() != TenantApplication.Status.ACTIVE) throw new ResourceConflictException("Application is disabled");
        String supplied = request.clientSecret();
        boolean keyAuthenticated = ClientAssertionKeys.PRIVATE_KEY_JWT.equals(request.tokenEndpointAuthMethod());
        if (supplied != null) {
            if (request.clientType() != TenantApplicationClient.Type.CONFIDENTIAL_SERVICE || keyAuthenticated) {
                throw new IllegalArgumentException("Only secret-authenticated confidential service clients accept a client secret");
            }
            OperatorSuppliedClientSecrets.requireValid(supplied);
        }
        TenantApplicationClient.Population population = population(request);
        if (registeredClients.findByClientId(request.clientId()) != null || clients.findByClientId(request.clientId()).isPresent()) {
            throw new ResourceConflictException("Client id already exists");
        }
        List<String> scopes = approvedScopes(tenantId, request.clientType(), population, request.scopes(), Boolean.TRUE.equals(request.refreshTokens()));
        boolean hasSecret = request.clientType() == TenantApplicationClient.Type.CONFIDENTIAL_WEB
                || (request.clientType() == TenantApplicationClient.Type.CONFIDENTIAL_SERVICE && !keyAuthenticated);
        String secret = hasSecret ? (supplied != null ? supplied : generatedSecret()) : null;
        RegisteredClient registered = registeredClient(app, request, scopes, secret, population);
        registeredClients.save(registered);
        TenantApplicationClient client = clients.save(new TenantApplicationClient(app.getId(), request.clientId(),
                request.clientType(), scopes, population));
        TenantApplicationClientResponse response = clientResponse(client, registered);
        audit.logRequired(tenantId, audit.currentActor(), "CREATE_APPLICATION_CLIENT", "application_client",
                client.getId().toString(), null, response, correlation(httpRequest));
        // An operator-supplied secret is never echoed: the caller already holds it.
        return new CreatedTenantApplicationClientResponse(response, supplied != null ? null : secret);
    }

    /** Adds a distinct application approval for a shared, external OAuth client identifier. No remote fetch occurs here. */
    public com.openwolf.iam.dto.TrustedClientResponse createTrustedClient(String tenantId, UUID applicationId,
            com.openwolf.iam.dto.TrustedClientRequest request, HttpServletRequest httpRequest) {
        TenantApplication app = applicationForTenant(tenantId, applicationId);
        com.openwolf.iam.auth.CimdHttpFetcher.requireUrl(request.clientId());
        if (!Set.of("none", "private_key_jwt").contains(request.tokenEndpointAuthMethod())) {
            throw new IllegalArgumentException("unsupported trusted client authentication method");
        }
        if (request.redirectUris() == null || request.redirectUris().isEmpty() || request.redirectUris().size() > 32) {
            throw new IllegalArgumentException("trusted redirects are required");
        }
        request.redirectUris().forEach(com.openwolf.iam.auth.CimdDocuments::requireRedirect);
        if (clients.existsByApplicationIdAndExternalClientIdAndStatus(applicationId, request.clientId(), TenantApplicationClient.Status.ACTIVE)) {
            throw new ResourceConflictException("This application already has an approval for that client URL");
        }
        List<String> requestedScopes = request.scopes();
        if (requestedScopes == null || requestedScopes.isEmpty()) {
            Set<String> inherited = new LinkedHashSet<>(List.of("openid", "profile", "email"));
            clients.findByApplicationIdOrderByClientId(app.getId()).stream()
                    .filter(c -> c.getStatus() == TenantApplicationClient.Status.ACTIVE && c.getClientType().interactive())
                    .forEach(c -> inherited.addAll(c.getAllowedScopes()));
            inherited.remove(OFFLINE_ACCESS);
            requestedScopes = List.copyOf(inherited);
        }
        boolean refresh = request.refreshTokens() == null || request.refreshTokens();
        Set<String> scopes = new LinkedHashSet<>(requestedScopes);
        if (refresh) scopes.add(OFFLINE_ACCESS);
        else if (scopes.contains(OFFLINE_ACCESS)) throw new IllegalArgumentException("offline_access requires refresh opt-in");
        String internal = "cimd-" + UUID.randomUUID();
        var input = new CreateTenantApplicationClientRequest(internal, TenantApplicationClient.Type.PUBLIC_BROWSER,
                request.redirectUris(), List.of(), List.copyOf(scopes), null, request.population(), request.accessTokenTtlSeconds(),
                request.refreshTokenTtlSeconds(), true, "none", null, refresh);
        createClient(tenantId, applicationId, input, httpRequest);
        TenantApplicationClient client = clients.findByClientId(internal).orElseThrow();
        client.trustExternalClient(request.clientId()); clients.save(client); clients.flush();
        RegisteredClient stored = storedRegistration(internal);
        var settings = ClientSettings.withSettings(stored.getClientSettings().getSettings())
                .setting(com.openwolf.iam.auth.CimdRegisteredClientRepository.CLIENT_ID, request.clientId());
        registeredClients.save(RegisteredClient.from(stored)
                .clientName(com.openwolf.iam.auth.CimdDocuments.safeDisplayName(request.displayName() == null ? app.getDisplayName() : request.displayName()))
                .clientAuthenticationMethods(methods -> { methods.clear(); methods.add(new ClientAuthenticationMethod(request.tokenEndpointAuthMethod())); })
                .clientSettings(settings.build()).build());
        var response = trustedResponse(client);
        audit.logRequired(tenantId, audit.currentActor(), "ADD_TRUSTED_CLIENT", "application_client", request.clientId(),
                null, Map.of("applicationId", applicationId.toString(), "approval", response), correlation(httpRequest));
        return response;
    }

    @Transactional(readOnly = true)
    public List<com.openwolf.iam.dto.TrustedClientResponse> listTrustedClients(String tenantId, UUID applicationId) {
        TenantApplication app = applicationForTenant(tenantId, applicationId);
        return clients.findByApplicationIdOrderByClientId(app.getId()).stream().filter(c -> c.getExternalClientId() != null)
                .map(this::trustedResponse).toList();
    }

    public void deleteTrustedClient(String tenantId, UUID applicationId, UUID id, long expectedRevision,
                                   HttpServletRequest httpRequest) {
        TenantApplicationClient client = clientForTenant(tenantId, applicationId, id);
        if (client.getExternalClientId() == null) throw EntityNotFoundException.forId("Trusted client", id);
        requireRevision(client, expectedRevision);
        var before = trustedResponse(client);
        client.disable(); clients.save(client);
        endClientSessions(tenantId, client.getClientId(), "trusted client approval removed");
        withdrawTrustedGrants(client);
        audit.logRequired(tenantId, audit.currentActor(), "DELETE_TRUSTED_CLIENT", "application_client", client.getExternalClientId(),
                before, Map.of("applicationId", applicationId.toString()), correlation(httpRequest));
    }

    private void withdrawTrustedGrants(TenantApplicationClient client) {
        if (client.getExternalClientId() == null) return;
        if (registeredClients instanceof com.openwolf.iam.auth.CimdRegisteredClientRepository cimd) cimd.evictMetadata(client.getExternalClientId());
        if (authorizationStore != null && authorizationStore.getIfAvailable() instanceof com.openwolf.iam.auth.RedisOAuth2AuthorizationService redis) {
            redis.removeForRegisteredClient(storedRegistration(client.getClientId()).getId());
        }
    }

    private org.springframework.beans.factory.ObjectProvider<org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService> authorizationStore;
    @Autowired
    void setAuthorizationStore(org.springframework.beans.factory.ObjectProvider<org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService> store) {
        this.authorizationStore = store;
    }

    /** Updating trust replaces the approval generation and withdraws every old grant before the new one can be used. */
    public com.openwolf.iam.dto.TrustedClientResponse updateTrustedClient(String tenantId, UUID applicationId, UUID id,
            com.openwolf.iam.dto.TrustedClientRequest request, HttpServletRequest httpRequest) {
        var client = clientForTenant(tenantId, applicationId, id);
        if (request.expectedRevision() == null || !request.clientId().equals(client.getExternalClientId())) {
            throw new IllegalArgumentException("An update requires expectedRevision and the unchanged client URL");
        }
        deleteTrustedClient(tenantId, applicationId, id, request.expectedRevision(), httpRequest);
        clients.flush();
        var updated = createTrustedClient(tenantId, applicationId, request, httpRequest);
        audit.logRequired(tenantId, audit.currentActor(), "UPDATE_TRUSTED_CLIENT", "application_client", request.clientId(),
                Map.of("previousApprovalId", id.toString()), updated, correlation(httpRequest));
        return updated;
    }

    private RegisteredClient storedRegistration(String clientId) {
        return registeredClients instanceof com.openwolf.iam.auth.CimdRegisteredClientRepository cimd
                ? cimd.storedByClientId(clientId) : registeredClients.findByClientId(clientId);
    }

    private com.openwolf.iam.dto.TrustedClientResponse trustedResponse(TenantApplicationClient client) {
        RegisteredClient registered = storedRegistration(client.getClientId());
        boolean refresh = registered.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN);
        return new com.openwolf.iam.dto.TrustedClientResponse(client.getId(), client.getExternalClientId(),
                registered.getRedirectUris().stream().sorted().toList(),
                registered.getClientAuthenticationMethods().iterator().next().getValue(), client.getAllowedScopes(), refresh,
                refresh ? registered.getTokenSettings().getRefreshTokenTimeToLive().toSeconds() : null,
                client.getPopulation(), client.getStatus(), client.getRevision(), registered.getClientName(),
                registered.getTokenSettings().getAccessTokenTimeToLive().toSeconds());
    }

    public void disableApplication(String tenantId, UUID applicationId, HttpServletRequest httpRequest) {
        TenantApplication app = applicationForTenant(tenantId, applicationId);
        if (app.getStatus() == TenantApplication.Status.DISABLED) return;
        TenantApplicationResponse before = applicationResponse(app);
        app.disable(); applications.save(app);
        audit.logRequired(tenantId, audit.currentActor(), "DISABLE_APPLICATION", "application", app.getId().toString(),
                before, applicationResponse(app), correlation(httpRequest));
        // Disabling an application ends every session issued to any of its clients.
        clients.findByApplicationIdOrderByClientId(app.getId())
                .forEach(c -> { endClientSessions(tenantId, c.getClientId(), "application disabled"); withdrawTrustedGrants(c); });
    }

    public void disableClient(String tenantId, UUID applicationId, UUID clientId, HttpServletRequest httpRequest) {
        TenantApplication app = applicationForTenant(tenantId, applicationId);
        TenantApplicationClient client = clients.findByIdAndApplicationId(clientId, app.getId())
                .orElseThrow(() -> EntityNotFoundException.forId("Application client", clientId));
        if (client.getStatus() == TenantApplicationClient.Status.DISABLED) return;
        TenantApplicationClientResponse before = clientResponse(client);
        client.disable(); clients.save(client);
        audit.logRequired(tenantId, audit.currentActor(), "DISABLE_APPLICATION_CLIENT", "application_client", client.getId().toString(),
                before, clientResponse(client), correlation(httpRequest));
        endClientSessions(tenantId, client.getClientId(), "client disabled");
        withdrawTrustedGrants(client);
    }

    /** Rotates a confidential service credential and returns its plaintext exactly once. */
    public CreatedTenantApplicationClientResponse rotateClientSecret(
            String tenantId, UUID applicationId, UUID clientId,
            RotateTenantApplicationClientSecretRequest request, HttpServletRequest httpRequest) {
        return rotateClientSecret(tenantId, applicationId, clientId, request, null, httpRequest);
    }

    /**
     * Rotates to {@code suppliedSecret} when given (operator-supplied, never returned) or to a generated secret
     * (returned once). Reached only through the approved identity-control apply path.
     */
    public CreatedTenantApplicationClientResponse rotateClientSecret(
            String tenantId, UUID applicationId, UUID clientId,
            RotateTenantApplicationClientSecretRequest request, String suppliedSecret, HttpServletRequest httpRequest) {
        if (suppliedSecret != null) OperatorSuppliedClientSecrets.requireValid(suppliedSecret);
        TenantApplicationClient client = clientForTenant(tenantId, applicationId, clientId);
        requireServiceClient(client);
        requireRevision(client, request.expectedRevision());
        RegisteredClient registered = registeredClientFor(client);
        if (!registered.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)) {
            throw new ResourceConflictException("This client authenticates with registered keys; replace its keys instead");
        }
        String secret = suppliedSecret != null ? suppliedSecret : generatedSecret();
        registeredClients.save(RegisteredClient.from(registered)
                .clientSecret(passwordEncoder.encode(secret)).build());
        // Phase 3.15: the previous secret stays valid only for the declared overlap (default: none).
        if (secretOverlaps != null) secretOverlaps.rotated(registered.getClientId(), registered.getClientSecret());
        client.rotateSecret();
        clients.save(client);
        TenantApplicationClientResponse response = clientResponse(client, registeredClientFor(client), client.getRevision() + 1);
        audit.logRequired(tenantId, audit.currentActor(), "ROTATE_APPLICATION_CLIENT_SECRET", "application_client",
                client.getId().toString(), clientResponse(client, registered, client.getRevision()), response,
                correlation(httpRequest));
        return new CreatedTenantApplicationClientResponse(response, suppliedSecret != null ? null : secret);
    }

    /**
     * Replaces the public keys of a {@code private_key_jwt} client (credential rotation by key: include the old and the
     * new key for an overlap, then replace again with only the new key). Only public keys are accepted; the private key
     * never leaves the client. Key ids are audited, key material is not.
     */
    public TenantApplicationClientResponse replaceClientKeys(String tenantId, UUID applicationId, UUID clientId,
                                                             Map<String, Object> jwks, long expectedRevision,
                                                             HttpServletRequest httpRequest) {
        TenantApplicationClient client = clientForTenant(tenantId, applicationId, clientId);
        requireServiceClient(client);
        requireRevision(client, expectedRevision);
        RegisteredClient registered = registeredClientFor(client);
        if (!registered.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.PRIVATE_KEY_JWT)) {
            throw new ResourceConflictException("This client authenticates with a secret, not registered keys");
        }
        ClientAssertionKeys.Registered keys = ClientAssertionKeys.validate(jwks);
        TenantApplicationClientResponse before = clientResponse(client, registered, client.getRevision());
        registeredClients.save(RegisteredClient.from(registered)
                .clientSettings(ClientSettings.withSettings(registered.getClientSettings().getSettings())
                        .tokenEndpointAuthenticationSigningAlgorithm(keys.algorithm())
                        .setting(ClientAssertionKeys.SETTING, keys.json()).build())
                .build());
        client.rotateSecret();
        clients.save(client);
        TenantApplicationClientResponse after = clientResponse(client, registeredClientFor(client), client.getRevision() + 1);
        audit.logRequired(tenantId, audit.currentActor(), "REPLACE_APPLICATION_CLIENT_KEYS", "application_client",
                client.getId().toString(), before, after, correlation(httpRequest));
        return after;
    }

    /** The sign-in population of an active interactive client; empty for service clients and system clients. */
    @Transactional(readOnly = true)
    public Optional<TenantApplicationClient.Population> signInPopulation(String clientId) {
        return activeAuthority(clientId).filter(authority -> authority.clientType().interactive())
                .map(ClientAuthority::population);
    }

    /** Immediately invalidates the protocol credential and disables the tenant client. */
    public TenantApplicationClientResponse revokeClientSecret(
            String tenantId, UUID applicationId, UUID clientId,
            RevokeTenantApplicationClientRequest request, HttpServletRequest httpRequest) {
        TenantApplicationClient client = clientForTenant(tenantId, applicationId, clientId);
        requireServiceClient(client);
        requireRevision(client, request.expectedRevision());
        RegisteredClient registered = registeredClientFor(client);
        TenantApplicationClientResponse before = clientResponse(client, registered, client.getRevision());
        client.disable();
        if (registered.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)) {
            registeredClients.save(RegisteredClient.from(registered)
                    .clientSecret(passwordEncoder.encode(generatedSecret())).build());
        }
        if (secretOverlaps != null) secretOverlaps.revoked(registered.getClientId());
        endClientSessions(tenantId, registered.getClientId(), "client secret revoked");
        clients.save(client);
        TenantApplicationClientResponse after = clientResponse(client, registeredClientFor(client), client.getRevision() + 1);
        audit.logRequired(tenantId, audit.currentActor(), "REVOKE_APPLICATION_CLIENT_SECRET", "application_client",
                client.getId().toString(), before, after, correlation(httpRequest));
        return after;
    }

    private IamSessionService sessionService;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    void setSessionService(@org.springframework.context.annotation.Lazy IamSessionService sessionService) {
        this.sessionService = sessionService;
    }

    /** Issued tokens of a disabled client stop at once: their durable sessions end (status checks then refuse). */
    private void endClientSessions(String tenantId, String clientId, String reason) {
        if (sessionService != null) {
            var row = clients.findByClientId(clientId).orElse(null);
            if (row != null && row.getExternalClientId() != null) {
                sessionService.revokeAllForApplicationClient(tenantId, row.getApplicationId(), row.getExternalClientId(), reason);
            } else sessionService.revokeAllForClient(tenantId, clientId, reason);
        }
    }

    private com.openwolf.iam.authority.lifecycle.ClientSecretOverlapStore secretOverlaps;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    void setSecretOverlaps(com.openwolf.iam.authority.lifecycle.ClientSecretOverlapStore secretOverlaps) {
        this.secretOverlaps = secretOverlaps;
    }

    /** Token-time authority; empty means a deployment-owned system client, not a permissive fallback. */
    @Transactional(readOnly = true)
    public Optional<ClientAuthority> activeAuthority(String clientId) {
        return clientLookup.find(clientId).flatMap(client -> applications.findById(client.getApplicationId())
                .filter(app -> activeTenants.isActive(app.getTenantId()))
                .filter(app -> app.getStatus() == TenantApplication.Status.ACTIVE)
                .filter(app -> client.getStatus() == TenantApplicationClient.Status.ACTIVE)
                .map(app -> new ClientAuthority(app.getTenantId(), app.getAudience(), client.getClientType(),
                        client.getAllowedScopes(), app.getId(), client.getPopulation())));
    }

    @Transactional(readOnly = true)
    public Optional<ClientAuthority> activeAuthority(String clientId, String tenantId, String audience) {
        if (clientId == null || !clientId.startsWith("https://")) return activeAuthority(clientId);
        var matches = clients.findTrustedByResource(clientId, audience).stream()
                .map(c -> activeAuthority(c.getClientId())).flatMap(Optional::stream)
                .filter(authority -> authority.tenantId().equals(tenantId)).toList();
        return matches.size() == 1 ? Optional.of(matches.getFirst()) : Optional.empty();
    }

    /** Context-free resolution for persisted grants and consent management, using a server-owned registration id. */
    @Transactional(readOnly = true)
    public Optional<ClientAuthority> activeAuthorityByRegisteredClientId(String registeredId) {
        RegisteredClient stored = registeredClients instanceof com.openwolf.iam.auth.CimdRegisteredClientRepository cimd
                ? cimd.storedById(registeredId) : registeredClients.findById(registeredId);
        return stored == null ? Optional.empty() : activeAuthority(stored.getClientId());
    }

    /** Serialize broker/workload registration on their shared OAuth client row. Caller must be transactional. */
    public void lockClientForIdentityRegistration(String clientId) {
        clients.findByClientIdForUpdate(clientId)
                .orElseThrow(() -> new IllegalArgumentException("identity registration requires a tenant application client"));
    }

    /** Server-owned resource-audience authority for exchange-route registration and token use. */
    @Transactional(readOnly = true)
    public boolean isActiveAudience(String tenantId, String audience) {
        return applications.findByTenantIdAndAudience(tenantId, audience)
                .filter(app -> activeTenants.isActive(app.getTenantId()))
                .filter(app -> app.getStatus() == TenantApplication.Status.ACTIVE)
                .isPresent();
    }

    @Transactional(readOnly = true)
    public boolean knownButDisabled(String clientId) {
        return clientLookup.find(clientId).map(client -> activeAuthority(clientId).isEmpty()).orElse(false);
    }

    @Transactional(readOnly = true)
    public void requireHumanClientTenant(String clientId, String tenantId) {
        ClientAuthority authority = activeAuthority(clientId)
                .orElseThrow(() -> new IllegalStateException("application client is disabled or unknown"));
        if (!authority.clientType().interactive() || !authority.tenantId().equals(tenantId)) {
            throw new IllegalStateException("client is not authorized for this tenant principal");
        }
    }

    private TenantApplication applicationForTenant(String tenantId, UUID applicationId) {
        requireTenantAdmin(tenantId);
        requireActiveTenant(tenantId);
        return applications.findByIdAndTenantId(applicationId, tenantId)
                .orElseThrow(() -> EntityNotFoundException.forId("Application", applicationId));
    }

    private TenantApplicationClient clientForTenant(String tenantId, UUID applicationId, UUID clientId) {
        TenantApplication app = applicationForTenant(tenantId, applicationId);
        return clients.findByIdAndApplicationId(clientId, app.getId())
                .orElseThrow(() -> EntityNotFoundException.forId("Application client", clientId));
    }

    private RegisteredClient registeredClientFor(TenantApplicationClient client) {
        RegisteredClient registered = storedRegistration(client.getClientId());
        if (registered == null) throw new IllegalStateException("Persisted application client registration is missing");
        return registered;
    }

    private static void requireServiceClient(TenantApplicationClient client) {
        if (client.getClientType() == TenantApplicationClient.Type.PUBLIC_BROWSER) {
            throw new ResourceConflictException("Only confidential clients have client credentials");
        }
        if (client.getStatus() != TenantApplicationClient.Status.ACTIVE) {
            throw new ResourceConflictException("Application client is disabled");
        }
    }

    private static void requireRevision(TenantApplicationClient client, long expectedRevision) {
        if (client.getRevision() != expectedRevision) {
            throw new ResourceConflictException("Application client revision is stale");
        }
    }

    private void requireTenantAdmin(String tenantId) {
        String callerTenant = executionTenant.require();
        if (tenantId.equals(callerTenant)) return;
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        boolean platformAdmin = authentication != null && authentication.getAuthorities().stream()
                .anyMatch(authority -> "ROLE_platform_admin".equals(authority.getAuthority()));
        if (!platformAdmin) throw EntityNotFoundException.forId("Application", tenantId);
    }

    private void requireActiveTenant(String tenantId) {
        if (!activeTenants.isActive(tenantId)) throw EntityNotFoundException.forId("Application", tenantId);
    }

    private RegisteredClient registeredClient(TenantApplication app, CreateTenantApplicationClientRequest request,
                                              List<String> scopes, String secret,
                                              TenantApplicationClient.Population population) {
        TenantApplicationClient.Type type = request.clientType();
        TokenSettings.Builder tokens = TokenSettings.builder().accessTokenTimeToLive(accessTokenTtl(request));
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(request.clientId()).clientName(app.getDisplayName());
        scopes.forEach(builder::scope);
        if (type.interactive()) {
            if (request.tokenEndpointAuthMethod() != null && !request.tokenEndpointAuthMethod().equals(
                    type == TenantApplicationClient.Type.PUBLIC_BROWSER ? "none" : "client_secret_basic")) {
                throw new IllegalArgumentException("Unsupported client authentication method for this client type");
            }
            if (request.jwks() != null) throw new IllegalArgumentException("Interactive clients do not register keys");
            List<String> redirects = requireBrowserUris(request.redirectUris(), "redirect URI");
            List<String> logoutRedirects = optionalBrowserUris(request.postLogoutRedirectUris(), "post-logout redirect URI");
            builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .clientSettings(ClientSettings.builder().requireProofKey(true)
                            .requireAuthorizationConsent(Boolean.TRUE.equals(request.requireConsent()))
                            .setting(POPULATION_SETTING, population.name()).build());
            if (type == TenantApplicationClient.Type.PUBLIC_BROWSER) {
                if (request.refreshTokenTtlSeconds() != null && !Boolean.TRUE.equals(request.refreshTokens())) {
                    throw new IllegalArgumentException("Public browser refresh tokens require explicit opt-in");
                }
                builder.clientAuthenticationMethod(ClientAuthenticationMethod.NONE);
                if (Boolean.TRUE.equals(request.refreshTokens())) {
                    builder.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                            .clientSettings(ClientSettings.builder().requireProofKey(true)
                                    .requireAuthorizationConsent(Boolean.TRUE.equals(request.requireConsent()))
                                    .setting(POPULATION_SETTING, population.name()).setting(com.openwolf.iam.auth.OptInRefreshTokenGenerator.ABSOLUTE_LIFETIME, true).build());
                    tokens.reuseRefreshTokens(false).refreshTokenTimeToLive(publicRefreshTtl(request.refreshTokenTtlSeconds()));
                }
            } else {
                builder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                        .clientSecret(passwordEncoder.encode(secret))
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
                // Rotation on every use (RFC 9700 section 4.14.2); reuse of a spent token withdraws the family.
                tokens.reuseRefreshTokens(false).refreshTokenTimeToLive(refreshTokenTtl(request));
            }
            redirects.forEach(builder::redirectUri); logoutRedirects.forEach(builder::postLogoutRedirectUri);
        } else {
            if (!empty(request.redirectUris()) || !empty(request.postLogoutRedirectUris())) {
                throw new IllegalArgumentException("Confidential service clients cannot register browser redirects");
            }
            if (request.requireConsent() != null || request.accessTokenTtlSeconds() != null
                    || request.refreshTokenTtlSeconds() != null || Boolean.TRUE.equals(request.refreshTokens())) {
                throw new IllegalArgumentException("Service clients use the deployment's client-credentials lifetime");
            }
            builder.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .authorizationGrantType(TokenExchangeConstants.GRANT_TYPE);
            String method = request.tokenEndpointAuthMethod() == null ? "client_secret_basic" : request.tokenEndpointAuthMethod();
            if (ClientAssertionKeys.PRIVATE_KEY_JWT.equals(method)) {
                ClientAssertionKeys.Registered keys = ClientAssertionKeys.validate(request.jwks());
                builder.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
                        .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false)
                                .tokenEndpointAuthenticationSigningAlgorithm(keys.algorithm())
                                .setting(ClientAssertionKeys.SETTING, keys.json()).build());
            } else if ("client_secret_basic".equals(method)) {
                if (request.jwks() != null) throw new IllegalArgumentException("Keys require private_key_jwt");
                builder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                        .clientSecret(passwordEncoder.encode(secret))
                        .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build());
            } else {
                throw new IllegalArgumentException("Unsupported client authentication method");
            }
        }
        return builder.tokenSettings(tokens.build()).build();
    }

    /** Client setting naming the interactive client's sign-in population (read by the authorization server). */
    public static final String POPULATION_SETTING = "settings.client.axiom.population";

    private static TenantApplicationClient.Population population(CreateTenantApplicationClientRequest request) {
        if (request.population() == null) return TenantApplicationClient.Population.WORKFORCE;
        if (!request.clientType().interactive() && request.population() != TenantApplicationClient.Population.WORKFORCE) {
            throw new IllegalArgumentException("Only interactive clients have a sign-in population");
        }
        return request.population();
    }

    private Duration accessTokenTtl(CreateTenantApplicationClientRequest request) {
        if (request.accessTokenTtlSeconds() == null) return interactiveTtl;
        Duration requested = Duration.ofSeconds(request.accessTokenTtlSeconds());
        if (requested.compareTo(Duration.ofSeconds(60)) < 0 || requested.compareTo(interactiveMaxTtl) > 0) {
            throw new IllegalArgumentException("accessTokenTtlSeconds must be between 60 and "
                    + interactiveMaxTtl.toSeconds());
        }
        return requested;
    }

    private Duration publicRefreshTtl(Long seconds) {
        Duration ttl = seconds == null ? Duration.ofDays(30) : Duration.ofSeconds(seconds);
        if (ttl.compareTo(Duration.ofMinutes(1)) < 0 || ttl.compareTo(refreshMaxTtl) > 0) {
            throw new IllegalArgumentException("public refresh lifetime exceeds the deployment refresh-token bounds");
        }
        return ttl;
    }

    private Duration refreshTokenTtl(CreateTenantApplicationClientRequest request) {
        if (request.refreshTokenTtlSeconds() == null) return refreshTtl;
        Duration requested = Duration.ofSeconds(request.refreshTokenTtlSeconds());
        if (requested.compareTo(Duration.ofSeconds(60)) < 0 || requested.compareTo(refreshMaxTtl) > 0) {
            throw new IllegalArgumentException("refreshTokenTtlSeconds must be between 60 and " + refreshMaxTtl.toSeconds());
        }
        return requested;
    }

    private Duration interactiveTtl = Duration.ofHours(1);
    private Duration interactiveMaxTtl = Duration.ofHours(1);
    private Duration refreshTtl = Duration.ofHours(8);
    private Duration refreshMaxTtl = Duration.ofDays(30);

    /**
     * Deployment policy for interactive (person/customer) access tokens and refresh tokens. The defaults keep today's
     * one-hour access tokens; a deployment that needs a shorter offline-withdrawal window lowers them.
     */
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    void setTokenLifetimes(
            @org.springframework.beans.factory.annotation.Value("${iam.oauth2.interactive-access-token.ttl:PT1H}") Duration ttl,
            @org.springframework.beans.factory.annotation.Value("${iam.oauth2.interactive-access-token.max-ttl:PT1H}") Duration max,
            @org.springframework.beans.factory.annotation.Value("${iam.oauth2.refresh-token.ttl:PT8H}") Duration refresh,
            @org.springframework.beans.factory.annotation.Value("${iam.oauth2.refresh-token.max-ttl:P30D}") Duration refreshMax) {
        if (max.compareTo(Duration.ofMinutes(1)) < 0 || max.compareTo(Duration.ofHours(24)) > 0
                || ttl.compareTo(Duration.ofMinutes(1)) < 0 || ttl.compareTo(max) > 0) {
            throw new IllegalArgumentException("interactive access-token TTL must be between one minute and its maximum (at most 24 h)");
        }
        if (refreshMax.compareTo(Duration.ofMinutes(1)) < 0 || refreshMax.compareTo(Duration.ofDays(90)) > 0
                || refresh.compareTo(Duration.ofMinutes(1)) < 0 || refresh.compareTo(refreshMax) > 0) {
            throw new IllegalArgumentException("refresh-token TTL must be between one minute and its maximum (at most 90 days)");
        }
        this.interactiveTtl = ttl; this.interactiveMaxTtl = max; this.refreshTtl = refresh; this.refreshMaxTtl = refreshMax;
    }

    private List<String> approvedScopes(String tenantId, TenantApplicationClient.Type type,
                                        TenantApplicationClient.Population population, List<String> requested, boolean publicRefresh) {
        Set<String> scopes = new LinkedHashSet<>(requested == null ? Set.of() : requested);
        Set<String> allowed = new LinkedHashSet<>(!type.interactive() ? SERVICE_SCOPES
                : population == TenantApplicationClient.Population.CUSTOMER ? CUSTOMER_SCOPES : PUBLIC_SCOPES);
        if (type == TenantApplicationClient.Type.CONFIDENTIAL_WEB || type == TenantApplicationClient.Type.PUBLIC_BROWSER && publicRefresh) allowed.add(OFFLINE_ACCESS);
        if (scopes.isEmpty()) scopes.addAll(allowed);
        for (String scope : scopes) {
            if (!allowed.contains(scope) && !businessScopes.isApproved(tenantId, scope)) {
                throw new IllegalArgumentException("Requested scopes are not approved for client posture");
            }
        }
        if (type.interactive() && !scopes.contains(OidcScopes.OPENID)) {
            throw new IllegalArgumentException("Interactive clients require openid scope");
        }
        return scopes.stream().sorted().toList();
    }

    private static boolean empty(List<String> values) { return values == null || values.isEmpty(); }
    private List<String> requireBrowserUris(List<String> values, String label) {
        if (empty(values)) throw new IllegalArgumentException("Public browser clients require at least one " + label);
        return values.stream().map(value -> checkedBrowserUri(value, label)).toList();
    }
    private List<String> optionalBrowserUris(List<String> values, String label) {
        return empty(values) ? List.of() : values.stream().map(value -> checkedBrowserUri(value, label)).toList();
    }
    private String checkedBrowserUri(String value, String label) {
        URI uri = URI.create(value);
        boolean localHttp = "http".equals(uri.getScheme()) && ("localhost".equals(uri.getHost()) || "127.0.0.1".equals(uri.getHost()) || "[::1]".equals(uri.getHost()));
        if ((!"https".equals(uri.getScheme()) && !localHttp) || uri.getHost() == null || uri.getFragment() != null || uri.getUserInfo() != null || uri.getPort() == 0 || uri.getPort() > 65535) {
            throw new IllegalArgumentException("Invalid " + label);
        }
        return uri.toString();
    }
    private TenantApplicationResponse applicationResponse(TenantApplication app) {
        return new TenantApplicationResponse(app.getId(), app.getTenantId(), app.getApplicationKey(), app.getDisplayName(),
                app.getDescription(), app.getAudience(), app.getStatus(), app.getRevision(), app.getCreatedAt(), app.getUpdatedAt());
    }
    private TenantApplicationClientResponse clientResponse(TenantApplicationClient client) {
        RegisteredClient registered = storedRegistration(client.getClientId());
        if (registered == null) throw new IllegalStateException("Persisted application client registration is missing");
        return clientResponse(client, registered);
    }
    private TenantApplicationClientResponse clientResponse(TenantApplicationClient client, RegisteredClient registered) {
        return clientResponse(client, registered, client.getRevision());
    }
    private TenantApplicationClientResponse clientResponse(TenantApplicationClient client, RegisteredClient registered, long revision) {
        boolean refresh = registered.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN);
        return new TenantApplicationClientResponse(client.getId(), client.getClientId(), client.getClientType(), client.getStatus(),
                client.getAllowedScopes(), registered.getRedirectUris().stream().sorted().toList(),
                registered.getPostLogoutRedirectUris().stream().sorted().toList(),
                registered.getAuthorizationGrantTypes().stream().map(AuthorizationGrantType::getValue).sorted().toList(),
                registered.getClientSettings().isRequireProofKey(), revision, client.getCreatedAt(), client.getUpdatedAt(),
                client.getPopulation(),
                registered.getClientAuthenticationMethods().stream().map(ClientAuthenticationMethod::getValue).sorted().toList(),
                client.getClientType().interactive() ? registered.getTokenSettings().getAccessTokenTimeToLive().toSeconds() : 0,
                refresh ? registered.getTokenSettings().getRefreshTokenTimeToLive().toSeconds() : null,
                registered.getClientSettings().isRequireAuthorizationConsent(),
                ClientAssertionKeys.keyIds(registered));
    }
    private static String generatedSecret() { byte[] bytes = new byte[32]; SECRET_RANDOM.nextBytes(bytes); return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes); }
    private static String correlation(HttpServletRequest request) { return request == null ? null : request.getHeader("X-Correlation-ID"); }

    public record ClientAuthority(String tenantId, String audience, TenantApplicationClient.Type clientType,
                                  List<String> scopes, UUID applicationId, TenantApplicationClient.Population population) {
        public ClientAuthority {
            if (population == null) population = TenantApplicationClient.Population.WORKFORCE;
        }
        public ClientAuthority(String tenantId, String audience, TenantApplicationClient.Type clientType,
                               List<String> scopes, UUID applicationId) {
            this(tenantId, audience, clientType, scopes, applicationId, TenantApplicationClient.Population.WORKFORCE);
        }
        public ClientAuthority(String tenantId, String audience, TenantApplicationClient.Type clientType, List<String> scopes) {
            this(tenantId, audience, clientType, scopes, null);
        }
        /** An interactive client through which customers (CIAM) sign in. */
        public boolean customerSignIn() {
            return clientType.interactive() && population == TenantApplicationClient.Population.CUSTOMER;
        }
        /** An interactive client through which workforce people sign in. */
        public boolean workforceSignIn() {
            return clientType.interactive() && population == TenantApplicationClient.Population.WORKFORCE;
        }
    }
}
