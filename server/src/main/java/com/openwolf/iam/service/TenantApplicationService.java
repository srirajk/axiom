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
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/** AXP-1 product registry. It never exposes Spring's client rows or stored secrets directly. */
@Service
@Transactional
public class TenantApplicationService {
    private static final Set<String> PUBLIC_SCOPES = Set.of(OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL, "roles");
    private static final Set<String> SERVICE_SCOPES = Set.of(
            ApplicationScopes.APPLICATION_READ,
            ApplicationScopes.SUBJECT_CONTEXT_READ,
            ApplicationScopes.PLATFORM_AUTHZ_DECIDE);
    private static final SecureRandom SECRET_RANDOM = new SecureRandom();

    private final TenantApplicationRepository applications;
    private final TenantApplicationClientRepository clients;
    private final TenantRepository tenants;
    private final ActiveTenantDirectory activeTenants;
    private final RegisteredClientRepository registeredClients;
    private final PasswordEncoder passwordEncoder;
    private final ExecutionTenant executionTenant;
    private final AuditService audit;

    public TenantApplicationService(TenantApplicationRepository applications, TenantApplicationClientRepository clients,
                                    TenantRepository tenants, ActiveTenantDirectory activeTenants, RegisteredClientRepository registeredClients,
                                    PasswordEncoder passwordEncoder,
                                    ExecutionTenant executionTenant, AuditService audit) {
        this.applications = applications; this.clients = clients; this.tenants = tenants; this.activeTenants = activeTenants;
        this.registeredClients = registeredClients; this.passwordEncoder = passwordEncoder;
        this.executionTenant = executionTenant; this.audit = audit;
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
        return clients.findByApplicationIdOrderByClientId(app.getId()).stream().map(this::clientResponse).toList();
    }

    public CreatedTenantApplicationClientResponse createClient(String tenantId, UUID applicationId,
                                                                 CreateTenantApplicationClientRequest request,
                                                                 HttpServletRequest httpRequest) {
        TenantApplication app = applicationForTenant(tenantId, applicationId);
        if (app.getStatus() != TenantApplication.Status.ACTIVE) throw new ResourceConflictException("Application is disabled");
        if (registeredClients.findByClientId(request.clientId()) != null || clients.findByClientId(request.clientId()).isPresent()) {
            throw new ResourceConflictException("Client id already exists");
        }
        List<String> scopes = approvedScopes(request.clientType(), request.scopes());
        String secret = request.clientType() == TenantApplicationClient.Type.CONFIDENTIAL_SERVICE ? generatedSecret() : null;
        RegisteredClient registered = registeredClient(app, request, scopes, secret);
        registeredClients.save(registered);
        TenantApplicationClient client = clients.save(new TenantApplicationClient(app.getId(), request.clientId(),
                request.clientType(), scopes));
        TenantApplicationClientResponse response = clientResponse(client, registered);
        audit.logRequired(tenantId, audit.currentActor(), "CREATE_APPLICATION_CLIENT", "application_client",
                client.getId().toString(), null, response, correlation(httpRequest));
        return new CreatedTenantApplicationClientResponse(response, secret);
    }

    public void disableApplication(String tenantId, UUID applicationId, HttpServletRequest httpRequest) {
        TenantApplication app = applicationForTenant(tenantId, applicationId);
        if (app.getStatus() == TenantApplication.Status.DISABLED) return;
        TenantApplicationResponse before = applicationResponse(app);
        app.disable(); applications.save(app);
        audit.logRequired(tenantId, audit.currentActor(), "DISABLE_APPLICATION", "application", app.getId().toString(),
                before, applicationResponse(app), correlation(httpRequest));
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
    }

    /** Rotates a confidential service credential and returns its plaintext exactly once. */
    public CreatedTenantApplicationClientResponse rotateClientSecret(
            String tenantId, UUID applicationId, UUID clientId,
            RotateTenantApplicationClientSecretRequest request, HttpServletRequest httpRequest) {
        TenantApplicationClient client = clientForTenant(tenantId, applicationId, clientId);
        requireServiceClient(client);
        requireRevision(client, request.expectedRevision());
        RegisteredClient registered = registeredClientFor(client);
        String secret = generatedSecret();
        registeredClients.save(RegisteredClient.from(registered)
                .clientSecret(passwordEncoder.encode(secret)).build());
        client.rotateSecret();
        clients.save(client);
        TenantApplicationClientResponse response = clientResponse(client, registeredClientFor(client), client.getRevision() + 1);
        audit.logRequired(tenantId, audit.currentActor(), "ROTATE_APPLICATION_CLIENT_SECRET", "application_client",
                client.getId().toString(), clientResponse(client, registered, client.getRevision()), response,
                correlation(httpRequest));
        return new CreatedTenantApplicationClientResponse(response, secret);
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
        registeredClients.save(RegisteredClient.from(registered)
                .clientSecret(passwordEncoder.encode(generatedSecret())).build());
        clients.save(client);
        TenantApplicationClientResponse after = clientResponse(client, registeredClientFor(client), client.getRevision() + 1);
        audit.logRequired(tenantId, audit.currentActor(), "REVOKE_APPLICATION_CLIENT_SECRET", "application_client",
                client.getId().toString(), before, after, correlation(httpRequest));
        return after;
    }

    /** Token-time authority; empty means a deployment-owned system client, not a permissive fallback. */
    @Transactional(readOnly = true)
    public Optional<ClientAuthority> activeAuthority(String clientId) {
        return clients.findByClientId(clientId).flatMap(client -> applications.findById(client.getApplicationId())
                .filter(app -> activeTenants.isActive(app.getTenantId()))
                .filter(app -> app.getStatus() == TenantApplication.Status.ACTIVE)
                .filter(app -> client.getStatus() == TenantApplicationClient.Status.ACTIVE)
                .map(app -> new ClientAuthority(app.getTenantId(), app.getAudience(), client.getClientType(), client.getAllowedScopes(), app.getId())));
    }

    @Transactional(readOnly = true)
    public boolean knownButDisabled(String clientId) {
        return clients.findByClientId(clientId).map(client -> activeAuthority(clientId).isEmpty()).orElse(false);
    }

    @Transactional(readOnly = true)
    public void requireHumanClientTenant(String clientId, String tenantId) {
        ClientAuthority authority = activeAuthority(clientId)
                .orElseThrow(() -> new IllegalStateException("application client is disabled or unknown"));
        if (authority.clientType() != TenantApplicationClient.Type.PUBLIC_BROWSER || !authority.tenantId().equals(tenantId)) {
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
        RegisteredClient registered = registeredClients.findByClientId(client.getClientId());
        if (registered == null) throw new IllegalStateException("Persisted application client registration is missing");
        return registered;
    }

    private static void requireServiceClient(TenantApplicationClient client) {
        if (client.getClientType() != TenantApplicationClient.Type.CONFIDENTIAL_SERVICE) {
            throw new ResourceConflictException("Only confidential service clients have service credentials");
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
                                              List<String> scopes, String secret) {
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(request.clientId()).clientName(app.getDisplayName())
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofHours(1)).build());
        scopes.forEach(builder::scope);
        if (request.clientType() == TenantApplicationClient.Type.PUBLIC_BROWSER) {
            List<String> redirects = requireBrowserUris(request.redirectUris(), "redirect URI");
            List<String> logoutRedirects = optionalBrowserUris(request.postLogoutRedirectUris(), "post-logout redirect URI");
            builder.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false).build());
            redirects.forEach(builder::redirectUri); logoutRedirects.forEach(builder::postLogoutRedirectUri);
        } else {
            if (!empty(request.redirectUris()) || !empty(request.postLogoutRedirectUris())) {
                throw new IllegalArgumentException("Confidential service clients cannot register browser redirects");
            }
            builder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .clientSecret(passwordEncoder.encode(secret))
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build());
        }
        return builder.build();
    }

    private List<String> approvedScopes(TenantApplicationClient.Type type, List<String> requested) {
        Set<String> scopes = new LinkedHashSet<>(requested == null ? Set.of() : requested);
        Set<String> allowed = type == TenantApplicationClient.Type.PUBLIC_BROWSER ? PUBLIC_SCOPES : SERVICE_SCOPES;
        if (scopes.isEmpty()) scopes.addAll(allowed);
        if (!allowed.containsAll(scopes)) throw new IllegalArgumentException("Requested scopes are not approved for client posture");
        if (type == TenantApplicationClient.Type.PUBLIC_BROWSER && !scopes.contains(OidcScopes.OPENID)) {
            throw new IllegalArgumentException("Public browser clients require openid scope");
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
        boolean localHttp = "http".equals(uri.getScheme()) && ("localhost".equals(uri.getHost()) || "127.0.0.1".equals(uri.getHost()));
        if ((!"https".equals(uri.getScheme()) && !localHttp) || uri.getHost() == null || uri.getFragment() != null) {
            throw new IllegalArgumentException("Invalid " + label);
        }
        return uri.toString();
    }
    private TenantApplicationResponse applicationResponse(TenantApplication app) {
        return new TenantApplicationResponse(app.getId(), app.getTenantId(), app.getApplicationKey(), app.getDisplayName(),
                app.getDescription(), app.getAudience(), app.getStatus(), app.getRevision(), app.getCreatedAt(), app.getUpdatedAt());
    }
    private TenantApplicationClientResponse clientResponse(TenantApplicationClient client) {
        RegisteredClient registered = registeredClients.findByClientId(client.getClientId());
        if (registered == null) throw new IllegalStateException("Persisted application client registration is missing");
        return clientResponse(client, registered);
    }
    private TenantApplicationClientResponse clientResponse(TenantApplicationClient client, RegisteredClient registered) {
        return clientResponse(client, registered, client.getRevision());
    }
    private TenantApplicationClientResponse clientResponse(TenantApplicationClient client, RegisteredClient registered, long revision) {
        return new TenantApplicationClientResponse(client.getId(), client.getClientId(), client.getClientType(), client.getStatus(),
                client.getAllowedScopes(), registered.getRedirectUris().stream().sorted().toList(),
                registered.getPostLogoutRedirectUris().stream().sorted().toList(),
                registered.getAuthorizationGrantTypes().stream().map(AuthorizationGrantType::getValue).sorted().toList(),
                registered.getClientSettings().isRequireProofKey(), revision, client.getCreatedAt(), client.getUpdatedAt());
    }
    private static String generatedSecret() { byte[] bytes = new byte[32]; SECRET_RANDOM.nextBytes(bytes); return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes); }
    private static String correlation(HttpServletRequest request) { return request == null ? null : request.getHeader("X-Correlation-ID"); }

    public record ClientAuthority(String tenantId, String audience, TenantApplicationClient.Type clientType,
                                  List<String> scopes, UUID applicationId) {
        public ClientAuthority(String tenantId, String audience, TenantApplicationClient.Type clientType, List<String> scopes) {
            this(tenantId, audience, clientType, scopes, null);
        }
    }
}
