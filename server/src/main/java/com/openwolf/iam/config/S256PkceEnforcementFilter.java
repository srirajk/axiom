package com.openwolf.iam.config;

import com.openwolf.iam.entity.Principal;
import com.openwolf.iam.repository.PrincipalRepository;
import com.openwolf.iam.service.ApplicationAccessService;
import com.openwolf.iam.service.TenantApplicationService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Validates the public-browser authorization boundary before Spring Authorization Server may issue
 * an authorization code.
 *
 * <p>The token endpoint always resolves current application membership and principal state. The
 * authorize endpoint must apply the same live-state check; otherwise an authenticated browser whose
 * principal or membership was disabled after login can receive a code that is guaranteed to fail
 * later as {@code invalid_grant}. Invalid login sessions are cleared and allowed to continue into
 * Spring Security's controlled login path. Disabled clients or memberships fail before a callback
 * code can be minted.</p>
 */
@Component
public final class S256PkceEnforcementFilter extends OncePerRequestFilter {

    /** Must match {@link SecurityConfig#authorizationServerSettings()}. */
    static final String AUTHORIZATION_ENDPOINT = "/oauth/authorize";
    private final ObjectProvider<RegisteredClientRepository> registeredClients;
    private final ObjectProvider<TenantApplicationService> applications;
    private final ObjectProvider<ApplicationAccessService> applicationAccess;
    private final ObjectProvider<PrincipalRepository> principals;

    private final ObjectProvider<com.openwolf.iam.service.CiamCustomerAuthenticationService> customers;

    public S256PkceEnforcementFilter(ObjectProvider<RegisteredClientRepository> registeredClients,
                                     ObjectProvider<TenantApplicationService> applications,
                                     ObjectProvider<ApplicationAccessService> applicationAccess,
                                     ObjectProvider<PrincipalRepository> principals) {
        this(registeredClients, applications, applicationAccess, principals, null);
    }

    @org.springframework.beans.factory.annotation.Autowired
    public S256PkceEnforcementFilter(ObjectProvider<RegisteredClientRepository> registeredClients,
                                     ObjectProvider<TenantApplicationService> applications,
                                     ObjectProvider<ApplicationAccessService> applicationAccess,
                                     ObjectProvider<PrincipalRepository> principals,
                                     ObjectProvider<com.openwolf.iam.service.CiamCustomerAuthenticationService> customers) {
        this.registeredClients = registeredClients;
        this.applications = applications;
        this.applicationAccess = applicationAccess;
        this.principals = principals;
        this.customers = customers == null ? new org.springframework.beans.factory.support.StaticListableBeanFactory()
                .getBeanProvider(com.openwolf.iam.service.CiamCustomerAuthenticationService.class) : customers;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !AUTHORIZATION_ENDPOINT.equals(request.getRequestURI());
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        String clientId = request.getParameter("client_id");
        TenantApplicationService applicationService = applications.getIfAvailable();
        if (applicationService != null && applicationService.knownButDisabled(clientId)) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "application client is disabled");
            return;
        }
        RegisteredClientRepository repository = registeredClients.getIfAvailable();
        RegisteredClient client = repository == null || clientId == null ? null : repository.findByClientId(clientId);
        // PKCE parameters belong to the authorization request (it carries response_type). The consent form's POST to
        // the same endpoint carries only client_id, state and the approved scopes; its PKCE binding is the original
        // request's, already verified when that request was accepted.
        boolean consentSubmission = "POST".equalsIgnoreCase(request.getMethod())
                && request.getParameter("response_type") == null;
        if (client != null && client.getClientSettings().isRequireProofKey() && !consentSubmission
                && (!"S256".equals(request.getParameter("code_challenge_method"))
                || request.getParameter("code_challenge") == null
                || request.getParameter("code_challenge").isBlank())) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                    "public browser clients require an S256 PKCE code challenge");
            return;
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()
                || "anonymousUser".equals(authentication.getPrincipal())) {
            filterChain.doFilter(request, response);
            return;
        }

        // Population boundary: a customer login never obtains a code for a workforce client and vice versa. A login of
        // the other population is cleared and the browser is sent to the login page of the client's population.
        boolean customerClient = applicationService != null && applicationService.signInPopulation(clientId)
                .map(com.openwolf.iam.entity.TenantApplicationClient.Population.CUSTOMER::equals).orElse(false);
        if (authentication instanceof com.openwolf.iam.auth.CustomerAuthenticationToken customer) {
            com.openwolf.iam.service.CiamCustomerAuthenticationService customerService = customers.getIfAvailable();
            boolean current = customerClient && customerService != null
                    && applicationService.activeAuthority(clientId)
                            .map(authority -> authority.tenantId().equals(customer.tenantId())).orElse(false)
                    && customerService.current(customer.tenantId(), java.util.UUID.fromString(customer.getName()),
                            customer.tokenVersion()).isPresent();
            if (!current) clearStaleLogin(request);
            filterChain.doFilter(request, response);
            return;
        }
        if (customerClient) {
            clearStaleLogin(request);
            filterChain.doFilter(request, response);
            return;
        }

        PrincipalRepository principalRepository = principals.getIfAvailable();
        Principal current = principalRepository == null ? null
                : principalRepository.findById(authentication.getName())
                        .or(() -> principalRepository.findByUsername(authentication.getName()))
                        .orElse(null);
        if (current == null || !current.isActive()) {
            clearStaleLogin(request);
            filterChain.doFilter(request, response);
            return;
        }

        if (applicationService != null && applicationService.activeAuthority(clientId).isPresent()) {
            ApplicationAccessService accessService = applicationAccess.getIfAvailable();
            try {
                if (accessService == null) {
                    throw new IllegalStateException("application access authority is unavailable");
                }
                accessService.tokenClaims(clientId, current.getId());
            } catch (IllegalStateException denied) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN,
                        "principal is not authorized for this application");
                return;
            }
        }
        filterChain.doFilter(request, response);
    }

    private static void clearStaleLogin(HttpServletRequest request) {
        if (request.getSession(false) != null) {
            request.getSession(false).invalidate();
        }
        SecurityContextHolder.clearContext();
    }
}
