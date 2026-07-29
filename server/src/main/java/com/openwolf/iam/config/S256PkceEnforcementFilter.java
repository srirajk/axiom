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

    public S256PkceEnforcementFilter(ObjectProvider<RegisteredClientRepository> registeredClients,
                                     ObjectProvider<TenantApplicationService> applications,
                                     ObjectProvider<ApplicationAccessService> applicationAccess,
                                     ObjectProvider<PrincipalRepository> principals) {
        this.registeredClients = registeredClients;
        this.applications = applications;
        this.applicationAccess = applicationAccess;
        this.principals = principals;
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
        if (client != null && client.getClientSettings().isRequireProofKey()
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
