package com.openwolf.iam.config;

import com.openwolf.iam.service.TenantApplicationService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/** Rejects PKCE downgrade for dynamically registered public browser clients before authorization starts. */
@Component
public final class S256PkceEnforcementFilter extends OncePerRequestFilter {

    /** Must match {@link SecurityConfig#authorizationServerSettings()}. */
    static final String AUTHORIZATION_ENDPOINT = "/oauth/authorize";
    private final ObjectProvider<RegisteredClientRepository> registeredClients;
    private final ObjectProvider<TenantApplicationService> applications;

    public S256PkceEnforcementFilter(ObjectProvider<RegisteredClientRepository> registeredClients,
                                     ObjectProvider<TenantApplicationService> applications) {
        this.registeredClients = registeredClients;
        this.applications = applications;
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
        filterChain.doFilter(request, response);
    }
}
