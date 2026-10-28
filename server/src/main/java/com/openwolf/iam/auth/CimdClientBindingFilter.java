package com.openwolf.iam.auth;

import com.openwolf.iam.repository.TenantApplicationClientRepository;
import com.openwolf.iam.service.TenantApplicationService;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.*;

/** Selects trust before any metadata fetch. Authorization uses resource; redemption uses the saved grant's client id. */
public final class CimdClientBindingFilter extends OncePerRequestFilter {
    private final CimdRegisteredClientRepository registrations;
    private final TenantApplicationClientRepository clients;
    private final ObjectProvider<TenantApplicationService> applications;
    private final OAuth2AuthorizationService authorizations;
    public CimdClientBindingFilter(RegisteredClientRepository registrations, TenantApplicationClientRepository clients,
            ObjectProvider<TenantApplicationService> applications, OAuth2AuthorizationService authorizations) {
        this.registrations = (CimdRegisteredClientRepository) registrations;
        this.clients = clients; this.applications = applications; this.authorizations = authorizations;
    }
    @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String path = request.getRequestURI();
        boolean token = "/oauth/token".equals(path);
        boolean authorize = "/oauth/authorize".equals(path);
        boolean consent = "/oauth2/consent".equals(path) || authorize && "POST".equals(request.getMethod())
                && request.getParameter("response_type") == null;
        boolean customerLogin = "/login/customer".equals(path);
        if (!(token || authorize || consent || customerLogin)) { chain.doFilter(request, response); return; }
        String[] ids = request.getParameterValues("client_id");
        String[] resources = request.getParameterValues("resource");
        if (customerLogin) {
            var saved = new HttpSessionRequestCache().getRequest(request, response);
            ids = saved == null ? null : saved.getParameterValues("client_id");
            resources = saved == null ? null : saved.getParameterValues("resource");
        }
        if (ids == null || ids.length != 1 || !ids[0].startsWith("https://")) { chain.doFilter(request, response); return; }
        String clientId = ids[0];
        String unknownClient = token ? "invalid_client" : "invalid_request";
        try {
          try {
            CimdHttpFetcher.requireUrl(clientId);
            if (authorize && !consent) {
                String[] redirects = request.getParameterValues("redirect_uri");
                if (redirects == null || redirects.length != 1 || redirects[0].isBlank()) { error(response, "invalid_request"); return; }
            }
            if (!clients.existsByExternalClientId(clientId)) { error(response, unknownClient); return; }
            com.openwolf.iam.entity.TenantApplicationClient selected;
            OAuth2Authorization savedAuthorization = null;
            if (consent || token) {
                String parameter = consent ? "state" : "refresh_token".equals(request.getParameter("grant_type")) ? "refresh_token" : "code";
                String[] values = request.getParameterValues(parameter);
                if (values == null || values.length != 1 || values[0].isBlank()) { error(response, token ? "invalid_grant" : "invalid_request"); return; }
                OAuth2TokenType type = new OAuth2TokenType(parameter);
                OAuth2Authorization authorization = authorizations instanceof RedisOAuth2AuthorizationService redis
                        ? redis.findForClientBinding(values[0], type) : authorizations.findByToken(values[0], type);
                if (authorization == null) { error(response, token ? "invalid_grant" : "invalid_request"); return; }
                savedAuthorization = authorization;
                var registered = registrations.storedById(authorization.getRegisteredClientId());
                selected = registered == null ? null : clients.findByClientId(registered.getClientId()).orElse(null);
                if (selected == null || !clientId.equals(selected.getExternalClientId())) { error(response, "invalid_grant"); return; }
            } else {
                if (resources == null || resources.length != 1) { error(response, "invalid_target"); return; }
                var candidates = clients.findTrustedByResource(clientId, resources[0]).stream()
                        .filter(row -> applications.getObject().activeAuthority(row.getClientId()).isPresent()).toList();
                if (candidates.size() != 1) { error(response, unknownClient); return; }
                selected = candidates.getFirst();
            }
            if (applications.getObject().activeAuthority(selected.getClientId()).isEmpty()) { error(response, unknownClient); return; }
            var stored = registrations.storedByClientId(selected.getClientId());
            if (stored == null) { error(response, unknownClient); return; }
            CimdClientContext.set(new CimdClientContext.Binding(clientId, selected.getClientId(), stored.getId()));
            var client = registrations.findByClientId(clientId);
            if (client == null) { error(response, unknownClient); return; }
            if (authorize && !consent) client = registrations.validateAuthorization(client);
            CimdClientContext.set(new CimdClientContext.Binding(clientId, selected.getClientId(), stored.getId(),
                    authorize && !consent ? client : null, savedAuthorization));
          } catch (OAuth2AuthenticationException | IllegalArgumentException refused) { error(response, unknownClient); return; }
          chain.doFilter(request, response);
        } finally { CimdClientContext.clear(); }
    }
    private static void error(HttpServletResponse response, String code) throws IOException {
        response.setStatus(400); response.setContentType("application/json"); response.setHeader("Cache-Control", "no-store");
        response.getWriter().write("{\"error\":\"" + code + "\"}");
    }
}
