package com.openwolf.iam.auth;

import com.openwolf.iam.service.AuditService;
import com.openwolf.iam.service.TenantApplicationService;
import jakarta.servlet.http.*;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.*;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/** RFC 9207 on the framework's validated callback, including errors. Invalid callbacks remain local errors. */
public final class IssuerAuthorizationResponses {
    private final ObjectProvider<TenantApplicationService> applications;
    private final ObjectProvider<AuditService> audit;
    public IssuerAuthorizationResponses(ObjectProvider<TenantApplicationService> applications, ObjectProvider<AuditService> audit) {
        this.applications = applications; this.audit = audit;
    }
    public void success(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        var result = (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;
        var binding = CimdClientContext.current();
        if (binding != null) {
            var authority = applications.getObject().activeAuthority(result.getClientId()).orElseThrow();
            audit.getObject().logRequired(authority.tenantId(), ((Authentication) result.getPrincipal()).getName(),
                    "CIMD_SIGN_IN", "application_client", result.getClientId(), null,
                    Map.of("applicationId", authority.applicationId().toString()), request.getHeader("X-Correlation-ID"));
        }
        var uri = UriComponentsBuilder.fromUriString(result.getRedirectUri()).queryParam("code", result.getAuthorizationCode().getTokenValue());
        parameter(uri, "state", result.getState());
        redirect(response, uri);
    }
    public void failure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        if (!(exception instanceof OAuth2AuthorizationCodeRequestAuthenticationException failure)
                || failure.getAuthorizationCodeRequestAuthentication() == null
                || failure.getAuthorizationCodeRequestAuthentication().getRedirectUri() == null) {
            response.sendError(400, exception instanceof OAuth2AuthorizationCodeRequestAuthenticationException oauth
                    ? oauth.getError().toString() : "Invalid authorization request"); return;
        }
        var result = failure.getAuthorizationCodeRequestAuthentication();
        var uri = UriComponentsBuilder.fromUriString(result.getRedirectUri()).queryParam("error", failure.getError().getErrorCode());
        parameter(uri, "error_description", failure.getError().getDescription());
        parameter(uri, "error_uri", failure.getError().getUri());
        parameter(uri, "state", result.getState());
        redirect(response, uri);
    }
    private static void parameter(UriComponentsBuilder uri, String name, String value) {
        if (value != null && !value.isBlank()) uri.queryParam(name, UriUtils.encode(value, StandardCharsets.UTF_8));
    }
    private static void redirect(HttpServletResponse response, UriComponentsBuilder uri) throws IOException {
        parameter(uri, "iss", AuthorizationServerContextHolder.getContext().getIssuer());
        response.sendRedirect(uri.build(true).toUriString());
    }
}
