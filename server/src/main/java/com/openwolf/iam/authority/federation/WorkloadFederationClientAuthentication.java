package com.openwolf.iam.authority.federation;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.AuthenticationConverter;

import java.util.Map;

/**
 * Phase 3.12 client authentication by federated workload assertion
 * ({@code client_assertion_type=urn:openwolf:params:oauth:client-assertion-type:workload-federation}). It
 * authenticates the bound workload's own OAuth client and therefore yields only the workload's own identity; every
 * grant then applies its ordinary rules. With no provider profile configured every attempt is {@code invalid_client}.
 */
public final class WorkloadFederationClientAuthentication {
    public static final String ASSERTION_TYPE = "urn:openwolf:params:oauth:client-assertion-type:workload-federation";
    public static final ClientAuthenticationMethod METHOD = new ClientAuthenticationMethod(ASSERTION_TYPE);

    private WorkloadFederationClientAuthentication() {}

    public static AuthenticationConverter converter() {
        return (HttpServletRequest request) -> {
            if (!ASSERTION_TYPE.equals(request.getParameter("client_assertion_type"))) return null;
            String[] clientId = request.getParameterValues("client_id");
            String[] assertion = request.getParameterValues("client_assertion");
            String[] profile = request.getParameterValues("client_assertion_profile");
            if (clientId == null || clientId.length != 1 || assertion == null || assertion.length != 1
                    || profile == null || profile.length != 1 || request.getHeader("Authorization") != null) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
            }
            return new OAuth2ClientAuthenticationToken(clientId[0], METHOD, assertion[0],
                    Map.of("client_assertion_profile", profile[0]));
        };
    }

    public static AuthenticationProvider provider(WorkloadFederationService federation, RegisteredClientRepository clients) {
        return new AuthenticationProvider() {
            @Override
            public Authentication authenticate(Authentication authentication) {
                OAuth2ClientAuthenticationToken request = (OAuth2ClientAuthenticationToken) authentication;
                if (!METHOD.equals(request.getClientAuthenticationMethod())) return null;
                String clientId = String.valueOf(request.getPrincipal());
                Object profile = request.getAdditionalParameters().get("client_assertion_profile");
                if (federation.authenticate(clientId, profile == null ? null : profile.toString(),
                        (String) request.getCredentials()).isEmpty()) {
                    throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
                }
                RegisteredClient client = clients.findByClientId(clientId);
                if (client == null) throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
                return new OAuth2ClientAuthenticationToken(client, METHOD, null);
            }

            @Override
            public boolean supports(Class<?> authentication) {
                return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
            }
        };
    }
}
