package com.openwolf.iam.controller;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Axiom's OAuth consent page (replaces Spring Authorization Server's built-in page, which loads its stylesheet from a
 * third-party CDN). Same protocol contract: a form posting {@code client_id}, the authorization {@code state} and the
 * approved {@code scope} values back to the authorization endpoint. All assets are served by Axiom.
 */
@Controller
public class ConsentController {
    public static final String PATH = "/oauth2/consent";

    private final RegisteredClientRepository clients;
    private final OAuth2AuthorizationConsentService consents;

    public ConsentController(RegisteredClientRepository clients, OAuth2AuthorizationConsentService consents) {
        this.clients = clients;
        this.consents = consents;
    }

    @GetMapping(PATH)
    public String consent(Principal principal, Model model,
                          @RequestParam("client_id") String clientId,
                          @RequestParam("scope") String scope,
                          @RequestParam("state") String state) {
        RegisteredClient client = clients.findByClientId(clientId);
        if (client == null) throw new IllegalArgumentException("unknown client");
        Set<String> previously = new LinkedHashSet<>();
        OAuth2AuthorizationConsent existing = consents.findById(client.getId(), principal.getName());
        if (existing != null) {
            for (GrantedAuthority authority : existing.getAuthorities()) {
                if (authority.getAuthority().startsWith("SCOPE_")) previously.add(authority.getAuthority().substring(6));
            }
        }
        Set<String> toApprove = new LinkedHashSet<>();
        for (String requested : scope.trim().split("\\s+")) {
            // openid is implied by the OIDC request itself; only requested scopes the client is registered for are shown.
            if (requested.isBlank() || OidcScopes.OPENID.equals(requested) || !client.getScopes().contains(requested)) continue;
            if (!previously.contains(requested)) toApprove.add(requested);
        }
        previously.remove(OidcScopes.OPENID);
        model.addAttribute("clientId", clientId);
        model.addAttribute("clientName", client.getClientName());
        model.addAttribute("state", state);
        model.addAttribute("scopes", toApprove);
        model.addAttribute("previouslyApprovedScopes", previously);
        model.addAttribute("authorizationEndpoint", "/oauth/authorize");
        return "consent";
    }
}
