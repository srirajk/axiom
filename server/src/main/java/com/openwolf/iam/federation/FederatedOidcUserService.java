package com.openwolf.iam.federation;

import com.openwolf.iam.entity.IdentitySource;
import com.openwolf.iam.repository.IdentitySourceRepository;
import com.openwolf.iam.service.AuditService;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

/** Resolves a successful upstream identity only through an existing ACTIVE exact link. */
@Service
public final class FederatedOidcUserService implements org.springframework.security.oauth2.client.userinfo.OAuth2UserService<OidcUserRequest, OidcUser> {
    private final OidcUserService delegate = new OidcUserService();
    private final IdentitySourceRepository sources;
    private final FederatedIdentityResolver resolver;
    private final ConnectionBoundOAuth2UserService userInfoService;
    private final AuditService audit;

    public FederatedOidcUserService(IdentitySourceRepository sources,
                                    FederatedIdentityResolver resolver,
                                    ConnectionBoundOAuth2UserService userInfoService,
                                    AuditService audit) {
        this.sources = sources;
        this.resolver = resolver;
        this.userInfoService = userInfoService;
        this.audit = audit;
        this.delegate.setOauth2UserService(userInfoService);
    }

    @Override
    public OidcUser loadUser(OidcUserRequest request) {
        IdentitySourceClientRegistrationRepository.RegistrationKey key =
                IdentitySourceClientRegistrationRepository.RegistrationKey.parse(
                        request.getClientRegistration().getRegistrationId());
        IdentitySource source = sources.findById(key.sourceId()).orElseThrow(this::denied);
        if (source.getStatus() != IdentitySource.Status.ACTIVE || source.getRevision() != key.revision()
                || !source.getIssuer().equals(request.getIdToken().getIssuer().toString())) {
            throw denied();
        }
        validateClaims(request, source);
        OidcUser upstream = delegate.loadUser(request);
        String subject = upstream.getSubject();
        FederatedIdentityResolver.ResolvedIdentity resolved = resolver.resolve(
                source.getId(), source.getRevision(), source.getIssuer(), subject);
        var principal = resolved.principal();
        audit.log(source.getTenantId(), principal.getId(), "FEDERATED_LOGIN", "identity_source",
                source.getId().toString(), null, null, null);
        return new LocalPrincipalOidcUser(upstream, principal.getId());
    }

    private void validateClaims(OidcUserRequest request, IdentitySource source) {
        var idToken = request.getIdToken();
        String algorithmName;
        String keyIdValue;
        try {
            SignedJWT signed = SignedJWT.parse(idToken.getTokenValue());
            algorithmName = signed.getHeader().getAlgorithm().getName();
            keyIdValue = signed.getHeader().getKeyID();
        } catch (java.text.ParseException ex) {
            throw denied();
        }
        if (!source.getAllowedSigningAlgorithms().contains(algorithmName)
                || keyIdValue == null || keyIdValue.isBlank()
                || !OidcAudienceRules.matches(idToken.getAudience(), source.getClientId(), idToken.getClaimAsString("azp"))
                || idToken.getIssuedAt() == null || idToken.getExpiresAt() == null
                || idToken.getIssuedAt().isAfter(Instant.now().plusSeconds(60))
                || idToken.getExpiresAt().isBefore(Instant.now())) {
            throw denied();
        }
        for (String claim : source.getRequiredClaims()) {
            if (!idToken.getClaims().containsKey(claim) || idToken.getClaims().get(claim) == null) throw denied();
        }
        if (!source.getRequiredAcrValues().isEmpty()
                && !source.getRequiredAcrValues().contains(idToken.getClaimAsString("acr"))) throw denied();
    }

    private FederatedAuthenticationException denied() {
        return new FederatedAuthenticationException();
    }

    private static final class LocalPrincipalOidcUser implements OidcUser {
        private final OidcUser delegate;
        private final String localPrincipalId;
        private LocalPrincipalOidcUser(OidcUser delegate, String localPrincipalId) {
            this.delegate = delegate; this.localPrincipalId = localPrincipalId;
        }
        @Override public String getName() { return localPrincipalId; }
        @Override public Collection<? extends GrantedAuthority> getAuthorities() { return delegate.getAuthorities(); }
        @Override public java.util.Map<String, Object> getAttributes() { return delegate.getAttributes(); }
        @Override public java.util.Map<String, Object> getClaims() { return delegate.getClaims(); }
        @Override public String getSubject() { return delegate.getSubject(); }
        @Override public java.net.URL getIssuer() { return delegate.getIssuer(); }
        @Override public OidcIdToken getIdToken() { return delegate.getIdToken(); }
        @Override public OidcUserInfo getUserInfo() { return delegate.getUserInfo(); }
    }
}
