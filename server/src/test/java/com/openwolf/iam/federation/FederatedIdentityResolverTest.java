package com.openwolf.iam.federation;

import com.openwolf.iam.entity.ExternalIdentityLink;
import com.openwolf.iam.entity.IdentitySource;
import com.openwolf.iam.entity.Principal;
import com.openwolf.iam.repository.ExternalIdentityLinkRepository;
import com.openwolf.iam.repository.IdentitySourceRepository;
import com.openwolf.iam.repository.PrincipalRepository;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class FederatedIdentityResolverTest {
    @Test
    void resolvesExactActiveSourceLinkAndPrincipalToStableLocalId() {
        IdentitySource source = source();
        Principal principal = new Principal("local-principal", "tenant-a", "local", "local@example.test", "x", true, "{}");
        ExternalIdentityLink link = new ExternalIdentityLink("tenant-a", source.getId(), source.getIssuer(), "opaque-sub", principal.getId());
        IdentitySourceRepository sources = mock(IdentitySourceRepository.class);
        ExternalIdentityLinkRepository links = mock(ExternalIdentityLinkRepository.class);
        PrincipalRepository principals = mock(PrincipalRepository.class);
        when(sources.findById(source.getId())).thenReturn(Optional.of(source));
        when(links.findBySourceIdAndIssuerAndSubject(source.getId(), source.getIssuer(), "opaque-sub"))
                .thenReturn(Optional.of(link));
        when(principals.findByIdAndTenantId(principal.getId(), "tenant-a")).thenReturn(Optional.of(principal));

        var resolved = new FederatedIdentityResolver(sources, links, principals)
                .resolve(source.getId(), source.getRevision(), source.getIssuer(), "opaque-sub");

        assertThat(resolved.principal().getId()).isEqualTo("local-principal");
    }

    @Test
    void disabledOrUnlinkedIdentityHasTheSameOpaqueDenial() {
        IdentitySource source = source();
        IdentitySourceRepository sources = mock(IdentitySourceRepository.class);
        ExternalIdentityLinkRepository links = mock(ExternalIdentityLinkRepository.class);
        when(sources.findById(source.getId())).thenReturn(Optional.of(source));
        when(links.findBySourceIdAndIssuerAndSubject(source.getId(), source.getIssuer(), "unknown"))
                .thenReturn(Optional.empty());
        var resolver = new FederatedIdentityResolver(sources, links, mock(PrincipalRepository.class));

        assertThatThrownBy(() -> resolver.resolve(source.getId(), source.getRevision(), source.getIssuer(), "unknown"))
                .isInstanceOf(FederatedAuthenticationException.class)
                .hasMessage("federated identity is not available");
    }

    private static IdentitySource source() {
        IdentitySource source = new IdentitySource("tenant-a", "Customer IdP", "https://idp.example.test",
                "https://idp.example.test/.well-known/openid-configuration", "client", "ciphertext",
                List.of("openid"), List.of("RS256"), List.of("sub", "iss", "aud", "exp", "iat", "nonce"), List.of());
        source.applyValidatedMetadata("https://idp.example.test/authorize", "https://idp.example.test/token",
                "https://idp.example.test/userinfo", "https://idp.example.test/jwks", Instant.now());
        source.activate();
        return source;
    }
}
