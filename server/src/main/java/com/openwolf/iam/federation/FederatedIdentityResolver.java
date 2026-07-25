package com.openwolf.iam.federation;

import com.openwolf.iam.entity.ExternalIdentityLink;
import com.openwolf.iam.entity.IdentitySource;
import com.openwolf.iam.entity.Principal;
import com.openwolf.iam.repository.ExternalIdentityLinkRepository;
import com.openwolf.iam.repository.IdentitySourceRepository;
import com.openwolf.iam.repository.PrincipalRepository;
import org.springframework.stereotype.Service;

import java.util.UUID;

/** Fail-closed mapping from a verified upstream tuple to an existing local principal. */
@Service
public final class FederatedIdentityResolver {
    private final IdentitySourceRepository sources;
    private final ExternalIdentityLinkRepository links;
    private final PrincipalRepository principals;

    public FederatedIdentityResolver(IdentitySourceRepository sources,
                                     ExternalIdentityLinkRepository links,
                                     PrincipalRepository principals) {
        this.sources = sources;
        this.links = links;
        this.principals = principals;
    }

    public ResolvedIdentity resolve(UUID sourceId, long revision, String issuer, String subject) {
        IdentitySource source = sources.findById(sourceId).orElseThrow(this::denied);
        if (source.getStatus() != IdentitySource.Status.ACTIVE
                || source.getRevision() != revision
                || !source.getIssuer().equals(issuer)) {
            throw denied();
        }
        ExternalIdentityLink link = links.findBySourceIdAndIssuerAndSubject(sourceId, issuer, subject)
                .filter(value -> value.getStatus() == ExternalIdentityLink.Status.ACTIVE)
                .orElseThrow(this::denied);
        Principal principal = principals.findByIdAndTenantId(link.getPrincipalId(), source.getTenantId())
                .filter(Principal::isActive)
                .orElseThrow(this::denied);
        return new ResolvedIdentity(source, principal);
    }

    private FederatedAuthenticationException denied() {
        return new FederatedAuthenticationException();
    }

    public record ResolvedIdentity(IdentitySource source, Principal principal) {}
}
