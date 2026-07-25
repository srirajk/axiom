package com.openwolf.iam.federation;

import com.openwolf.iam.entity.IdentitySource;
import com.openwolf.iam.repository.IdentitySourceRepository;
import org.springframework.stereotype.Service;

import java.util.UUID;

/** Rechecks the persisted source fence immediately before each upstream protocol call. */
@Service
public final class IdentitySourceRevisionGuard {
    private final IdentitySourceRepository sources;

    public IdentitySourceRevisionGuard(IdentitySourceRepository sources) {
        this.sources = sources;
    }

    public IdentitySource requireActive(IdentitySourceClientRegistrationRepository.RegistrationKey key) {
        try {
            IdentitySource source = sources.findById(key.sourceId()).orElseThrow(FederatedAuthenticationException::new);
            if (source.getStatus() != IdentitySource.Status.ACTIVE || source.getRevision() != key.revision()) {
                throw new FederatedAuthenticationException();
            }
            return source;
        } catch (FederatedAuthenticationException ex) {
            throw ex;
        } catch (RuntimeException ex) {
            throw new FederatedAuthenticationException(ex);
        }
    }
}
