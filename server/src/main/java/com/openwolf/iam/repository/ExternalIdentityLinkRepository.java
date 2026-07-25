package com.openwolf.iam.repository;

import com.openwolf.iam.entity.ExternalIdentityLink;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface ExternalIdentityLinkRepository extends JpaRepository<ExternalIdentityLink, UUID> {
    List<ExternalIdentityLink> findByTenantIdAndSourceIdOrderBySubject(String tenantId, UUID sourceId);
    Optional<ExternalIdentityLink> findByIdAndTenantId(UUID id, String tenantId);
    Optional<ExternalIdentityLink> findBySourceIdAndIssuerAndSubject(UUID sourceId, String issuer, String subject);
    boolean existsBySourceIdAndIssuerAndSubject(UUID sourceId, String issuer, String subject);
    boolean existsBySourceIdAndPrincipalId(UUID sourceId, String principalId);
}
