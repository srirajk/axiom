package com.openwolf.iam.repository;

import com.openwolf.iam.entity.ScimResourceLink;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.List;
import java.util.UUID;

public interface ScimResourceLinkRepository extends JpaRepository<ScimResourceLink, UUID> {
    List<ScimResourceLink> findBySourceId(UUID sourceId);
    Optional<ScimResourceLink> findBySourceIdAndResourceTypeAndExternalId(UUID sourceId, String resourceType, String externalId);
    Optional<ScimResourceLink> findBySourceIdAndResourceTypeAndResourceId(UUID sourceId, String resourceType, String resourceId);
    Page<ScimResourceLink> findBySourceIdAndResourceType(UUID sourceId, String resourceType, Pageable pageable);
    Page<ScimResourceLink> findBySourceIdAndResourceTypeAndExternalId(UUID sourceId, String resourceType, String externalId, Pageable pageable);
}
