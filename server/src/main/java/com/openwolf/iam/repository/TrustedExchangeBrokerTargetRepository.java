package com.openwolf.iam.repository;

import com.openwolf.iam.entity.TrustedExchangeBrokerTarget;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface TrustedExchangeBrokerTargetRepository extends JpaRepository<TrustedExchangeBrokerTarget, UUID> {
    List<TrustedExchangeBrokerTarget> findByTenantIdAndBrokerIdOrderByCreatedAtAsc(String tenantId, UUID brokerId);
    List<TrustedExchangeBrokerTarget> findByTenantIdAndBrokerIdAndAudienceOrderByCreatedAtDesc(
            String tenantId, UUID brokerId, String audience);
    Optional<TrustedExchangeBrokerTarget> findByTenantIdAndBrokerIdAndId(String tenantId, UUID brokerId, UUID id);
}
