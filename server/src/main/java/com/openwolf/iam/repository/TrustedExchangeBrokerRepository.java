package com.openwolf.iam.repository;

import com.openwolf.iam.entity.TrustedExchangeBroker;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface TrustedExchangeBrokerRepository extends JpaRepository<TrustedExchangeBroker, UUID> {
    Optional<TrustedExchangeBroker> findByTenantIdAndOauthClientId(String tenantId, String oauthClientId);
    Optional<TrustedExchangeBroker> findByOauthClientId(String oauthClientId);
    Optional<TrustedExchangeBroker> findByTenantIdAndGatewayAudience(String tenantId, String gatewayAudience);
    List<TrustedExchangeBroker> findByTenantIdOrderByCreatedAtAsc(String tenantId);
}
