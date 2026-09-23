package com.openwolf.iam.repository;

import com.openwolf.iam.entity.CiamLifecycleEvent;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface CiamLifecycleEventRepository extends JpaRepository<CiamLifecycleEvent, UUID> {
    List<CiamLifecycleEvent> findByTenantIdOrderByOccurredAtAsc(String tenantId);
}
