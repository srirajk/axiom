package com.openwolf.iam.tenancy;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Durable backing for the active directory (Axiom B4). The in-memory {@link ActiveTenantDirectory}
 * snapshot is the request-path read; this repository is loaded at startup and written on the
 * activation/deactivation CAS only — never on a lookup.
 */
@Repository
public interface ActiveTenantRepository extends JpaRepository<ActiveTenant, String> {
}
