package com.openwolf.iam.policystudio.breakglass;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface BreakGlassBundleGrantRepository extends JpaRepository<BreakGlassBundleGrant, String> {
    List<BreakGlassBundleGrant> findByBundleId(String bundleId);
    boolean existsByBundleId(String bundleId);
}
