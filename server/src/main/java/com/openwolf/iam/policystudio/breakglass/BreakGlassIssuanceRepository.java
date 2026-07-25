package com.openwolf.iam.policystudio.breakglass;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface BreakGlassIssuanceRepository extends JpaRepository<BreakGlassIssuance, String> {
    List<BreakGlassIssuance> findByStateAndAuditRecordedFalse(BreakGlassIssuance.State state);
    List<BreakGlassIssuance> findByActiveBundleIdAndState(String activeBundleId, BreakGlassIssuance.State state);
    boolean existsByActiveBundleIdAndState(String activeBundleId, BreakGlassIssuance.State state);
}
