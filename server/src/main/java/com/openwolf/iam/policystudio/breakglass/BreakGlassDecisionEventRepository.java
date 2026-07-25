package com.openwolf.iam.policystudio.breakglass;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface BreakGlassDecisionEventRepository extends JpaRepository<BreakGlassDecisionEvent, String> {
    List<BreakGlassDecisionEvent> findByDecisionAndProcessedFalseOrderByOccurredAt(String decision);
}
