package com.openwolf.iam.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record ScimReconciliationResponse(UUID sourceId, String tenantId, long sourceLinkedUsers,
                                         long sourceLinkedGroups, List<String> missingBackingResources,
                                         List<String> ownershipMismatches, List<String> duplicateExternalIds,
                                         Instant checkedAt) {}
