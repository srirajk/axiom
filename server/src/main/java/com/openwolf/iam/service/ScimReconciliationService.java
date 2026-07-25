package com.openwolf.iam.service;

import com.openwolf.iam.auth.ExecutionTenant;
import com.openwolf.iam.dto.ScimReconciliationResponse;
import com.openwolf.iam.entity.Group;
import com.openwolf.iam.entity.Principal;
import com.openwolf.iam.entity.ScimProvisioningSource;
import com.openwolf.iam.entity.ScimResourceLink;
import com.openwolf.iam.exception.EntityNotFoundException;
import com.openwolf.iam.repository.GroupRepository;
import com.openwolf.iam.repository.PrincipalRepository;
import com.openwolf.iam.repository.ScimProvisioningSourceRepository;
import com.openwolf.iam.repository.ScimResourceLinkRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@Transactional
public class ScimReconciliationService {
    private final ScimProvisioningSourceRepository sources;
    private final ScimResourceLinkRepository links;
    private final PrincipalRepository principals;
    private final GroupRepository groups;
    private final AuditService audit;
    private final ExecutionTenant tenant;

    public ScimReconciliationService(ScimProvisioningSourceRepository sources, ScimResourceLinkRepository links,
                                     PrincipalRepository principals, GroupRepository groups, AuditService audit,
                                     ExecutionTenant tenant) {
        this.sources = sources; this.links = links; this.principals = principals; this.groups = groups;
        this.audit = audit; this.tenant = tenant;
    }

    public ScimReconciliationResponse check(String tenantId, UUID sourceId, HttpServletRequest request) {
        if (!tenant.require().equals(tenantId)) throw EntityNotFoundException.forId("SCIM source", sourceId);
        ScimProvisioningSource source = sources.findByIdAndTenantId(sourceId, tenantId)
                .orElseThrow(() -> EntityNotFoundException.forId("SCIM source", sourceId));
        List<ScimResourceLink> sourceLinks = links.findBySourceId(sourceId);
        List<String> missing = new ArrayList<>();
        List<String> mismatches = new ArrayList<>();
        Map<String, Integer> externalIds = new HashMap<>();
        long users = 0; long groupsCount = 0;
        for (ScimResourceLink link : sourceLinks) {
            externalIds.merge(link.getResourceType() + ":" + link.getExternalId(), 1, Integer::sum);
            if ("User".equals(link.getResourceType())) {
                users++;
                var principal = principals.findByIdAndTenantId(link.getResourceId(), tenantId);
                if (principal.isEmpty()) missing.add("User:" + link.getResourceId() + ":" + link.getExternalId());
                else if (!sourceId.equals(principal.get().getScimSourceId())) mismatches.add("User:" + link.getResourceId());
            } else if ("Group".equals(link.getResourceType())) {
                groupsCount++;
                try {
                    var group = groups.findByIdAndTenantId(UUID.fromString(link.getResourceId()), tenantId);
                    if (group.isEmpty()) missing.add("Group:" + link.getResourceId() + ":" + link.getExternalId());
                    else if (!sourceId.equals(group.get().getScimSourceId())) mismatches.add("Group:" + link.getResourceId());
                } catch (IllegalArgumentException ex) { missing.add("Group:" + link.getResourceId() + ":" + link.getExternalId()); }
            } else {
                missing.add(link.getResourceType() + ":" + link.getResourceId());
            }
        }
        List<String> duplicates = externalIds.entrySet().stream().filter(entry -> entry.getValue() > 1).map(Map.Entry::getKey).sorted().toList();
        ScimReconciliationResponse result = new ScimReconciliationResponse(source.getId(), tenantId, users, groupsCount,
                List.copyOf(missing), List.copyOf(mismatches), duplicates, Instant.now());
        audit.logRequired(tenantId, audit.currentActor(), "RECONCILE_SCIM_SOURCE", "scim_source", sourceId.toString(), null, result, correlation(request));
        return result;
    }

    private static String correlation(HttpServletRequest request) { return request == null ? null : request.getHeader("X-Correlation-ID"); }
}
