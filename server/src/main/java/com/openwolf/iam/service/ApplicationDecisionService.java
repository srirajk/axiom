package com.openwolf.iam.service;

import com.openwolf.iam.dto.ApplicationDecisionBatchRequest;
import com.openwolf.iam.dto.ApplicationDecisionItem;
import com.openwolf.iam.dto.ApplicationDecisionResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Application-access policy v1. RBAC comes only from active application role permissions; ABAC is
 * the neutral membership {@code scopes} map. This is deliberately separate from Axiom-admin Cerbos
 * Policy Studio and never evaluates application governance policy.
 */
@Service
@Transactional
public class ApplicationDecisionService {
    private final ApplicationAccessService access;
    private final AuditService audit;

    public ApplicationDecisionService(ApplicationAccessService access, AuditService audit) {
        this.access = access;
        this.audit = audit;
    }

    public ApplicationDecisionResponse decide(String tenantId, String subjectId, UUID applicationId,
                                               ApplicationDecisionBatchRequest request,
                                               HttpServletRequest httpRequest) {
        if (!"1.0".equals(request.contractVersion())) throw new IllegalArgumentException("unsupported contract version");
        requireUniqueKeys(request.decisions());
        Optional<ApplicationAccessService.DecisionAuthority> resolved;
        try {
            resolved = access.decisionAuthority(tenantId, applicationId, subjectId);
        } catch (RuntimeException unavailable) {
            return deniedBatch(tenantId, subjectId, request.decisions(), "DENY_AUTHORITY_UNAVAILABLE", request, httpRequest);
        }
        if (resolved.isEmpty()) {
            return deniedBatch(tenantId, subjectId, request.decisions(), "DENY_SUBJECT_OR_MEMBERSHIP", request, httpRequest);
        }
        ApplicationAccessService.DecisionAuthority authority = resolved.get();
        List<ApplicationDecisionResponse.Result> results = new ArrayList<>();
        for (ApplicationDecisionItem item : request.decisions()) {
            String effectOrDeny = reason(tenantId, authority, item);
            boolean allowed = Set.of("allow", "read", "scoped").contains(effectOrDeny);
            boolean cosign = "cosign".equals(effectOrDeny);
            String reason = allowed ? ("scoped".equals(effectOrDeny) ? "SCOPED_PERMISSION_GRANTED" : "PERMISSION_GRANTED")
                    : cosign ? "COSIGN_REQUIRED" : effectOrDeny;
            ApplicationDecisionResponse.Result result = new ApplicationDecisionResponse.Result(item.decisionKey(),
                    allowed ? "permit" : cosign ? "require_cosign" : "deny", allowed,
                    allowed ? effectOrDeny : cosign ? "cosign" : "deny", List.of(reason), UUID.randomUUID());
            audit(result, tenantId, subjectId, authority.applicationKey(), Long.toString(authority.entitlementRevision()),
                    authority.policyRevision(), request, httpRequest);
            results.add(result);
        }
        return new ApplicationDecisionResponse("1.0", request.requestId(), tenantId, subjectId,
                Long.toString(authority.entitlementRevision()), authority.policyRevision(), Instant.now(), results);
    }

    private ApplicationDecisionResponse deniedBatch(String tenantId, String subjectId, List<ApplicationDecisionItem> items, String reason,
                                                    ApplicationDecisionBatchRequest request, HttpServletRequest httpRequest) {
        List<ApplicationDecisionResponse.Result> results = new ArrayList<>();
        for (ApplicationDecisionItem item : items) {
            ApplicationDecisionResponse.Result result = new ApplicationDecisionResponse.Result(item.decisionKey(),
                    "deny", false, "deny", List.of(reason), UUID.randomUUID());
            audit(result, tenantId, subjectId, "", "unavailable", "unavailable", request, httpRequest);
            results.add(result);
        }
        return new ApplicationDecisionResponse("1.0", request.requestId(), tenantId, subjectId,
                "unavailable", "unavailable", Instant.now(), results);
    }

    private static String reason(String tenantId, ApplicationAccessService.DecisionAuthority authority, ApplicationDecisionItem item) {
        if (!tenantId.equals(item.resource().tenantId()) || !scalar(item.resource().kind()) || !scalar(item.resource().id())
                || !Set.of("ordinary", "no_disclosure", "sensitive").contains(item.resource().disclosureClass())
                || !scalar(item.permission()) || !allScalars(item.resource().attributes())) {
            return "DENY_MALFORMED";
        }
        String effect = authority.permissionEffects().get(item.permission());
        if (effect == null) return "DENY_UNKNOWN_PERMISSION";
        if ("scoped".equals(effect) && !scopeMatches(authority.attributes(), item)) return "DENY_SCOPE";
        return effect;
    }

    private static boolean scopeMatches(Map<String, Object> attributes, ApplicationDecisionItem item) {
        Object raw = attributes.get("scopes");
        if (!(raw instanceof Map<?, ?> scopes)) return false;
        Map<String, Object> coordinates = new java.util.TreeMap<>(item.resource().attributes());
        if (item.resource().domain() != null) coordinates.put("domain", item.resource().domain());
        if (item.resource().ownerSubjectId() != null) coordinates.put("owner_subject_id", item.resource().ownerSubjectId());
        if (scopes.isEmpty()) return false;
        int applied = 0;
        for (Map.Entry<?, ?> configured : scopes.entrySet()) {
            if (!(configured.getKey() instanceof String key) || key.isBlank() || !coordinates.containsKey(key)
                    || !scalar(coordinates.get(key))) return false;
            Object allowance = configured.getValue();
            if (!(allowance instanceof Collection<?> values) || !values.stream()
                    .map(ApplicationDecisionService::scalarValue).anyMatch(resourceValue -> resourceValue.equals(scalarValue(coordinates.get(key))))) {
                return false;
            }
            applied++;
        }
        return applied > 0;
    }

    private static boolean allScalars(Map<String, Object> attributes) {
        return attributes != null && attributes.entrySet().stream()
                .allMatch(entry -> scalar(entry.getKey()) && scalar(entry.getValue()));
    }

    private static boolean scalar(Object value) {
        return value instanceof String text ? !text.isBlank()
                : value instanceof Number || value instanceof Boolean;
    }

    private static String scalarValue(Object value) {
        return scalar(value) ? String.valueOf(value) : "";
    }

    private static void requireUniqueKeys(List<ApplicationDecisionItem> items) {
        Set<String> keys = new HashSet<>();
        for (ApplicationDecisionItem item : items) {
            if (!keys.add(item.decisionKey())) throw new IllegalArgumentException("duplicate decision key");
        }
    }

    private void audit(ApplicationDecisionResponse.Result result, String tenantId, String subjectId, String applicationKey,
                       String entitlementRevision, String policyRevision, ApplicationDecisionBatchRequest request,
                       HttpServletRequest httpRequest) {
        audit.logRequired(tenantId, audit.currentActor(), "EVALUATE_APPLICATION_ACCESS_DECISION",
                "application_access_decision", result.callId().toString(), null,
                Map.of("decision_key", result.decisionKey(), "application_id", applicationKey, "subject_id", subjectId,
                        "allowed", result.allowed(), "reason_codes", result.reasonCodes(),
                        "entitlement_revision", entitlementRevision, "application_access_policy_revision", policyRevision),
                request.requestId() == null ? correlation(httpRequest) : request.requestId());
    }

    private static String correlation(HttpServletRequest request) {
        return request == null ? null : request.getHeader("X-Correlation-ID");
    }
}
