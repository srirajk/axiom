package com.openwolf.iam.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.openwolf.iam.auth.TenantClaims;
import com.openwolf.iam.dto.SubjectContextResponse;
import com.openwolf.iam.entity.Principal;
import com.openwolf.iam.entity.Role;
import com.openwolf.iam.repository.PrincipalRepository;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.Set;

/** Reads subject entitlements from Axiom-owned, tenant-qualified state only. */
@Service
public class SubjectContextService {
    private static final String USE_CASE_SCOPE_MODE = "use_case_scope_mode";
    private static final String USE_CASE_SCOPES = "use_case_scopes";
    private static final Set<String> SAFE_DOMAIN_ATTRIBUTE_KEYS = Set.of("classification", "business_line");

    private final PrincipalRepository principalRepository;
    private final ObjectMapper objectMapper;
    private final ApplicationAccessService applicationAccess;

    @Autowired
    public SubjectContextService(PrincipalRepository principalRepository, ObjectMapper objectMapper,
                                 ApplicationAccessService applicationAccess) {
        this.principalRepository = principalRepository;
        this.objectMapper = objectMapper;
        this.applicationAccess = applicationAccess;
    }

    /** Preserves direct unit construction for legacy tenant-global context tests. */
    public SubjectContextService(PrincipalRepository principalRepository, ObjectMapper objectMapper) {
        this(principalRepository, objectMapper, null);
    }

    @Transactional(readOnly = true)
    public Optional<SubjectContextResponse> resolve(String subjectId, String tenantId) {
        String canonicalTenant = TenantClaims.requireTenant(tenantId);
        return principalRepository.findByIdAndTenantId(subjectId, canonicalTenant)
                .filter(Principal::isActive)
                .map(principal -> toResponse(principal, canonicalTenant));
    }

    /**
     * Service consumers receive only the exact application membership, never tenant-wide Axiom
     * administration roles or attributes. The frozen fields are projected from neutral membership
     * role/permission/effect and scopes state.
     */
    @Transactional(readOnly = true)
    public Optional<SubjectContextResponse> resolveForApplication(String requestId, String subjectId, String tenantId,
                                                                    java.util.UUID applicationId) {
        if (applicationAccess == null) throw new IllegalStateException("application access authority unavailable");
        return applicationAccess.decisionAuthority(tenantId, applicationId, subjectId).map(authority -> {
            Map<String, Object> attributes = new TreeMap<>(authority.attributes());
            List<String> domains = scopeValues(attributes.get("scopes"), "domain");
            return new SubjectContextResponse("1.0", requestId, subjectId, tenantId, true,
                    authority.roleKeys().stream().sorted().toList(), domains, attributes,
                    Long.toString(authority.entitlementRevision()), java.time.Instant.now());
        });
    }

    private static List<String> scopeValues(Object rawScopes, String key) {
        if (!(rawScopes instanceof Map<?, ?> scopes) || !(scopes.get(key) instanceof Collection<?> values)) return List.of();
        return values.stream().map(String::valueOf).filter(value -> !value.isBlank()).sorted().toList();
    }

    private SubjectContextResponse toResponse(Principal principal, String tenantId) {
        Map<String, Object> attributes = parseAttributes(principal.getAttributes());
        String useCaseScopeMode = textValue(attributes.get(USE_CASE_SCOPE_MODE));
        List<String> useCaseScopes = stringList(attributes.get(USE_CASE_SCOPES));
        String canonicalScopeMode = canonicalScopeMode(useCaseScopeMode, useCaseScopes);
        Map<String, Object> domainAttributes = new TreeMap<>();
        SAFE_DOMAIN_ATTRIBUTE_KEYS.forEach(key -> {
            if (attributes.containsKey(key)) domainAttributes.put(key, attributes.get(key));
        });
        List<String> domains = domains(attributes);
        List<String> roles = new TreeSet<>(principal.getRoles().stream()
                .map(Role::getName)
                .filter(name -> name != null && !name.isBlank())
                .toList()).stream().toList();
        List<String> permissions = new TreeSet<>(principal.getRoles().stream()
                .map(Role::getPermissions)
                .map(this::parsePermissions)
                .flatMap(Collection::stream)
                .filter(permission -> permission != null && !permission.isBlank())
                .toList()).stream().toList();
        String revision = entitlementRevision(principal, tenantId, roles, domains, domainAttributes,
                canonicalScopeMode, useCaseScopes, permissions);
        return new SubjectContextResponse("1.0", "legacy", principal.getId(), tenantId, true, roles, domains,
                domainAttributes, revision, java.time.Instant.now());
    }

    private Map<String, Object> parseAttributes(String json) {
        if (json == null || json.isBlank()) return Map.of();
        try {
            return objectMapper.readValue(json, new TypeReference<>() {});
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("subject attributes are not valid Axiom JSON", ex);
        }
    }

    private List<String> parsePermissions(String json) {
        if (json == null || json.isBlank()) return List.of();
        try {
            return objectMapper.readValue(json, new TypeReference<>() {});
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("role permissions are not valid Axiom JSON", ex);
        }
    }

    private static String textValue(Object value) {
        return value == null || String.valueOf(value).isBlank() ? null : String.valueOf(value);
    }

    private static List<String> stringList(Object value) {
        if (!(value instanceof Collection<?> values)) return List.of();
        return values.stream().map(String::valueOf).filter(valueItem -> !valueItem.isBlank()).sorted().toList();
    }

    private static String canonicalScopeMode(String mode, List<String> scopes) {
        String resolved = mode == null ? "all_in_assigned_domains" : mode;
        if ("all_in_assigned_domains".equals(resolved) && !scopes.isEmpty()) {
            throw new IllegalStateException("all_in_assigned_domains cannot carry listed use-case scopes");
        }
        if ("listed_only".equals(resolved) && scopes.isEmpty()) {
            throw new IllegalStateException("listed_only requires non-empty use-case scopes");
        }
        if (!"all_in_assigned_domains".equals(resolved) && !"listed_only".equals(resolved)) {
            throw new IllegalStateException("unsupported use-case scope mode");
        }
        return resolved;
    }

    private static List<String> domains(Map<String, Object> attributes) {
        TreeSet<String> domains = new TreeSet<>(stringList(attributes.get("admin_domains")));
        Object rawSegments = attributes.get("segments");
        if (rawSegments instanceof Map<?, ?> segmentMap) {
            segmentMap.keySet().stream().map(String::valueOf)
                    .filter(value -> !value.isBlank()).forEach(domains::add);
        } else if (rawSegments instanceof Collection<?> segmentList) {
            segmentList.stream().map(String::valueOf)
                    .filter(value -> !value.isBlank()).forEach(domains::add);
        }
        return domains.stream().toList();
    }

    private String entitlementRevision(
            Principal principal,
            String tenantId,
            List<String> roles,
            List<String> domains,
            Map<String, Object> domainAttributes,
            String useCaseScopeMode,
            List<String> useCaseScopes,
            List<String> permissions) {
        Map<String, Object> canonical = new LinkedHashMap<>();
        canonical.put("subject_id", principal.getId());
        canonical.put("tenant_id", tenantId);
        canonical.put("active", principal.isActive());
        canonical.put("roles", roles);
        canonical.put("domains", domains);
        canonical.put("domain_attributes", new TreeMap<>(domainAttributes));
        canonical.put("use_case_scope_mode", useCaseScopeMode);
        canonical.put("use_case_scopes", useCaseScopes);
        canonical.put("permissions", permissions);
        try {
            byte[] bytes = objectMapper.writeValueAsBytes(canonical);
            return hex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (JsonProcessingException | NoSuchAlgorithmException ex) {
            throw new IllegalStateException("could not derive entitlement revision", ex);
        }
    }

    private static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) result.append(String.format("%02x", value));
        return result.toString();
    }
}
