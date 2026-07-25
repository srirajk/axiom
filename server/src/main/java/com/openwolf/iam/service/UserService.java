package com.openwolf.iam.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.openwolf.iam.dto.CreateUserRequest;
import com.openwolf.iam.dto.PageResponse;
import com.openwolf.iam.dto.UpdateUserRequest;
import com.openwolf.iam.dto.UserResponse;
import com.openwolf.iam.auth.ExecutionTenant;
import com.openwolf.iam.entity.Group;
import com.openwolf.iam.entity.Principal;
import com.openwolf.iam.entity.Role;
import com.openwolf.iam.exception.EntityNotFoundException;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.repository.GroupRepository;
import com.openwolf.iam.repository.PrincipalRepository;
import com.openwolf.iam.repository.RoleRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

@Service
@Transactional
public class UserService {

    private static final Logger log = LoggerFactory.getLogger(UserService.class);
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};
    private static final TypeReference<List<String>> LIST_TYPE = new TypeReference<>() {};

    private final PrincipalRepository principalRepository;
    private final RoleRepository roleRepository;
    private final GroupRepository groupRepository;
    private final AuditService auditService;
    private final PasswordEncoder passwordEncoder;
    private final ObjectMapper objectMapper;
    private final ExecutionTenant executionTenant;

    public UserService(PrincipalRepository principalRepository,
                       RoleRepository roleRepository,
                       GroupRepository groupRepository,
                       AuditService auditService,
                       PasswordEncoder passwordEncoder,
                       ObjectMapper objectMapper,
                       ExecutionTenant executionTenant) {
        this.principalRepository = principalRepository;
        this.roleRepository = roleRepository;
        this.groupRepository = groupRepository;
        this.auditService = auditService;
        this.passwordEncoder = passwordEncoder;
        this.objectMapper = objectMapper;
        this.executionTenant = executionTenant;
    }

    // -------------------------------------------------------
    // List / Get
    // -------------------------------------------------------

    @Transactional(readOnly = true)
    public PageResponse<UserResponse> listUsers(int page, int size) {
        Page<Principal> principals = principalRepository.findByTenantId(executionTenant.require(), PageRequest.of(page, size));
        Page<UserResponse> responses = principals.map(this::toUserResponse);
        return PageResponse.of(responses);
    }

    @Transactional(readOnly = true)
    public UserResponse getUser(String userId) {
        Principal p = principalRepository.findByIdAndTenantId(userId, executionTenant.require())
                .orElseThrow(() -> EntityNotFoundException.forId("User", userId));
        return toUserResponse(p);
    }

    // -------------------------------------------------------
    // Create
    // -------------------------------------------------------

    public UserResponse createUser(CreateUserRequest req, HttpServletRequest httpReq) {
        String tenantId = executionTenant.require();
        if (principalRepository.findByUsername(req.username()).isPresent()) {
            throw new ResourceConflictException("Username already taken: " + req.username());
        }

        String attrsJson = serializeAttributes(req.attributes());
        Principal p = new Principal(
                req.id(),
                tenantId,
                req.username(),
                req.email(),
                passwordEncoder.encode(req.password()),
                true,
                attrsJson
        );
        principalRepository.save(p);

        auditService.log(tenantId, auditService.currentActor(),
                "CREATE_USER", "user", p.getId(), null, toUserResponse(p), httpReq);
        log.info("Created user id={} username={}", p.getId(), p.getUsername());
        return toUserResponse(p);
    }

    // -------------------------------------------------------
    // Update
    // -------------------------------------------------------

    public UserResponse updateUser(String userId, UpdateUserRequest req, HttpServletRequest httpReq) {
        String tenantId = executionTenant.require();
        Principal p = principalRepository.findByIdAndTenantId(userId, tenantId)
                .orElseThrow(() -> EntityNotFoundException.forId("User", userId));

        if (p.getScimSourceId() != null) {
            throw new ResourceConflictException("SCIM-owned identity fields must be changed through SCIM");
        }

        UserResponse before = toUserResponse(p);

        if (req.email() != null) p.setEmail(req.email());
        if (req.isActive() != null) p.setActive(req.isActive());
        if (req.attributes() != null) p.setAttributes(mergeAttributes(p.getAttributes(), req.attributes()));

        principalRepository.save(p);
        UserResponse after = toUserResponse(p);
        auditService.log(tenantId, auditService.currentActor(),
                "UPDATE_USER", "user", userId, before, after, httpReq);
        return after;
    }

    // -------------------------------------------------------
    // Delete (soft)
    // -------------------------------------------------------

    public void deleteUser(String userId, HttpServletRequest httpReq) {
        String tenantId = executionTenant.require();
        Principal p = principalRepository.findByIdAndTenantId(userId, tenantId)
                .orElseThrow(() -> EntityNotFoundException.forId("User", userId));

        if (p.getScimSourceId() != null) {
            throw new ResourceConflictException("SCIM-owned identity fields must be changed through SCIM");
        }

        UserResponse before = toUserResponse(p);
        p.setActive(false);
        principalRepository.save(p);
        auditService.log(tenantId, auditService.currentActor(),
                "DELETE_USER", "user", userId, before, null, httpReq);
        log.info("Soft-deleted user id={}", userId);
    }

    // -------------------------------------------------------
    // Roles
    // -------------------------------------------------------

    public UserResponse assignRole(String userId, String roleId, HttpServletRequest httpReq) {
        String tenantId = executionTenant.require();
        Principal p = principalRepository.findByIdAndTenantId(userId, tenantId)
                .orElseThrow(() -> EntityNotFoundException.forId("User", userId));

        UUID roleUuid;
        try {
            roleUuid = UUID.fromString(roleId);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Invalid role ID format: " + roleId);
        }

        Role role = roleRepository.findByIdAndTenantId(roleUuid, tenantId)
                .orElseThrow(() -> EntityNotFoundException.forId("Role", roleId));

        if (!p.getTenantId().equals(role.getTenantId())) {
            throw new IllegalArgumentException("role assignment cannot cross tenant boundaries");
        }
        p.assignRole(role);
        principalRepository.save(p);

        UserResponse after = toUserResponse(p);
        auditService.log(tenantId, auditService.currentActor(),
                "ASSIGN_ROLE", "user", userId, null,
                Map.of("role", role.getName()), httpReq);
        return after;
    }

    public void removeRole(String userId, String roleId, HttpServletRequest httpReq) {
        String tenantId = executionTenant.require();
        Principal p = principalRepository.findByIdAndTenantId(userId, tenantId)
                .orElseThrow(() -> EntityNotFoundException.forId("User", userId));

        UUID roleUuid;
        try {
            roleUuid = UUID.fromString(roleId);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Invalid role ID format: " + roleId);
        }

        Role role = roleRepository.findByIdAndTenantId(roleUuid, tenantId)
                .orElseThrow(() -> EntityNotFoundException.forId("Role", roleId));

        if (!p.getTenantId().equals(role.getTenantId())) {
            throw new IllegalArgumentException("role removal cannot cross tenant boundaries");
        }
        p.revokeRole(role);
        principalRepository.save(p);

        auditService.log(tenantId, auditService.currentActor(),
                "REMOVE_ROLE", "user", userId, Map.of("role", role.getName()), null, httpReq);
    }

    // -------------------------------------------------------
    // Teams / Domains
    // -------------------------------------------------------

    @Transactional(readOnly = true)
    public List<String> getUserTeams(String userId) {
        String tenantId = executionTenant.require();
        if (principalRepository.findByIdAndTenantId(userId, tenantId).isEmpty()) {
            throw EntityNotFoundException.forId("User", userId);
        }
        return groupRepository.findByTenantIdAndMemberId(tenantId, userId)
                .stream()
                .map(Group::getName)
                .toList();
    }

    @Transactional(readOnly = true)
    public List<String> getUserDomains(String userId) {
        String tenantId = executionTenant.require();
        if (principalRepository.findByIdAndTenantId(userId, tenantId).isEmpty()) {
            throw EntityNotFoundException.forId("User", userId);
        }
        return groupRepository.findByTenantIdAndMemberId(tenantId, userId)
                .stream()
                .map(Group::getDomainId)
                .filter(Objects::nonNull)
                .distinct()
                .toList();
    }

    // -------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------

    /**
     * Converts a {@link Principal} entity to a {@link UserResponse} DTO.
     * Must be called within an active transaction (for LAZY role loading).
     */
    public UserResponse toUserResponse(Principal p) {
        List<String> roles = p.getRoles().stream()
                .map(Role::getName)
                .sorted()
                .toList();

        Map<String, Object> attrs = parseAttributes(p.getAttributes());
        String classification = (String) attrs.getOrDefault("classification", "internal");
        Map<String, String> segments = getSegmentMap(attrs, classification);
        List<String> adminDomains = getStringList(attrs, "admin_domains");

        return new UserResponse(
                p.getId(),
                p.getUsername(),
                p.getEmail(),
                p.isActive(),
                roles,
                segments,
                classification,
                adminDomains,
                p.getCreatedAt()
        );
    }

    private Map<String, Object> parseAttributes(String json) {
        if (json == null || json.isBlank()) return new HashMap<>();
        try {
            return objectMapper.readValue(json, MAP_TYPE);
        } catch (JsonProcessingException ex) {
            log.warn("Failed to parse principal attributes JSON: {}", ex.getMessage());
            return new HashMap<>();
        }
    }

    @SuppressWarnings("unchecked")
    private List<String> getStringList(Map<String, Object> attrs, String key) {
        Object val = attrs.get(key);
        if (val instanceof List<?> list) {
            return list.stream()
                    .filter(Objects::nonNull)
                    .map(Object::toString)
                    .toList();
        }
        return Collections.emptyList();
    }

    /**
     * Reads the {@code segments} attribute as the ABAC per-segment clearance MAP
     * {@code {segment -> tier}} (the current shape). Legacy tolerance: if an un-migrated
     * principal still stores {@code segments} as a flat JSON array, each segment is mapped to
     * the principal's global {@code classification} tier so the admin console renders the same
     * per-segment ceiling the token enricher derives — no access is silently dropped and no
     * tier is invented. Insertion order is preserved for stable rendering.
     */
    private Map<String, String> getSegmentMap(Map<String, Object> attrs, String fallbackTier) {
        Object raw = attrs.get("segments");
        Map<String, String> out = new LinkedHashMap<>();
        if (raw instanceof Map<?, ?> map) {
            map.forEach((k, v) -> {
                if (k != null && v != null) out.put(k.toString(), v.toString());
            });
        } else if (raw instanceof List<?> list) {
            String tier = (fallbackTier == null || fallbackTier.isBlank()) ? "internal" : fallbackTier;
            for (Object s : list) {
                if (s != null) out.put(s.toString(), tier);
            }
        }
        return out;
    }

    /**
     * Shallow-merges {@code incoming} over the principal's existing attribute bag at the
     * top-level-key granularity. This is what makes an admin edit non-destructive: the console
     * only sends the keys it manages ({@code segments}, {@code classification}, {@code team}),
     * so identity metadata it never renders ({@code display_name}, {@code title},
     * {@code department}, {@code admin_domains}) survives the update. Any key present in
     * {@code incoming} fully replaces its stored value (so a whole {@code segments} map — with a
     * segment row removed — is replaced atomically, not deep-merged).
     */
    private String mergeAttributes(String existingJson, Map<String, Object> incoming) {
        Map<String, Object> merged = new LinkedHashMap<>(parseAttributes(existingJson));
        merged.putAll(incoming);
        return serializeAttributes(merged);
    }

    private String serializeAttributes(Map<String, Object> attributes) {
        if (attributes == null) return "{}";
        try {
            return objectMapper.writeValueAsString(attributes);
        } catch (JsonProcessingException ex) {
            log.warn("Failed to serialise attributes: {}", ex.getMessage());
            return "{}";
        }
    }
}
