package com.openwolf.iam.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.openwolf.iam.dto.AddMemberRequest;
import com.openwolf.iam.dto.CreateGroupRequest;
import com.openwolf.iam.dto.GroupResponse;
import com.openwolf.iam.dto.UserResponse;
import com.openwolf.iam.auth.ExecutionTenant;
import com.openwolf.iam.entity.Group;
import com.openwolf.iam.entity.Principal;
import com.openwolf.iam.exception.EntityNotFoundException;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.repository.GroupRepository;
import com.openwolf.iam.repository.PrincipalRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@Transactional
public class GroupService {

    private static final Logger log = LoggerFactory.getLogger(GroupService.class);
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};
    private static final TypeReference<List<String>> LIST_TYPE = new TypeReference<>() {};

    private final GroupRepository groupRepository;
    private final PrincipalRepository principalRepository;
    private final AuditService auditService;
    private final UserService userService;
    private final ObjectMapper objectMapper;
    private final ExecutionTenant executionTenant;

    public GroupService(GroupRepository groupRepository,
                        PrincipalRepository principalRepository,
                        AuditService auditService,
                        UserService userService,
                        ObjectMapper objectMapper,
                        ExecutionTenant executionTenant) {
        this.groupRepository = groupRepository;
        this.principalRepository = principalRepository;
        this.auditService = auditService;
        this.userService = userService;
        this.objectMapper = objectMapper;
        this.executionTenant = executionTenant;
    }

    // -------------------------------------------------------
    // List / Get
    // -------------------------------------------------------

    @Transactional(readOnly = true)
    public List<GroupResponse> listGroups() {
        return groupRepository.findByTenantId(executionTenant.require())
                .stream()
                .map(this::toGroupResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public List<GroupResponse> listGroupsByDomain(String domainId) {
        return groupRepository.findByTenantIdAndDomainId(executionTenant.require(), domainId)
                .stream()
                .map(this::toGroupResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public GroupResponse getGroup(UUID groupId) {
        Group g = groupRepository.findByIdAndTenantId(groupId, executionTenant.require())
                .orElseThrow(() -> EntityNotFoundException.forId("Group", groupId));
        return toGroupResponse(g);
    }

    // -------------------------------------------------------
    // Create
    // -------------------------------------------------------

    public GroupResponse createGroup(CreateGroupRequest req, HttpServletRequest httpReq) {
        String tenantId = executionTenant.require();
        if (groupRepository.findByTenantIdAndName(tenantId, req.name()).isPresent()) {
            throw new ResourceConflictException("Group already exists: " + req.name());
        }
        String metadataJson = buildMetadata(req.defaultRoles(), req.segments(), req.allowedDomains());
        Group g = new Group(tenantId, req.name(), req.domainId(), req.description(), metadataJson);
        groupRepository.save(g);
        GroupResponse response = toGroupResponse(g);
        auditService.log(tenantId, auditService.currentActor(),
                "CREATE_GROUP", "group", g.getId().toString(), null, response, httpReq);
        return response;
    }

    // -------------------------------------------------------
    // Update
    // -------------------------------------------------------

    public GroupResponse updateGroup(UUID groupId, CreateGroupRequest req, HttpServletRequest httpReq) {
        String tenantId = executionTenant.require();
        Group g = groupRepository.findByIdAndTenantId(groupId, tenantId)
                .orElseThrow(() -> EntityNotFoundException.forId("Group", groupId));

        if (g.getScimSourceId() != null) throw new ResourceConflictException("SCIM-owned group fields must be changed through SCIM");

        GroupResponse before = toGroupResponse(g);
        g.setName(req.name());
        g.setDomainId(req.domainId());
        g.setDescription(req.description());
        g.setMetadata(buildMetadata(req.defaultRoles(), req.segments(), req.allowedDomains()));
        groupRepository.save(g);

        GroupResponse after = toGroupResponse(g);
        auditService.log(tenantId, auditService.currentActor(),
                "UPDATE_GROUP", "group", groupId.toString(), before, after, httpReq);
        return after;
    }

    // -------------------------------------------------------
    // Delete
    // -------------------------------------------------------

    public void deleteGroup(UUID groupId, HttpServletRequest httpReq) {
        String tenantId = executionTenant.require();
        Group g = groupRepository.findByIdAndTenantId(groupId, tenantId)
                .orElseThrow(() -> EntityNotFoundException.forId("Group", groupId));
        if (g.getScimSourceId() != null) throw new ResourceConflictException("SCIM-owned group fields must be changed through SCIM");
        GroupResponse before = toGroupResponse(g);
        groupRepository.delete(g);
        auditService.log(tenantId, auditService.currentActor(),
                "DELETE_GROUP", "group", groupId.toString(), before, null, httpReq);
    }

    // -------------------------------------------------------
    // Members
    // -------------------------------------------------------

    public GroupResponse addMember(UUID groupId, String userId, HttpServletRequest httpReq) {
        String tenantId = executionTenant.require();
        Group g = groupRepository.findByIdAndTenantId(groupId, tenantId)
                .orElseThrow(() -> EntityNotFoundException.forId("Group", groupId));
        if (g.getScimSourceId() != null) throw new ResourceConflictException("SCIM-owned group fields must be changed through SCIM");
        requireLegacyMembershipGroup(g);
        Principal p = principalRepository.findByIdAndTenantId(userId, tenantId)
                .orElseThrow(() -> EntityNotFoundException.forId("User", userId));

        g.getMembers().add(p);
        groupRepository.save(g);

        GroupResponse after = toGroupResponse(g);
        auditService.log(tenantId, auditService.currentActor(),
                "ADD_MEMBER", "group", groupId.toString(),
                null, Map.of("userId", userId), httpReq);
        return after;
    }

    public void removeMember(UUID groupId, String userId, HttpServletRequest httpReq) {
        String tenantId = executionTenant.require();
        Group g = groupRepository.findByIdAndTenantId(groupId, tenantId)
                .orElseThrow(() -> EntityNotFoundException.forId("Group", groupId));
        if (g.getScimSourceId() != null) throw new ResourceConflictException("SCIM-owned group fields must be changed through SCIM");
        requireLegacyMembershipGroup(g);
        Principal p = principalRepository.findByIdAndTenantId(userId, tenantId)
                .orElseThrow(() -> EntityNotFoundException.forId("User", userId));

        g.getMembers().remove(p);
        groupRepository.save(g);

        auditService.log(tenantId, auditService.currentActor(),
                "REMOVE_MEMBER", "group", groupId.toString(),
                Map.of("userId", userId), null, httpReq);
    }

    @Transactional(readOnly = true)
    public List<UserResponse> listMembers(UUID groupId) {
        Group g = groupRepository.findByIdAndTenantId(groupId, executionTenant.require())
                .orElseThrow(() -> EntityNotFoundException.forId("Group", groupId));
        return membersFor(g).stream()
                .map(userService::toUserResponse)
                .toList();
    }

    // -------------------------------------------------------
    // Domain admin helpers
    // -------------------------------------------------------

    /**
     * Adds a domain to the principal's {@code admin_domains} JSON attribute.
     */
    public void addDomainAdmin(UUID groupId, String userId, HttpServletRequest httpReq) {
        String tenantId = executionTenant.require();
        // Verify group/domain exists
        Group g = groupRepository.findByIdAndTenantId(groupId, tenantId)
                .orElseThrow(() -> EntityNotFoundException.forId("Domain", groupId));

        Principal p = principalRepository.findByIdAndTenantId(userId, tenantId)
                .orElseThrow(() -> EntityNotFoundException.forId("User", userId));

        String domainId = g.getDomainId() != null ? g.getDomainId() : g.getId().toString();

        // Parse current attributes
        Map<String, Object> attrs = parseMetadata(p.getAttributes() != null ? p.getAttributes() : "{}");
        @SuppressWarnings("unchecked")
        List<String> adminDomains = (List<String>) attrs.computeIfAbsent("admin_domains",
                k -> new java.util.ArrayList<>());
        if (!adminDomains.contains(domainId)) {
            adminDomains.add(domainId);
        }
        p.setAttributes(serializeMap(attrs));
        principalRepository.save(p);

        auditService.log(tenantId, auditService.currentActor(),
                "ADD_DOMAIN_ADMIN", "domain", groupId.toString(),
                null, Map.of("userId", userId, "domain", domainId), httpReq);
    }

    /**
     * Removes a domain from the principal's {@code admin_domains} JSON attribute.
     */
    public void removeDomainAdmin(UUID groupId, String userId, HttpServletRequest httpReq) {
        String tenantId = executionTenant.require();
        Group g = groupRepository.findByIdAndTenantId(groupId, tenantId)
                .orElseThrow(() -> EntityNotFoundException.forId("Domain", groupId));
        Principal p = principalRepository.findByIdAndTenantId(userId, tenantId)
                .orElseThrow(() -> EntityNotFoundException.forId("User", userId));

        String domainId = g.getDomainId() != null ? g.getDomainId() : g.getId().toString();

        Map<String, Object> attrs = parseMetadata(p.getAttributes() != null ? p.getAttributes() : "{}");
        @SuppressWarnings("unchecked")
        List<String> adminDomains = (List<String>) attrs.getOrDefault("admin_domains",
                new java.util.ArrayList<>());
        adminDomains.remove(domainId);
        attrs.put("admin_domains", adminDomains);
        p.setAttributes(serializeMap(attrs));
        principalRepository.save(p);

        auditService.log(tenantId, auditService.currentActor(),
                "REMOVE_DOMAIN_ADMIN", "domain", groupId.toString(),
                Map.of("userId", userId, "domain", domainId), null, httpReq);
    }

    /**
     * Lists all principals who are admins of the given domain.
     */
    @Transactional(readOnly = true)
    public List<UserResponse> listDomainAdmins(UUID groupId) {
        String tenantId = executionTenant.require();
        Group g = groupRepository.findByIdAndTenantId(groupId, tenantId)
                .orElseThrow(() -> EntityNotFoundException.forId("Domain", groupId));
        return domainAssignmentsFor(g)
                .stream()
                .map(userService::toUserResponse)
                .toList();
    }

    // -------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------

    public GroupResponse toGroupResponse(Group g) {
        Map<String, Object> meta = parseMetadata(g.getMetadata());
        List<String> defaultRoles = getStringList(meta, "defaultRoles");
        List<String> segments = getStringList(meta, "segments");
        List<String> allowedDomains = getStringList(meta, "allowedDomains");
        // Domain-backed teams are a read projection of the same principal assignment
        // that SubjectContextService uses for live domain scope.  group_members is a
        // legacy organisational grouping and must not make those assignments invisible.
        int memberCount = isDomainBacked(g)
                ? domainAssignmentsFor(g).size()
                : groupRepository.countMembersById(g.getId());

        return new GroupResponse(
                g.getId(),
                g.getName(),
                g.getDomainId(),
                g.getDescription(),
                memberCount,
                g.getTenantId(),
                defaultRoles,
                segments,
                allowedDomains
        );
    }

    private List<Principal> membersFor(Group group) {
        return isDomainBacked(group) ? domainAssignmentsFor(group) : List.copyOf(group.getMembers());
    }

    private List<Principal> domainAssignmentsFor(Group group) {
        String domainId = group.getDomainId();
        return principalRepository.findByTenantIdAndCanonicalDomain(group.getTenantId(), domainId);
    }

    private static boolean isDomainBacked(Group group) {
        return group.getDomainId() != null && !group.getDomainId().isBlank();
    }

    private static void requireLegacyMembershipGroup(Group group) {
        if (isDomainBacked(group)) {
            throw new ResourceConflictException("Domain assignments must be managed through domain administration");
        }
    }

    private String buildMetadata(List<String> defaultRoles, List<String> segments,
                                  List<String> allowedDomains) {
        Map<String, Object> meta = new HashMap<>();
        meta.put("defaultRoles", defaultRoles != null ? defaultRoles : Collections.emptyList());
        meta.put("segments", segments != null ? segments : Collections.emptyList());
        meta.put("allowedDomains", allowedDomains != null ? allowedDomains : Collections.emptyList());
        return serializeMap(meta);
    }

    private Map<String, Object> parseMetadata(String json) {
        if (json == null || json.isBlank()) return new HashMap<>();
        try {
            return objectMapper.readValue(json, MAP_TYPE);
        } catch (JsonProcessingException ex) {
            log.warn("Failed to parse group metadata JSON: {}", ex.getMessage());
            return new HashMap<>();
        }
    }

    @SuppressWarnings("unchecked")
    private List<String> getStringList(Map<String, Object> map, String key) {
        Object val = map.get(key);
        if (val instanceof List<?> list) {
            return list.stream()
                    .filter(o -> o != null)
                    .map(Object::toString)
                    .toList();
        }
        return Collections.emptyList();
    }

    private String serializeMap(Map<String, Object> map) {
        try {
            return objectMapper.writeValueAsString(map);
        } catch (JsonProcessingException ex) {
            log.warn("Failed to serialise map: {}", ex.getMessage());
            return "{}";
        }
    }
}
