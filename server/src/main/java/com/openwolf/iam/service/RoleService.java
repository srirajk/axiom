package com.openwolf.iam.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.openwolf.iam.dto.CreateRoleRequest;
import com.openwolf.iam.auth.ExecutionTenant;
import com.openwolf.iam.dto.RoleResponse;
import com.openwolf.iam.entity.Role;
import com.openwolf.iam.exception.EntityNotFoundException;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.repository.RoleRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.List;
import java.util.UUID;

@Service
@Transactional
public class RoleService {

    private static final Logger log = LoggerFactory.getLogger(RoleService.class);
    private static final TypeReference<List<String>> LIST_TYPE = new TypeReference<>() {};

    private final RoleRepository roleRepository;
    private final AuditService auditService;
    private final ObjectMapper objectMapper;
    private final ExecutionTenant executionTenant;

    public RoleService(RoleRepository roleRepository,
                       AuditService auditService,
                       ObjectMapper objectMapper,
                       ExecutionTenant executionTenant) {
        this.roleRepository = roleRepository;
        this.auditService = auditService;
        this.objectMapper = objectMapper;
        this.executionTenant = executionTenant;
    }

    @Transactional(readOnly = true)
    public List<RoleResponse> listRoles() {
        return roleRepository.findByTenantId(executionTenant.require())
                .stream()
                .map(this::toRoleResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public RoleResponse getRole(UUID roleId) {
        Role role = roleRepository.findByIdAndTenantId(roleId, executionTenant.require())
                .orElseThrow(() -> EntityNotFoundException.forId("Role", roleId));
        return toRoleResponse(role);
    }

    public RoleResponse createRole(CreateRoleRequest req, HttpServletRequest httpReq) {
        String tenantId = executionTenant.require();
        if (roleRepository.findByNameAndTenantId(req.name(), tenantId).isPresent()) {
            throw new ResourceConflictException("Role already exists: " + req.name());
        }
        String permissionsJson = serializeList(req.permissions());
        Role role = new Role(tenantId, req.name(), permissionsJson, req.description());
        roleRepository.save(role);
        auditService.log(tenantId, auditService.currentActor(),
                "CREATE_ROLE", "role", role.getId().toString(), null, toRoleResponse(role), httpReq);
        return toRoleResponse(role);
    }

    public RoleResponse updateRole(UUID roleId, CreateRoleRequest req, HttpServletRequest httpReq) {
        String tenantId = executionTenant.require();
        Role role = roleRepository.findByIdAndTenantId(roleId, tenantId)
                .orElseThrow(() -> EntityNotFoundException.forId("Role", roleId));

        RoleResponse before = toRoleResponse(role);
        role.setName(req.name());
        role.setDescription(req.description());
        role.setPermissions(serializeList(req.permissions()));
        roleRepository.save(role);

        RoleResponse after = toRoleResponse(role);
        auditService.log(tenantId, auditService.currentActor(),
                "UPDATE_ROLE", "role", roleId.toString(), before, after, httpReq);
        return after;
    }

    public void deleteRole(UUID roleId, HttpServletRequest httpReq) {
        String tenantId = executionTenant.require();
        Role role = roleRepository.findByIdAndTenantId(roleId, tenantId)
                .orElseThrow(() -> EntityNotFoundException.forId("Role", roleId));
        RoleResponse before = toRoleResponse(role);
        roleRepository.delete(role);
        auditService.log(tenantId, auditService.currentActor(),
                "DELETE_ROLE", "role", roleId.toString(), before, null, httpReq);
        log.info("Deleted role id={} name={}", roleId, role.getName());
    }

    public RoleResponse toRoleResponse(Role role) {
        return new RoleResponse(
                role.getId(),
                role.getName(),
                role.getDescription(),
                parseList(role.getPermissions()),
                role.getTenantId()
        );
    }

    private List<String> parseList(String json) {
        if (json == null || json.isBlank()) return Collections.emptyList();
        try {
            return objectMapper.readValue(json, LIST_TYPE);
        } catch (JsonProcessingException ex) {
            log.warn("Failed to parse permissions JSON: {}", ex.getMessage());
            return Collections.emptyList();
        }
    }

    private String serializeList(List<String> list) {
        if (list == null) return "[]";
        try {
            return objectMapper.writeValueAsString(list);
        } catch (JsonProcessingException ex) {
            log.warn("Failed to serialise permissions list: {}", ex.getMessage());
            return "[]";
        }
    }
}
