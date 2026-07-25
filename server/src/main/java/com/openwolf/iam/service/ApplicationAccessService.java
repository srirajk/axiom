package com.openwolf.iam.service;

import com.openwolf.iam.auth.ExecutionTenant;
import com.openwolf.iam.dto.ApplicationMembershipResponse;
import com.openwolf.iam.dto.ApplicationRoleResponse;
import com.openwolf.iam.dto.AssignApplicationRoleRequest;
import com.openwolf.iam.dto.CreateApplicationMembershipRequest;
import com.openwolf.iam.dto.CreateApplicationRoleRequest;
import com.openwolf.iam.dto.UpdateApplicationMembershipAttributesRequest;
import com.openwolf.iam.entity.Principal;
import com.openwolf.iam.entity.TenantApplication;
import com.openwolf.iam.entity.TenantApplicationClient;
import com.openwolf.iam.entity.TenantApplicationMembership;
import com.openwolf.iam.entity.TenantApplicationRole;
import com.openwolf.iam.entity.TenantApplicationRoleAssignment;
import com.openwolf.iam.exception.EntityNotFoundException;
import com.openwolf.iam.exception.ResourceConflictException;
import com.openwolf.iam.repository.PrincipalRepository;
import com.openwolf.iam.repository.TenantApplicationClientRepository;
import com.openwolf.iam.repository.TenantApplicationMembershipRepository;
import com.openwolf.iam.repository.TenantApplicationRepository;
import com.openwolf.iam.repository.TenantApplicationRoleAssignmentRepository;
import com.openwolf.iam.repository.TenantApplicationRoleRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;

/** Durable application-scoped access. Tenant-wide Axiom administration roles never leak here. */
@Service
@Transactional
public class ApplicationAccessService {
    private final TenantApplicationRepository applications;
    private final TenantApplicationClientRepository clients;
    private final TenantApplicationMembershipRepository memberships;
    private final TenantApplicationRoleRepository roles;
    private final TenantApplicationRoleAssignmentRepository assignments;
    private final PrincipalRepository principals;
    private final ExecutionTenant executionTenant;
    private final AuditService audit;

    public ApplicationAccessService(
            TenantApplicationRepository applications,
            TenantApplicationClientRepository clients,
            TenantApplicationMembershipRepository memberships,
            TenantApplicationRoleRepository roles,
            TenantApplicationRoleAssignmentRepository assignments,
            PrincipalRepository principals,
            ExecutionTenant executionTenant,
            AuditService audit) {
        this.applications = applications;
        this.clients = clients;
        this.memberships = memberships;
        this.roles = roles;
        this.assignments = assignments;
        this.principals = principals;
        this.executionTenant = executionTenant;
        this.audit = audit;
    }

    public ApplicationRoleResponse createRole(String tenantId, UUID applicationId,
                                               CreateApplicationRoleRequest request,
                                               HttpServletRequest httpRequest) {
        TenantApplication application = requireActiveApplication(tenantId, applicationId);
        if (roles.existsByApplicationIdAndRoleKey(applicationId, request.roleKey())) {
            throw new ResourceConflictException("Application role already exists");
        }
        List<String> permissions = request.permissions() == null
                ? List.of() : request.permissions().stream().distinct().sorted().toList();
        Map<String, String> permissionEffects = canonicalEffects(permissions, request.permissionEffects());
        TenantApplicationRole role = roles.save(new TenantApplicationRole(application.getId(), request.roleKey(),
                request.displayName(), request.description(), permissions, permissionEffects));
        ApplicationRoleResponse response = roleResponse(role);
        audit.logRequired(tenantId, audit.currentActor(), "CREATE_APPLICATION_ROLE", "application_role",
                role.getId().toString(), null, response, correlation(httpRequest));
        return response;
    }

    public ApplicationRoleResponse updateRole(String tenantId, UUID applicationId, UUID roleId,
                                               CreateApplicationRoleRequest request,
                                               HttpServletRequest httpRequest) {
        requireActiveApplication(tenantId, applicationId);
        TenantApplicationRole role = roles.findByIdAndApplicationId(roleId, applicationId)
                .orElseThrow(() -> EntityNotFoundException.forId("Application role", roleId));
        if (!role.getRoleKey().equals(request.roleKey())) {
            throw new ResourceConflictException("Application role key is immutable");
        }
        List<String> permissions = request.permissions() == null
                ? List.of() : request.permissions().stream().distinct().sorted().toList();
        Map<String, String> permissionEffects = canonicalEffects(permissions, request.permissionEffects());
        role.update(request.displayName(), request.description(), permissions, permissionEffects);
        ApplicationRoleResponse response = roleResponse(roles.save(role));
        audit.logRequired(tenantId, audit.currentActor(), "UPDATE_APPLICATION_ROLE", "application_role",
                role.getId().toString(), null, response, correlation(httpRequest));
        return response;
    }

    @Transactional(readOnly = true)
    public List<ApplicationRoleResponse> listRoles(String tenantId, UUID applicationId) {
        requireApplication(tenantId, applicationId);
        return roles.findByApplicationIdOrderByRoleKey(applicationId).stream().map(this::roleResponse).toList();
    }

    public ApplicationMembershipResponse createMembership(String tenantId, UUID applicationId,
                                                           CreateApplicationMembershipRequest request,
                                                           HttpServletRequest httpRequest) {
        TenantApplication application = requireActiveApplication(tenantId, applicationId);
        Principal principal = principals.findByIdAndTenantId(request.principalId(), tenantId)
                .filter(Principal::isActive)
                .orElseThrow(() -> EntityNotFoundException.forId("Principal", request.principalId()));
        TenantApplicationMembership existing = memberships
                .findByApplicationIdAndPrincipalId(applicationId, principal.getId()).orElse(null);
        if (existing != null && existing.getStatus() == TenantApplicationMembership.Status.ACTIVE) {
            return membershipResponse(existing);
        }
        if (existing != null) throw new ResourceConflictException("Disabled membership requires a new reviewed grant");
        TenantApplicationMembership membership = memberships.save(new TenantApplicationMembership(
                application.getId(), principal.getId(), request.assignmentSource(), audit.currentActor()));
        ApplicationMembershipResponse response = membershipResponse(membership);
        audit.logRequired(tenantId, audit.currentActor(), "CREATE_APPLICATION_MEMBERSHIP", "application_membership",
                membership.getId().toString(), null, response, correlation(httpRequest));
        return response;
    }

    @Transactional(readOnly = true)
    public List<ApplicationMembershipResponse> listMemberships(String tenantId, UUID applicationId) {
        requireActiveApplication(tenantId, applicationId);
        return memberships.findByApplicationIdOrderByPrincipalId(applicationId).stream()
                .map(this::membershipResponse).toList();
    }

    public ApplicationMembershipResponse assignRole(String tenantId, UUID applicationId, UUID membershipId,
                                                     AssignApplicationRoleRequest request,
                                                     HttpServletRequest httpRequest) {
        requireActiveApplication(tenantId, applicationId);
        TenantApplicationMembership membership = requireMembership(applicationId, membershipId);
        if (membership.getStatus() != TenantApplicationMembership.Status.ACTIVE) {
            throw new ResourceConflictException("Application membership is disabled");
        }
        TenantApplicationRole role = roles.findByIdAndApplicationId(request.roleId(), applicationId)
                .orElseThrow(() -> EntityNotFoundException.forId("Application role", request.roleId()));
        TenantApplicationRoleAssignment existing = assignments
                .findByMembershipIdAndApplicationRoleIdAndRevokedAtIsNull(membershipId, role.getId()).orElse(null);
        if (existing != null) return membershipResponse(membership);
        assignments.save(new TenantApplicationRoleAssignment(membershipId, role.getId(),
                request.assignmentSource(), audit.currentActor()));
        membership.touch();
        memberships.save(membership);
        ApplicationMembershipResponse response = membershipResponse(membership);
        audit.logRequired(tenantId, audit.currentActor(), "ASSIGN_APPLICATION_ROLE", "application_membership",
                membershipId.toString(), null, response, correlation(httpRequest));
        return response;
    }

    public ApplicationMembershipResponse replaceAttributes(String tenantId, UUID applicationId, UUID membershipId,
                                                            UpdateApplicationMembershipAttributesRequest request,
                                                            HttpServletRequest httpRequest) {
        requireActiveApplication(tenantId, applicationId);
        TenantApplicationMembership membership = requireMembership(applicationId, membershipId);
        if (membership.getStatus() != TenantApplicationMembership.Status.ACTIVE) {
            throw new ResourceConflictException("Application membership is disabled");
        }
        ApplicationMembershipResponse before = membershipResponse(membership);
        membership.replaceAttributes(new java.util.TreeMap<>(request.attributes()));
        memberships.save(membership);
        ApplicationMembershipResponse response = membershipResponse(membership);
        audit.logRequired(tenantId, audit.currentActor(), "REPLACE_APPLICATION_ATTRIBUTES", "application_membership",
                membershipId.toString(), before, response, correlation(httpRequest));
        return response;
    }

    public void disableMembership(String tenantId, UUID applicationId, UUID membershipId,
                                  HttpServletRequest httpRequest) {
        requireActiveApplication(tenantId, applicationId);
        TenantApplicationMembership membership = requireMembership(applicationId, membershipId);
        if (membership.getStatus() == TenantApplicationMembership.Status.DISABLED) return;
        ApplicationMembershipResponse before = membershipResponse(membership);
        membership.disable();
        memberships.save(membership);
        audit.logRequired(tenantId, audit.currentActor(), "DISABLE_APPLICATION_MEMBERSHIP", "application_membership",
                membershipId.toString(), before, membershipResponse(membership), correlation(httpRequest));
    }

    public ApplicationMembershipResponse enableMembership(String tenantId, UUID applicationId, UUID membershipId,
                                                           HttpServletRequest httpRequest) {
        requireActiveApplication(tenantId, applicationId);
        TenantApplicationMembership membership = requireMembership(applicationId, membershipId);
        if (membership.getStatus() == TenantApplicationMembership.Status.ACTIVE) return membershipResponse(membership);
        ApplicationMembershipResponse before = membershipResponse(membership);
        membership.enable();
        memberships.save(membership);
        ApplicationMembershipResponse response = membershipResponse(membership);
        audit.logRequired(tenantId, audit.currentActor(), "ENABLE_APPLICATION_MEMBERSHIP", "application_membership",
                membershipId.toString(), before, response, correlation(httpRequest));
        return response;
    }

    public ApplicationMembershipResponse revokeRole(String tenantId, UUID applicationId, UUID membershipId, UUID roleId,
                                                     HttpServletRequest httpRequest) {
        requireActiveApplication(tenantId, applicationId);
        TenantApplicationMembership membership = requireMembership(applicationId, membershipId);
        TenantApplicationRole role = roles.findByIdAndApplicationId(roleId, applicationId)
                .orElseThrow(() -> EntityNotFoundException.forId("Application role", roleId));
        TenantApplicationRoleAssignment assignment = assignments
                .findByMembershipIdAndApplicationRoleIdAndRevokedAtIsNull(membershipId, role.getId())
                .orElseThrow(() -> EntityNotFoundException.forId("Application role assignment", roleId));
        ApplicationMembershipResponse before = membershipResponse(membership);
        assignment.revoke();
        assignments.save(assignment);
        membership.touch();
        memberships.save(membership);
        ApplicationMembershipResponse response = membershipResponse(membership);
        audit.logRequired(tenantId, audit.currentActor(), "REVOKE_APPLICATION_ROLE", "application_membership",
                membershipId.toString(), before, response, correlation(httpRequest));
        return response;
    }

    /** Token-time claims for one exact public application client and active member. */
    @Transactional(readOnly = true)
    public Map<String, Object> tokenClaims(String clientId, String principalId) {
        TenantApplicationClient client = clients.findByClientId(clientId)
                .filter(value -> value.getStatus() == TenantApplicationClient.Status.ACTIVE)
                .filter(value -> value.getClientType() == TenantApplicationClient.Type.PUBLIC_BROWSER)
                .orElseThrow(() -> new IllegalStateException("public application client is not active"));
        TenantApplication application = applications.findById(client.getApplicationId())
                .filter(value -> value.getStatus() == TenantApplication.Status.ACTIVE)
                .orElseThrow(() -> new IllegalStateException("application is not active"));
        Principal principal = principals.findByIdAndTenantId(principalId, application.getTenantId())
                .filter(Principal::isActive)
                .orElseThrow(() -> new IllegalStateException("application principal is not active"));
        TenantApplicationMembership membership = memberships
                .findByApplicationIdAndPrincipalId(application.getId(), principal.getId())
                .filter(value -> value.getStatus() == TenantApplicationMembership.Status.ACTIVE)
                .orElseThrow(() -> new IllegalStateException("principal is not a member of this application"));

        List<TenantApplicationRole> grantedRoles = activeRoles(membership);
        TreeSet<String> permissions = new TreeSet<>();
        grantedRoles.stream().map(TenantApplicationRole::getPermissions).forEach(permissions::addAll);
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("tenant_id", application.getTenantId());
        claims.put("application_id", application.getApplicationKey());
        claims.put("roles", grantedRoles.stream().map(TenantApplicationRole::getRoleKey).sorted().toList());
        claims.put("permissions", new ArrayList<>(permissions));
        claims.put("attributes", membership.getAttributes());
        claims.put("entitlement_revision", membership.getEntitlementRevision());
        return claims;
    }

    /**
     * Live, application-bound authority for a service decision. This intentionally does not expose
     * tenant-wide Axiom administration roles: only the active membership and its assigned
     * application roles participate.
     */
    @Transactional(readOnly = true)
    public Optional<DecisionAuthority> decisionAuthority(String tenantId, UUID applicationId, String principalId) {
        TenantApplication application = applications.findByIdAndTenantId(applicationId, tenantId)
                .filter(value -> value.getStatus() == TenantApplication.Status.ACTIVE).orElse(null);
        if (application == null) return Optional.empty();
        Principal principal = principals.findByIdAndTenantId(principalId, tenantId)
                .filter(Principal::isActive).orElse(null);
        if (principal == null) return Optional.empty();
        TenantApplicationMembership membership = memberships.findByApplicationIdAndPrincipalId(applicationId, principalId)
                .filter(value -> value.getStatus() == TenantApplicationMembership.Status.ACTIVE).orElse(null);
        if (membership == null) return Optional.empty();
        List<TenantApplicationRole> active = activeRoles(membership);
        Map<String, String> permissionEffects = new TreeMap<>();
        active.forEach(role -> role.getPermissionEffects().forEach((permission, effect) ->
                permissionEffects.merge(permission, effect, ApplicationAccessService::mostPermissiveEffect)));
        return Optional.of(new DecisionAuthority(application.getApplicationKey(), membership.getEntitlementRevision(),
                active.stream().map(TenantApplicationRole::getRoleKey).collect(java.util.stream.Collectors.toCollection(TreeSet::new)),
                Map.copyOf(permissionEffects), membership.getAttributes(), policyRevision(applicationId)));
    }

    private TenantApplication requireApplication(String tenantId, UUID applicationId) {
        if (!tenantId.equals(executionTenant.require())) {
            throw EntityNotFoundException.forId("Application", applicationId);
        }
        return applications.findByIdAndTenantId(applicationId, tenantId)
                .orElseThrow(() -> EntityNotFoundException.forId("Application", applicationId));
    }

    private TenantApplication requireActiveApplication(String tenantId, UUID applicationId) {
        TenantApplication application = requireApplication(tenantId, applicationId);
        if (application.getStatus() != TenantApplication.Status.ACTIVE) {
            throw new ResourceConflictException("Application is disabled");
        }
        return application;
    }

    private TenantApplicationMembership requireMembership(UUID applicationId, UUID membershipId) {
        return memberships.findByIdAndApplicationId(membershipId, applicationId)
                .orElseThrow(() -> EntityNotFoundException.forId("Application membership", membershipId));
    }

    private ApplicationRoleResponse roleResponse(TenantApplicationRole role) {
        return new ApplicationRoleResponse(role.getId(), role.getRoleKey(), role.getDisplayName(),
                role.getDescription(), role.getPermissions(), role.getPermissionEffects(), role.getCreatedAt(), role.getUpdatedAt());
    }

    private ApplicationMembershipResponse membershipResponse(TenantApplicationMembership membership) {
        List<String> roleKeys = activeRoles(membership).stream()
                .map(TenantApplicationRole::getRoleKey).sorted().toList();
        return new ApplicationMembershipResponse(membership.getId(), membership.getPrincipalId(), membership.getStatus(),
                membership.getAttributes(), roleKeys, membership.getAssignmentSource(), membership.getAssignedBy(),
                membership.getEntitlementRevision(), membership.getCreatedAt(), membership.getUpdatedAt());
    }

    private List<TenantApplicationRole> activeRoles(TenantApplicationMembership membership) {
        List<TenantApplicationRole> active = new ArrayList<>();
        for (TenantApplicationRoleAssignment assignment : assignments.findByMembershipIdAndRevokedAtIsNull(membership.getId())) {
            TenantApplicationRole role = roles.findById(assignment.getApplicationRoleId())
                    .orElseThrow(() -> new IllegalStateException("active application role assignment is missing its role"));
            if (!membership.getApplicationId().equals(role.getApplicationId())) {
                throw new IllegalStateException("active application role assignment crosses application scope");
            }
            active.add(role);
        }
        return active;
    }

    private String policyRevision(UUID applicationId) {
        StringBuilder canonical = new StringBuilder();
        roles.findByApplicationIdOrderByRoleKey(applicationId).forEach(role -> {
            canonical.append(role.getRoleKey()).append('\u0000');
            role.getPermissionEffects().entrySet().stream().sorted(Map.Entry.comparingByKey())
                    .forEach(entry -> canonical.append(entry.getKey()).append('=').append(entry.getValue()).append('\u0000'));
            canonical.append('\n');
        });
        try {
            return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(canonical.toString().getBytes(StandardCharsets.UTF_8)));
        } catch (Exception exception) {
            throw new IllegalStateException("application access policy revision unavailable", exception);
        }
    }

    private static Map<String, String> canonicalEffects(List<String> permissions, Map<String, String> requested) {
        Map<String, String> effects = new TreeMap<>();
        if (requested == null || requested.isEmpty()) {
            permissions.forEach(permission -> effects.put(permission, "allow"));
            return Map.copyOf(effects);
        }
        if (!new TreeSet<>(permissions).equals(new TreeSet<>(requested.keySet()))) {
            throw new ResourceConflictException("permission effects must define every registered permission exactly once");
        }
        requested.forEach((permission, effect) -> {
            if (!Set.of("allow", "read", "scoped", "cosign").contains(effect)) {
                throw new ResourceConflictException("unsupported application permission effect");
            }
            effects.put(permission, effect);
        });
        return Map.copyOf(effects);
    }

    /** Frozen application-access v1 precedence: a stronger grant must not be downgraded by another role. */
    static String mostPermissiveEffect(String left, String right) {
        List<String> order = List.of("read", "cosign", "scoped", "allow");
        if (!order.contains(left) || !order.contains(right)) {
            throw new IllegalStateException("persisted application permission effect is invalid");
        }
        return order.indexOf(left) >= order.indexOf(right) ? left : right;
    }

    public record DecisionAuthority(String applicationKey, long entitlementRevision, Set<String> roleKeys,
                                    Map<String, String> permissionEffects,
                                    Map<String, Object> attributes, String policyRevision) {
        public DecisionAuthority {
            roleKeys = Set.copyOf(roleKeys);
            permissionEffects = Map.copyOf(permissionEffects);
            attributes = Map.copyOf(attributes);
        }
    }

    private static String correlation(HttpServletRequest request) {
        return request == null ? null : request.getHeader("X-Correlation-ID");
    }
}
