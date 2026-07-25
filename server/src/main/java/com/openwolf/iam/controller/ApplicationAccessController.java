package com.openwolf.iam.controller;

import com.openwolf.iam.dto.ApplicationMembershipResponse;
import com.openwolf.iam.dto.ApplicationRoleResponse;
import com.openwolf.iam.dto.AssignApplicationRoleRequest;
import com.openwolf.iam.dto.CreateApplicationMembershipRequest;
import com.openwolf.iam.dto.CreateApplicationRoleRequest;
import com.openwolf.iam.dto.UpdateApplicationMembershipAttributesRequest;
import com.openwolf.iam.service.ApplicationAccessService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/admin/tenants/{tenantId}/applications/{applicationId}/access")
@PreAuthorize("hasAnyRole('platform_admin','tenant_admin')")
public class ApplicationAccessController {
    private final ApplicationAccessService service;

    public ApplicationAccessController(ApplicationAccessService service) { this.service = service; }

    @GetMapping("/roles")
    public ResponseEntity<List<ApplicationRoleResponse>> roles(@PathVariable String tenantId,
                                                               @PathVariable UUID applicationId) {
        return ResponseEntity.ok(service.listRoles(tenantId, applicationId));
    }

    @PostMapping("/roles")
    public ResponseEntity<ApplicationRoleResponse> createRole(@PathVariable String tenantId,
                                                              @PathVariable UUID applicationId,
                                                              @Valid @RequestBody CreateApplicationRoleRequest request,
                                                              HttpServletRequest httpRequest) {
        return ResponseEntity.status(201).body(service.createRole(tenantId, applicationId, request, httpRequest));
    }

    @PutMapping("/roles/{roleId}")
    public ResponseEntity<ApplicationRoleResponse> updateRole(@PathVariable String tenantId,
                                                              @PathVariable UUID applicationId,
                                                              @PathVariable UUID roleId,
                                                              @Valid @RequestBody CreateApplicationRoleRequest request,
                                                              HttpServletRequest httpRequest) {
        return ResponseEntity.ok(
                service.updateRole(tenantId, applicationId, roleId, request, httpRequest));
    }

    @GetMapping("/memberships")
    public ResponseEntity<List<ApplicationMembershipResponse>> memberships(@PathVariable String tenantId,
                                                                            @PathVariable UUID applicationId) {
        return ResponseEntity.ok(service.listMemberships(tenantId, applicationId));
    }

    @PostMapping("/memberships")
    public ResponseEntity<ApplicationMembershipResponse> createMembership(@PathVariable String tenantId,
            @PathVariable UUID applicationId, @Valid @RequestBody CreateApplicationMembershipRequest request,
            HttpServletRequest httpRequest) {
        return ResponseEntity.status(201).body(service.createMembership(tenantId, applicationId, request, httpRequest));
    }

    @PostMapping("/memberships/{membershipId}/roles")
    public ResponseEntity<ApplicationMembershipResponse> assignRole(@PathVariable String tenantId,
            @PathVariable UUID applicationId, @PathVariable UUID membershipId,
            @Valid @RequestBody AssignApplicationRoleRequest request, HttpServletRequest httpRequest) {
        return ResponseEntity.ok(service.assignRole(tenantId, applicationId, membershipId, request, httpRequest));
    }

    @DeleteMapping("/memberships/{membershipId}/roles/{roleId}")
    public ResponseEntity<ApplicationMembershipResponse> revokeRole(@PathVariable String tenantId,
            @PathVariable UUID applicationId, @PathVariable UUID membershipId, @PathVariable UUID roleId,
            HttpServletRequest httpRequest) {
        return ResponseEntity.ok(service.revokeRole(tenantId, applicationId, membershipId, roleId, httpRequest));
    }

    @PatchMapping("/memberships/{membershipId}/attributes")
    public ResponseEntity<ApplicationMembershipResponse> replaceAttributes(@PathVariable String tenantId,
            @PathVariable UUID applicationId, @PathVariable UUID membershipId,
            @Valid @RequestBody UpdateApplicationMembershipAttributesRequest request,
            HttpServletRequest httpRequest) {
        return ResponseEntity.ok(service.replaceAttributes(tenantId, applicationId, membershipId, request, httpRequest));
    }

    @DeleteMapping("/memberships/{membershipId}")
    public ResponseEntity<Void> disableMembership(@PathVariable String tenantId, @PathVariable UUID applicationId,
                                                   @PathVariable UUID membershipId, HttpServletRequest httpRequest) {
        service.disableMembership(tenantId, applicationId, membershipId, httpRequest);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/memberships/{membershipId}/enable")
    public ResponseEntity<ApplicationMembershipResponse> enableMembership(@PathVariable String tenantId,
            @PathVariable UUID applicationId, @PathVariable UUID membershipId, HttpServletRequest httpRequest) {
        return ResponseEntity.ok(service.enableMembership(tenantId, applicationId, membershipId, httpRequest));
    }
}
