package com.openwolf.iam.controller;

import com.openwolf.iam.dto.AddMemberRequest;
import com.openwolf.iam.dto.CreateGroupRequest;
import com.openwolf.iam.dto.GroupResponse;
import com.openwolf.iam.dto.UserResponse;
import com.openwolf.iam.service.GroupService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;
import java.util.UUID;

/**
 * Manages domains — business capability areas that group principals and resources.
 * Domains are backed by the same {@code groups} table as teams but have
 * additional semantics: domain_id is required, and domain admins are tracked
 * in each principal's {@code admin_domains} attribute.
 */
@RestController
@RequestMapping("/domains")
public class DomainController {

    private final GroupService groupService;

    public DomainController(GroupService groupService) {
        this.groupService = groupService;
    }

    @GetMapping
    public ResponseEntity<List<GroupResponse>> listDomains() {
        // Returns all groups — domains are distinguished by having a domainId
        return ResponseEntity.ok(groupService.listGroups());
    }

    @PostMapping
    public ResponseEntity<GroupResponse> createDomain(
            @Valid @RequestBody CreateGroupRequest req,
            HttpServletRequest httpReq) {
        // Domains MUST have a domainId
        if (req.domainId() == null || req.domainId().isBlank()) {
            throw new IllegalArgumentException("domainId is required when creating a domain");
        }
        GroupResponse domain = groupService.createGroup(req, httpReq);
        URI location = ServletUriComponentsBuilder.fromCurrentRequest()
                .path("/{id}")
                .buildAndExpand(domain.id())
                .toUri();
        return ResponseEntity.created(location).body(domain);
    }

    @GetMapping("/{domainId}")
    public ResponseEntity<GroupResponse> getDomain(@PathVariable UUID domainId) {
        return ResponseEntity.ok(groupService.getGroup(domainId));
    }

    // -------------------------------------------------------
    // Domain members
    // -------------------------------------------------------

    @PostMapping("/{domainId}/members")
    public ResponseEntity<GroupResponse> addMember(
            @PathVariable UUID domainId,
            @Valid @RequestBody AddMemberRequest req,
            HttpServletRequest httpReq) {
        GroupResponse domain = groupService.addMember(domainId, req.userId(), httpReq);
        return ResponseEntity.status(201).body(domain);
    }

    @DeleteMapping("/{domainId}/members/{userId}")
    public ResponseEntity<Void> removeMember(
            @PathVariable UUID domainId,
            @PathVariable String userId,
            HttpServletRequest httpReq) {
        groupService.removeMember(domainId, userId, httpReq);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/{domainId}/members")
    public ResponseEntity<List<UserResponse>> listMembers(@PathVariable UUID domainId) {
        return ResponseEntity.ok(groupService.listMembers(domainId));
    }

    // -------------------------------------------------------
    // Domain admins
    // -------------------------------------------------------

    /**
     * {@code POST /domains/{id}/admins} — makes a user a domain admin.
     * Adds the domain to the user's {@code admin_domains} attribute array.
     */
    @PostMapping("/{domainId}/admins")
    public ResponseEntity<Void> addAdmin(
            @PathVariable UUID domainId,
            @Valid @RequestBody AddMemberRequest req,
            HttpServletRequest httpReq) {
        groupService.addDomainAdmin(domainId, req.userId(), httpReq);
        return ResponseEntity.status(201).build();
    }

    @DeleteMapping("/{domainId}/admins/{userId}")
    public ResponseEntity<Void> removeAdmin(
            @PathVariable UUID domainId,
            @PathVariable String userId,
            HttpServletRequest httpReq) {
        groupService.removeDomainAdmin(domainId, userId, httpReq);
        return ResponseEntity.noContent().build();
    }

    /**
     * {@code GET /domains/{id}/admins} — lists principals who are admins of this domain.
     * Finds principals whose {@code admin_domains} attribute contains this domain's ID.
     */
    @GetMapping("/{domainId}/admins")
    public ResponseEntity<List<UserResponse>> listAdmins(@PathVariable UUID domainId) {
        return ResponseEntity.ok(groupService.listDomainAdmins(domainId));
    }
}
