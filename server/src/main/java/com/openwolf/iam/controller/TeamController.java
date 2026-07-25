package com.openwolf.iam.controller;

import com.openwolf.iam.dto.AddMemberRequest;
import com.openwolf.iam.dto.CreateGroupRequest;
import com.openwolf.iam.dto.GroupResponse;
import com.openwolf.iam.dto.UserResponse;
import com.openwolf.iam.service.GroupService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
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
 * Manages teams (groups in the /teams namespace).
 * Teams and domains both use the same {@code groups} table — they differ by context/domain_id.
 */
@RestController
@RequestMapping("/teams")
public class TeamController {

    private final GroupService groupService;

    public TeamController(GroupService groupService) {
        this.groupService = groupService;
    }

    @GetMapping
    public ResponseEntity<List<GroupResponse>> listTeams() {
        return ResponseEntity.ok(groupService.listGroups());
    }

    @PostMapping
    public ResponseEntity<GroupResponse> createTeam(
            @Valid @RequestBody CreateGroupRequest req,
            HttpServletRequest httpReq) {
        GroupResponse team = groupService.createGroup(req, httpReq);
        URI location = ServletUriComponentsBuilder.fromCurrentRequest()
                .path("/{id}")
                .buildAndExpand(team.id())
                .toUri();
        return ResponseEntity.created(location).body(team);
    }

    @GetMapping("/{teamId}")
    public ResponseEntity<GroupResponse> getTeam(@PathVariable UUID teamId) {
        return ResponseEntity.ok(groupService.getGroup(teamId));
    }

    @PutMapping("/{teamId}")
    public ResponseEntity<GroupResponse> updateTeam(
            @PathVariable UUID teamId,
            @Valid @RequestBody CreateGroupRequest req,
            HttpServletRequest httpReq) {
        return ResponseEntity.ok(groupService.updateGroup(teamId, req, httpReq));
    }

    @DeleteMapping("/{teamId}")
    public ResponseEntity<Void> deleteTeam(
            @PathVariable UUID teamId,
            HttpServletRequest httpReq) {
        groupService.deleteGroup(teamId, httpReq);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{teamId}/members")
    public ResponseEntity<GroupResponse> addMember(
            @PathVariable UUID teamId,
            @Valid @RequestBody AddMemberRequest req,
            HttpServletRequest httpReq) {
        GroupResponse team = groupService.addMember(teamId, req.userId(), httpReq);
        return ResponseEntity.status(201).body(team);
    }

    @DeleteMapping("/{teamId}/members/{userId}")
    public ResponseEntity<Void> removeMember(
            @PathVariable UUID teamId,
            @PathVariable String userId,
            HttpServletRequest httpReq) {
        groupService.removeMember(teamId, userId, httpReq);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/{teamId}/members")
    public ResponseEntity<List<UserResponse>> listMembers(@PathVariable UUID teamId) {
        return ResponseEntity.ok(groupService.listMembers(teamId));
    }
}
