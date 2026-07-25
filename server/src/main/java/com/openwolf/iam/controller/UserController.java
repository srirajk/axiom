package com.openwolf.iam.controller;

import com.openwolf.iam.dto.AssignRoleRequest;
import com.openwolf.iam.dto.CreateUserRequest;
import com.openwolf.iam.dto.PageResponse;
import com.openwolf.iam.dto.UpdateUserRequest;
import com.openwolf.iam.dto.UserResponse;
import com.openwolf.iam.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping
    @PreAuthorize("hasRole('platform_admin') or hasRole('tenant_admin') or hasRole('domain_admin')")
    public ResponseEntity<PageResponse<UserResponse>> listUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        return ResponseEntity.ok(userService.listUsers(page, size));
    }

    @GetMapping("/{userId}")
    public ResponseEntity<UserResponse> getUser(@PathVariable String userId) {
        return ResponseEntity.ok(userService.getUser(userId));
    }

    @PostMapping
    public ResponseEntity<UserResponse> createUser(
            @Valid @RequestBody CreateUserRequest req,
            HttpServletRequest httpReq) {
        UserResponse user = userService.createUser(req, httpReq);
        URI location = ServletUriComponentsBuilder.fromCurrentRequest()
                .path("/{id}")
                .buildAndExpand(user.id())
                .toUri();
        return ResponseEntity.created(location).body(user);
    }

    @PutMapping("/{userId}")
    public ResponseEntity<UserResponse> updateUser(
            @PathVariable String userId,
            @Valid @RequestBody UpdateUserRequest req,
            HttpServletRequest httpReq) {
        return ResponseEntity.ok(userService.updateUser(userId, req, httpReq));
    }

    @DeleteMapping("/{userId}")
    public ResponseEntity<Void> deleteUser(
            @PathVariable String userId,
            HttpServletRequest httpReq) {
        userService.deleteUser(userId, httpReq);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{userId}/roles")
    public ResponseEntity<UserResponse> assignRole(
            @PathVariable String userId,
            @Valid @RequestBody AssignRoleRequest req,
            HttpServletRequest httpReq) {
        return ResponseEntity.ok(userService.assignRole(userId, req.roleId(), httpReq));
    }

    @DeleteMapping("/{userId}/roles/{roleId}")
    public ResponseEntity<Void> removeRole(
            @PathVariable String userId,
            @PathVariable String roleId,
            HttpServletRequest httpReq) {
        userService.removeRole(userId, roleId, httpReq);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/{userId}/teams")
    public ResponseEntity<Map<String, Object>> getUserTeams(@PathVariable String userId) {
        List<String> teams = userService.getUserTeams(userId);
        return ResponseEntity.ok(Map.of("userId", userId, "teams", teams));
    }

    @GetMapping("/{userId}/domains")
    public ResponseEntity<Map<String, Object>> getUserDomains(@PathVariable String userId) {
        List<String> domains = userService.getUserDomains(userId);
        return ResponseEntity.ok(Map.of("userId", userId, "domains", domains));
    }
}
