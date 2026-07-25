package com.openwolf.iam.controller;

import com.openwolf.iam.dto.CreateRoleRequest;
import com.openwolf.iam.dto.RoleResponse;
import com.openwolf.iam.service.RoleService;
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

@RestController
@RequestMapping("/roles")
public class RoleController {

    private final RoleService roleService;

    public RoleController(RoleService roleService) {
        this.roleService = roleService;
    }

    @GetMapping
    public ResponseEntity<List<RoleResponse>> listRoles() {
        return ResponseEntity.ok(roleService.listRoles());
    }

    @PostMapping
    public ResponseEntity<RoleResponse> createRole(
            @Valid @RequestBody CreateRoleRequest req,
            HttpServletRequest httpReq) {
        RoleResponse role = roleService.createRole(req, httpReq);
        URI location = ServletUriComponentsBuilder.fromCurrentRequest()
                .path("/{id}")
                .buildAndExpand(role.id())
                .toUri();
        return ResponseEntity.created(location).body(role);
    }

    @GetMapping("/{roleId}")
    public ResponseEntity<RoleResponse> getRole(@PathVariable UUID roleId) {
        return ResponseEntity.ok(roleService.getRole(roleId));
    }

    @PutMapping("/{roleId}")
    public ResponseEntity<RoleResponse> updateRole(
            @PathVariable UUID roleId,
            @Valid @RequestBody CreateRoleRequest req,
            HttpServletRequest httpReq) {
        return ResponseEntity.ok(roleService.updateRole(roleId, req, httpReq));
    }

    @DeleteMapping("/{roleId}")
    public ResponseEntity<Void> deleteRole(
            @PathVariable UUID roleId,
            HttpServletRequest httpReq) {
        roleService.deleteRole(roleId, httpReq);
        return ResponseEntity.noContent().build();
    }
}
