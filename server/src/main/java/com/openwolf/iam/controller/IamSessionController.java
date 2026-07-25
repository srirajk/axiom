package com.openwolf.iam.controller;

import com.openwolf.iam.dto.IamSessionResponse;
import com.openwolf.iam.dto.RevokeIamSessionRequest;
import com.openwolf.iam.entity.IamSession;
import com.openwolf.iam.service.IamSessionService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
public class IamSessionController {
    private final IamSessionService sessions;
    public IamSessionController(IamSessionService sessions) { this.sessions = sessions; }

    @GetMapping("/admin/tenants/{tenantId}/sessions")
    @PreAuthorize("hasAnyRole('platform_admin','tenant_admin')")
    public ResponseEntity<Page<IamSessionResponse>> list(
            @PathVariable String tenantId,
            @RequestParam(required = false) String principalId,
            @RequestParam(required = false) String clientId,
            @RequestParam(required = false) IamSession.Status status,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        return ResponseEntity.ok(sessions.list(tenantId, principalId, clientId, status, page, size));
    }

    @PostMapping("/admin/tenants/{tenantId}/sessions/{sessionId}/revoke")
    @PreAuthorize("hasAnyRole('platform_admin','tenant_admin')")
    public ResponseEntity<IamSessionResponse> revoke(
            @PathVariable String tenantId, @PathVariable UUID sessionId,
            @Valid @RequestBody RevokeIamSessionRequest request, HttpServletRequest httpRequest) {
        return ResponseEntity.ok(sessions.revoke(tenantId, sessionId, request, httpRequest));
    }

    @GetMapping("/api/me/sessions")
    public ResponseEntity<List<IamSessionResponse>> selfList(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        return ResponseEntity.ok(sessions.selfList(page, size));
    }

    @PostMapping("/api/me/sessions/{sessionId}/revoke")
    public ResponseEntity<IamSessionResponse> selfRevoke(
            @PathVariable UUID sessionId, @Valid @RequestBody RevokeIamSessionRequest request,
            HttpServletRequest httpRequest) {
        return ResponseEntity.ok(sessions.selfRevoke(sessionId, request, httpRequest));
    }
}
