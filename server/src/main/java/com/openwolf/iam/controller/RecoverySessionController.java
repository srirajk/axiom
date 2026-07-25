package com.openwolf.iam.controller;

import com.openwolf.iam.dto.RecoverySessionRequest;
import com.openwolf.iam.dto.RecoverySessionResponse;
import com.openwolf.iam.service.RecoverySessionService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RecoverySessionController {
    private final RecoverySessionService service;
    public RecoverySessionController(RecoverySessionService service) { this.service = service; }

    @PostMapping("/auth/recovery/session")
    public ResponseEntity<RecoverySessionResponse> issue(@Valid @RequestBody RecoverySessionRequest request,
                                                         HttpServletRequest httpRequest) {
        return ResponseEntity.ok(service.issue(request, httpRequest));
    }
}
