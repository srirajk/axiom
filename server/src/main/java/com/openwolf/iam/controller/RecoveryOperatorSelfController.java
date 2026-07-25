package com.openwolf.iam.controller;

import com.openwolf.iam.dto.RecoveryOperatorResponse;
import com.openwolf.iam.dto.RecoveryOperatorTransitionRequest;
import com.openwolf.iam.service.RecoveryOperatorService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;
import java.util.List;

@RestController
@RequestMapping("/api/me/recovery-operators")
public class RecoveryOperatorSelfController {
    private final RecoveryOperatorService service;
    public RecoveryOperatorSelfController(RecoveryOperatorService service) { this.service = service; }

    @GetMapping
    public ResponseEntity<List<RecoveryOperatorResponse>> list() {
        return ResponseEntity.ok(service.selfList());
    }

    @PostMapping("/{operatorId}/activate")
    public ResponseEntity<RecoveryOperatorResponse> activate(@PathVariable UUID operatorId,
            @Valid @RequestBody RecoveryOperatorTransitionRequest request, HttpServletRequest httpRequest) {
        return ResponseEntity.ok(service.activateSelf(operatorId, request, httpRequest));
    }

    @PostMapping("/{operatorId}/rotate")
    public ResponseEntity<RecoveryOperatorResponse> rotate(@PathVariable UUID operatorId,
            @Valid @RequestBody RecoveryOperatorTransitionRequest request, HttpServletRequest httpRequest) {
        return ResponseEntity.ok(service.completeRotationSelf(operatorId, request, httpRequest));
    }
}
