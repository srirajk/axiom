package com.openwolf.iam.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Simple health endpoint — permits all (no auth required).
 * The Spring Actuator /actuator/health endpoint provides richer detail;
 * this endpoint preserves the legacy /health path for nginx probes.
 */
@RestController
@RequestMapping("/health")
public class HealthController {

    @GetMapping
    public ResponseEntity<Map<String, String>> health() {
        return ResponseEntity.ok(Map.of(
                "status", "UP",
                "service", "iam-service",
                "version", "1.0.0"
        ));
    }
}
