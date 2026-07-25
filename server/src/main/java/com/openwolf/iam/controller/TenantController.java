package com.openwolf.iam.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.openwolf.iam.entity.Tenant;
import com.openwolf.iam.auth.ExecutionTenant;
import com.openwolf.iam.exception.EntityNotFoundException;
import com.openwolf.iam.repository.TenantRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Tenant-scoped configuration endpoints.
 */
@RestController
@RequestMapping("/tenants")
public class TenantController {

    private static final Logger log = LoggerFactory.getLogger(TenantController.class);
    private static final TypeReference<List<Map<String, Object>>> LIST_MAP_TYPE = new TypeReference<>() {};

    private final TenantRepository tenantRepository;
    private final ObjectMapper objectMapper;
    private final ExecutionTenant executionTenant;

    public TenantController(TenantRepository tenantRepository, ObjectMapper objectMapper, ExecutionTenant executionTenant) {
        this.tenantRepository = tenantRepository;
        this.objectMapper = objectMapper;
        this.executionTenant = executionTenant;
    }

    /**
     * {@code GET /tenants/current/classification-schema} — returns the execution tenant's data
     * classification tiers ordered by rank (e.g. public → restricted).
     */
    @GetMapping("/current/classification-schema")
    @Transactional(readOnly = true)
    public ResponseEntity<List<Map<String, Object>>> getClassificationSchema() {
        String tenantId = executionTenant.require();
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> EntityNotFoundException.forId("Tenant", tenantId));

        List<Map<String, Object>> schema = parseSchema(tenant.getClassificationSchema());
        return ResponseEntity.ok(schema);
    }

    private List<Map<String, Object>> parseSchema(String json) {
        if (json == null || json.isBlank() || json.equals("[]")) {
            return Collections.emptyList();
        }
        try {
            return objectMapper.readValue(json, LIST_MAP_TYPE);
        } catch (JsonProcessingException ex) {
            log.warn("Failed to parse classification schema JSON: {}", ex.getMessage());
            return Collections.emptyList();
        }
    }
}
