package com.openwolf.iam.policystudio.breakglass;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;

/**
 * Idempotent importer for Cerbos 0.53 JSONL decision logs. It understands the real batched shape:
 * {@code log.kind=decision}, {@code callId}, {@code checkResources.inputs[]} and paired
 * {@code outputs[]}. Every resource/action output gets its own durable composite event id.
 */
@Service
public class CerbosAuditFileImporter {
    private static final Logger log = LoggerFactory.getLogger(CerbosAuditFileImporter.class);

    private final ObjectMapper mapper;
    private final BreakGlassDecisionEventRepository events;
    private final BreakGlassBundleGrantRepository bundleGrants;
    private final Path auditFile;

    public CerbosAuditFileImporter(ObjectMapper mapper, BreakGlassDecisionEventRepository events,
                                   BreakGlassBundleGrantRepository bundleGrants,
                                   @Value("${iam.break-glass.cerbos-audit-file:/audit/audit.log}")
                                   String auditFile) {
        this.mapper = mapper;
        this.events = events;
        this.bundleGrants = bundleGrants;
        this.auditFile = auditFile == null || auditFile.isBlank() ? null : Path.of(auditFile);
    }

    @Scheduled(fixedDelayString = "${iam.break-glass.cerbos-import-ms:5000}")
    public void scheduledImport() {
        importAvailable();
    }

    public int importAvailable() {
        if (auditFile == null || !Files.isRegularFile(auditFile)) {
            return 0;
        }
        int imported = 0;
        try (var lines = Files.lines(auditFile)) {
            for (String line : (Iterable<String>) lines::iterator) {
                imported += importLine(line);
            }
        } catch (Exception e) {
            log.warn("Unable to import Cerbos audit file '{}': {}", auditFile, e.toString());
        }
        return imported;
    }

    int importLine(String line) {
        try {
            JsonNode root = mapper.readTree(line);
            String logKind = root.path("log.kind").asText(null);
            if (logKind == null) logKind = root.path("log").path("kind").asText(null);
            if (!"decision".equals(logKind)) return 0;
            String callId = text(root, "callId");
            Instant occurredAt = Instant.parse(text(root, "timestamp"));
            JsonNode check = root.path("checkResources");
            JsonNode inputs = check.path("inputs");
            JsonNode outputs = check.has("outputs") ? check.path("outputs") : root.path("outputs");
            if (callId == null || !inputs.isArray() || !outputs.isArray()) return 0;

            int imported = 0;
            for (int i = 0; i < outputs.size(); i++) {
                JsonNode output = outputs.get(i);
                String resourceId = text(output, "resourceId");
                JsonNode input = pairedInput(inputs, i, resourceId);
                if (input == null) continue;
                JsonNode principal = input.path("principal");
                JsonNode resource = input.path("resource");
                String principalId = text(principal, "id");
                String kind = text(resource, "kind");
                String version = text(resource, "policyVersion");
                String tenant = text(resource.path("attr"), "tenant_id");
                if (tenant == null) tenant = text(principal.path("attr"), "tenant_id");
                if (resourceId == null) resourceId = text(resource, "id");
                if (principalId == null || kind == null || version == null || tenant == null || resourceId == null) {
                    continue;
                }
                if (!bundleGrants.existsByBundleId(version)) {
                    continue; // normal policy traffic is not C6 use evidence
                }
                java.util.Set<String> roles = new java.util.LinkedHashSet<>();
                principal.path("roles").forEach(roleNode -> roles.add(roleNode.asText()));
                var actionFields = output.path("actions").fields();
                while (actionFields.hasNext()) {
                    var action = actionFields.next();
                    String effect = action.getValue().isTextual()
                            ? action.getValue().asText() : text(action.getValue(), "effect");
                    String decision = "EFFECT_ALLOW".equals(effect) || "ALLOW".equals(effect) ? "ALLOW" : "DENY";
                    BreakGlassDecisionEvent event = new BreakGlassDecisionEvent(callId, tenant, version,
                            decision, principalId, kind, resourceId, action.getKey(), roles, occurredAt);
                    if (!events.existsById(event.getEventId())) {
                        events.save(event);
                        imported++;
                    }
                }
            }
            return imported;
        } catch (Exception malformed) {
            log.debug("Skipping malformed/non-decision Cerbos audit line: {}", malformed.toString());
            return 0;
        }
    }

    private static JsonNode pairedInput(JsonNode inputs, int index, String resourceId) {
        if (index < inputs.size()) {
            JsonNode paired = inputs.get(index);
            if (resourceId == null || resourceId.equals(text(paired.path("resource"), "id"))) return paired;
        }
        for (JsonNode input : inputs) {
            if (resourceId != null && resourceId.equals(text(input.path("resource"), "id"))) return input;
        }
        return null;
    }

    private static String text(JsonNode node, String field) {
        String value = node.path(field).asText(null);
        return value == null || value.isBlank() ? null : value;
    }
}
