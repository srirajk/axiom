package com.openwolf.iam.authority.task;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.UUID;

/** Phase 3.5 callback intake. Responses never explain a refusal beyond its status. */
@RestController
@RequestMapping("/api/v1/callbacks/tenants/{tenantId}/tasks/{taskId}")
public class TaskCallbackController {
    private final TaskCallbackService callbacks;

    public TaskCallbackController(TaskCallbackService callbacks) {
        this.callbacks = callbacks;
    }

    @PostMapping
    public ResponseEntity<Map<String, Object>> accept(@PathVariable String tenantId, @PathVariable UUID taskId,
                                                      @RequestHeader(value = "X-Axiom-Callback-Provider", required = false) String provider,
                                                      @RequestHeader(value = "X-Axiom-Callback-Timestamp", required = false) Long issuedAt,
                                                      @RequestHeader(value = "X-Axiom-Callback-Nonce", required = false) String nonce,
                                                      @RequestHeader(value = "X-Axiom-Callback-Event", required = false) String event,
                                                      @RequestHeader(value = "X-Axiom-Callback-Signature", required = false) String signature,
                                                      @RequestBody(required = false) byte[] body) {
        try {
            if (issuedAt == null) return ResponseEntity.status(400).body(Map.of("status", "rejected"));
            callbacks.accept(tenantId, taskId, provider, issuedAt, nonce, event, body, signature);
            return ResponseEntity.accepted().body(Map.of("status", "accepted"));
        } catch (TaskCallbackService.Refused refused) {
            return ResponseEntity.status(refused.status()).body(Map.of("status", "rejected"));
        }
    }
}
