package com.openwolf.iam.authority;

import com.openwolf.iam.authority.task.DurableTask;
import com.openwolf.iam.authority.task.DurableTaskService;
import com.openwolf.iam.invocation.InvocationContextService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.UUID;

/**
 * Phase 3.4/3.6 workload API. The caller is the confidential client named by its own client-credentials token; the
 * tenant comes from that token, never from the path.
 */
@RestController
@RequestMapping("/api/v1/workload")
public class WorkloadAuthorityController {
    public record CreateTaskRequest(@NotNull DurableTask.AuthorityType authorityType, @NotNull UUID authorityId,
                                    @Size(max = 128) String taskRef, @Size(max = 128) String callbackProvider) {}

    public record EndRequest(@Size(max = 200) String reason) {}

    private final DurableTaskService tasks;
    private final InvocationContextService contexts;

    public WorkloadAuthorityController(DurableTaskService tasks, InvocationContextService contexts) {
        this.tasks = tasks;
        this.contexts = contexts;
    }

    @PostMapping("/tasks")
    public ResponseEntity<DurableTaskService.TaskView> create(@AuthenticationPrincipal Jwt caller,
                                                              @Valid @RequestBody CreateTaskRequest request) {
        return ResponseEntity.status(201).body(tasks.create(tenant(caller), client(caller), request.authorityType(),
                request.authorityId(), request.taskRef(), request.callbackProvider()));
    }

    @GetMapping("/tasks/{taskId}")
    public ResponseEntity<DurableTaskService.TaskView> get(@AuthenticationPrincipal Jwt caller, @PathVariable UUID taskId) {
        return ResponseEntity.ok(tasks.get(tenant(caller), client(caller), taskId));
    }

    @PostMapping("/tasks/{taskId}/resume")
    public ResponseEntity<DurableTaskService.TaskView> resume(@AuthenticationPrincipal Jwt caller,
                                                              @PathVariable UUID taskId) {
        return ResponseEntity.ok(tasks.resume(tenant(caller), client(caller), taskId));
    }

    @PostMapping("/tasks/{taskId}/complete")
    public ResponseEntity<DurableTaskService.TaskView> complete(@AuthenticationPrincipal Jwt caller,
                                                                @PathVariable UUID taskId,
                                                                @Valid @RequestBody(required = false) EndRequest request) {
        return ResponseEntity.ok(tasks.endByWorkload(tenant(caller), client(caller), taskId,
                DurableTask.Status.COMPLETED, request == null ? null : request.reason()));
    }

    @PostMapping("/tasks/{taskId}/cancel")
    public ResponseEntity<DurableTaskService.TaskView> cancel(@AuthenticationPrincipal Jwt caller,
                                                              @PathVariable UUID taskId,
                                                              @Valid @RequestBody(required = false) EndRequest request) {
        return ResponseEntity.ok(tasks.endByWorkload(tenant(caller), client(caller), taskId,
                DurableTask.Status.CANCELLED, request == null ? null : request.reason()));
    }

    /** Phase 3.6: the broker that established a run cancels one branch (or the whole run) and its descendants. */
    @PostMapping("/invocation-contexts/{contextId}/cancel")
    public ResponseEntity<Map<String, Object>> cancelContext(@AuthenticationPrincipal Jwt caller,
                                                             @PathVariable UUID contextId,
                                                             @Valid @RequestBody(required = false) EndRequest request) {
        int cancelled = contexts.cancelByBroker(tenant(caller), contextId, client(caller),
                request == null ? null : request.reason());
        return ResponseEntity.ok(Map.of("context_id", contextId.toString(), "cancelled_contexts", cancelled));
    }

    private static String tenant(Jwt caller) { return caller.getClaimAsString("tenant_id"); }

    private static String client(Jwt caller) { return caller.getClaimAsString("client_id"); }
}
