package com.openwolf.iam.controller;

import com.openwolf.iam.auth.ApplicationScopes;
import com.openwolf.iam.auth.SubjectContextCaller;
import com.openwolf.iam.dto.SubjectContextRequest;
import com.openwolf.iam.dto.SubjectContextResponse;
import com.openwolf.iam.dto.ApplicationDecisionBatchRequest;
import com.openwolf.iam.dto.ApplicationDecisionResponse;
import com.openwolf.iam.service.ApplicationDecisionService;
import com.openwolf.iam.service.SubjectContextService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/** Service-only Axiom platform-authz read surface for verified registered application clients. */
@RestController
@RequestMapping("/api/v1/platform-authz")
public class PlatformAuthzController {
    private static final String V1_MEDIA_TYPE = "application/vnd.axiom.platform-authz.v1+json";
    private final SubjectContextCaller caller;
    private final SubjectContextService subjectContextService;
    private final ApplicationDecisionService decisions;

    public PlatformAuthzController(SubjectContextCaller caller, SubjectContextService subjectContextService,
                                   ApplicationDecisionService decisions) {
        this.caller = caller;
        this.subjectContextService = subjectContextService;
        this.decisions = decisions;
    }

    @PostMapping(value = "/subject-context", consumes = V1_MEDIA_TYPE, produces = V1_MEDIA_TYPE)
    @PreAuthorize("hasAuthority('SCOPE_" + ApplicationScopes.SUBJECT_CONTEXT_READ + "')")
    public ResponseEntity<SubjectContextResponse> subjectContext(
            @Valid @RequestBody SubjectContextRequest request) {
        if (!"1.0".equals(request.contractVersion())) throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE, "unsupported contract version");
        var authority = caller.requireAuthorized(request.tenantId());
        return subjectContextService.resolveForApplication(request.requestId(), request.subjectId(), request.tenantId(), authority.applicationId())
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.<SubjectContextResponse>notFound().build());
    }

    /** Generic application-access policy v1; never an Axiom-admin or consuming-product policy decision. */
    @PostMapping(value = "/decisions", consumes = V1_MEDIA_TYPE, produces = V1_MEDIA_TYPE)
    @PreAuthorize("hasAuthority('SCOPE_" + ApplicationScopes.PLATFORM_AUTHZ_DECIDE + "')")
    public ResponseEntity<ApplicationDecisionResponse> decide(
            @Valid @RequestBody ApplicationDecisionBatchRequest request, HttpServletRequest httpRequest) {
        try {
            var authority = caller.requireAuthorized(request.tenantId(), ApplicationScopes.PLATFORM_AUTHZ_DECIDE);
            return ResponseEntity.ok(decisions.decide(request.tenantId(), request.subjectId(), authority.applicationId(),
                    request, httpRequest));
        } catch (IllegalArgumentException malformed) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "malformed decision batch");
        }
    }
}
