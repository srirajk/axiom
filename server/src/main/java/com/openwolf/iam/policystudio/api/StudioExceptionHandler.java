package com.openwolf.iam.policystudio.api;

import com.openwolf.iam.policystudio.StaleReviewException;
import com.openwolf.iam.policystudio.breakglass.BreakGlassSodException;
import com.openwolf.iam.policystudio.lifecycle.AuditIntegrityException;
import com.openwolf.iam.policystudio.lifecycle.BundleTamperException;
import com.openwolf.iam.policystudio.lifecycle.StalePromotionException;
import com.openwolf.iam.policystudio.lifecycle.UnauthorizedPromotionException;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

/**
 * Maps the studio service/domain exceptions to stable HTTP status codes for the studio SPA, scoped to
 * the {@code com.openwolf.iam.controller.studio} package so it never alters the status contract of any
 * other IAM controller. The status codes are part of the published API contract
 * ({@code docs/studio-api-contract.md}):
 *
 * <ul>
 *   <li>403 — cross-tenant / missing tenant claim / an approval that does not authorize the candidate</li>
 *   <li>409 — separation-of-duties violation, or a stale compare-and-set (the reviewed baseline moved)</li>
 *   <li>422 — a tampered candidate bundle, or an inadmissible artifact / integrity failure</li>
 *   <li>400 — a malformed request (bad scope, missing field)</li>
 * </ul>
 */
@Order(Ordered.HIGHEST_PRECEDENCE) // consulted before the service-wide GlobalExceptionHandler
@RestControllerAdvice(assignableTypes = {
        StudioAuthoringController.class,
        StudioReviewController.class,
        StudioPromotionController.class,
        StudioLifecycleController.class,
        StudioBreakGlassController.class
})
class StudioExceptionHandler {

    private static ResponseEntity<Map<String, String>> body(HttpStatus status, String error, String message) {
        return ResponseEntity.status(status).body(Map.of("error", error, "message", message == null ? "" : message));
    }

    @ExceptionHandler({CrossTenantException.class, MissingTenantClaimException.class})
    ResponseEntity<Map<String, String>> forbiddenScope(RuntimeException e) {
        return body(HttpStatus.FORBIDDEN, "tenant_scope_violation", e.getMessage());
    }

    @ExceptionHandler(UnauthorizedPromotionException.class)
    ResponseEntity<Map<String, String>> unauthorizedPromotion(UnauthorizedPromotionException e) {
        return body(HttpStatus.FORBIDDEN, "unauthorized_promotion", e.getMessage());
    }

    @ExceptionHandler({SeparationOfDutiesException.class, BreakGlassSodException.class})
    ResponseEntity<Map<String, String>> sod(RuntimeException e) {
        return body(HttpStatus.CONFLICT, "separation_of_duties", e.getMessage());
    }

    @ExceptionHandler({StaleReviewException.class, StalePromotionException.class})
    ResponseEntity<Map<String, String>> stale(RuntimeException e) {
        return body(HttpStatus.CONFLICT, "stale_baseline", e.getMessage());
    }

    @ExceptionHandler(BundleTamperException.class)
    ResponseEntity<Map<String, String>> tamper(BundleTamperException e) {
        return body(HttpStatus.UNPROCESSABLE_ENTITY, "bundle_tamper", e.getMessage());
    }

    @ExceptionHandler(AuditIntegrityException.class)
    ResponseEntity<Map<String, String>> auditIntegrity(AuditIntegrityException e) {
        return body(HttpStatus.UNPROCESSABLE_ENTITY, "audit_integrity", e.getMessage());
    }

    @ExceptionHandler(IllegalStateException.class)
    ResponseEntity<Map<String, String>> illegalState(IllegalStateException e) {
        return body(HttpStatus.UNPROCESSABLE_ENTITY, "unprocessable", e.getMessage());
    }

    @ExceptionHandler(IllegalArgumentException.class)
    ResponseEntity<Map<String, String>> illegalArgument(IllegalArgumentException e) {
        return body(HttpStatus.BAD_REQUEST, "bad_request", e.getMessage());
    }
}
