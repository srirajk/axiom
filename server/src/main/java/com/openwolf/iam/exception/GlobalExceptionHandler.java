package com.openwolf.iam.exception;

import com.openwolf.iam.dto.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.stream.Collectors;

/**
 * Centralized exception handler — all exceptions map to {@link ErrorResponse}.
 * Stack traces are NEVER exposed to callers.
 * 4xx logged as WARN, 5xx logged as ERROR.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    // -------------------------------------------------------
    // 400 Bad Request
    // -------------------------------------------------------

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidation(
            MethodArgumentNotValidException ex, HttpServletRequest req) {
        String fields = ex.getBindingResult().getFieldErrors().stream()
                .map(FieldError::getDefaultMessage)
                .collect(Collectors.joining("; "));
        log.warn("Validation failed on {}: {}", req.getRequestURI(), fields);
        return ResponseEntity.badRequest().body(
                ErrorResponse.of("Validation Failed", fields, 400, req.getRequestURI()));
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ErrorResponse> handleConstraintViolation(
            ConstraintViolationException ex, HttpServletRequest req) {
        String message = ex.getConstraintViolations().stream()
                .map(cv -> cv.getPropertyPath() + ": " + cv.getMessage())
                .collect(Collectors.joining("; "));
        log.warn("Constraint violation on {}: {}", req.getRequestURI(), message);
        return ResponseEntity.badRequest().body(
                ErrorResponse.of("Constraint Violation", message, 400, req.getRequestURI()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgument(
            IllegalArgumentException ex, HttpServletRequest req) {
        log.warn("Illegal argument on {}: {}", req.getRequestURI(), ex.getMessage());
        return ResponseEntity.badRequest().body(
                ErrorResponse.of("Bad Request", ex.getMessage(), 400, req.getRequestURI()));
    }

    // -------------------------------------------------------
    // 401 Unauthorized
    // -------------------------------------------------------

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ErrorResponse> handleAuthentication(
            AuthenticationException ex, HttpServletRequest req) {
        log.warn("Authentication failure on {}: {}", req.getRequestURI(), ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                ErrorResponse.of("Unauthorized", "Authentication required", 401, req.getRequestURI()));
    }

    // -------------------------------------------------------
    // 403 Forbidden
    // -------------------------------------------------------

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDenied(
            AccessDeniedException ex, HttpServletRequest req) {
        log.warn("Access denied on {}: {}", req.getRequestURI(), ex.getMessage());
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(
                ErrorResponse.of("Forbidden", "Access denied", 403, req.getRequestURI()));
    }

    // -------------------------------------------------------
    // 404 Not Found
    // -------------------------------------------------------

    @ExceptionHandler(EntityNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleNotFound(
            EntityNotFoundException ex, HttpServletRequest req) {
        log.warn("Entity not found on {}: {}", req.getRequestURI(), ex.getMessage());
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
                ErrorResponse.of("Not Found", ex.getMessage(), 404, req.getRequestURI()));
    }

    // -------------------------------------------------------
    // 409 Conflict
    // -------------------------------------------------------

    @ExceptionHandler(ResourceConflictException.class)
    public ResponseEntity<ErrorResponse> handleConflict(
            ResourceConflictException ex, HttpServletRequest req) {
        log.warn("Resource conflict on {}: {}", req.getRequestURI(), ex.getMessage());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(
                ErrorResponse.of("Conflict", ex.getMessage(), 409, req.getRequestURI()));
    }

    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<ErrorResponse> handleIllegalState(
            IllegalStateException ex, HttpServletRequest req) {
        log.warn("Illegal state on {}: {}", req.getRequestURI(), ex.getMessage());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(
                ErrorResponse.of("Conflict", ex.getMessage(), 409, req.getRequestURI()));
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ErrorResponse> handleDataIntegrity(
            DataIntegrityViolationException ex, HttpServletRequest req) {
        log.warn("Data integrity violation on {}: {}", req.getRequestURI(), ex.getMostSpecificCause().getMessage());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(
                ErrorResponse.of("Conflict", "Resource already exists or violates a uniqueness constraint",
                        409, req.getRequestURI()));
    }

    // -------------------------------------------------------
    // 500 Internal Server Error (catch-all)
    // -------------------------------------------------------

    // Spring framework request errors are client faults, not server faults. Without these two
    // handlers the catch-all below turned an unsupported method into a 500 (e.g. PUT on a path that
    // only serves POST/DELETE) and a malformed body into a 500. Map them to their correct 4xx so the
    // catch-all only ever fires on a genuine server error.

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ErrorResponse> handleMethodNotSupported(
            HttpRequestMethodNotSupportedException ex, HttpServletRequest req) {
        log.warn("Method not supported on {}: {}", req.getRequestURI(), ex.getMessage());
        return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED).body(
                ErrorResponse.of("Method Not Allowed", ex.getMessage(), 405, req.getRequestURI()));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleNotReadable(
            HttpMessageNotReadableException ex, HttpServletRequest req) {
        log.warn("Malformed request body on {}: {}", req.getRequestURI(), ex.getMessage());
        return ResponseEntity.badRequest().body(
                ErrorResponse.of("Bad Request", "Malformed request body", 400, req.getRequestURI()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleUnexpected(
            Exception ex, HttpServletRequest req) {
        // Log full stack trace for unexpected errors — never expose it to callers
        log.error("Unexpected error on {}: {}", req.getRequestURI(), ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                ErrorResponse.of("Internal Server Error", "An unexpected error occurred",
                        500, req.getRequestURI()));
    }
}
