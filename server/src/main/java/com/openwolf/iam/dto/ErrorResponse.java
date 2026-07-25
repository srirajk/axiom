package com.openwolf.iam.dto;

import java.time.Instant;

/**
 * Standard error response body. Every exception handler returns this shape.
 * Stack traces are NEVER included.
 */
public record ErrorResponse(
        String error,
        String message,
        int status,
        String path,
        Instant timestamp
) {
    /**
     * Factory — captures the current timestamp automatically.
     */
    public static ErrorResponse of(String error, String message, int status, String path) {
        return new ErrorResponse(error, message, status, path, Instant.now());
    }
}
