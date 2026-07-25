package com.openwolf.iam.exception;

/**
 * Thrown when a create/update operation would violate a uniqueness constraint.
 * Maps to HTTP 409 in {@link GlobalExceptionHandler}.
 */
public class ResourceConflictException extends RuntimeException {

    public ResourceConflictException(String message) {
        super(message);
    }

    public ResourceConflictException(String message, Throwable cause) {
        super(message, cause);
    }
}
