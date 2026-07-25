package com.openwolf.iam.exception;

/**
 * Thrown when a requested entity does not exist in the database.
 * Maps to HTTP 404 in {@link GlobalExceptionHandler}.
 */
public class EntityNotFoundException extends RuntimeException {

    public EntityNotFoundException(String message) {
        super(message);
    }

    public EntityNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }

    public static EntityNotFoundException forId(String entityType, Object id) {
        return new EntityNotFoundException(entityType + " not found: " + id);
    }
}
