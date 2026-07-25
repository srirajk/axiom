package com.openwolf.iam.policystudio.lifecycle;

/**
 * Thrown when a stored/promoted policy bundle fails its content-addressed integrity check (Axiom Story
 * C5.4) — a promoted bundle is immutable; editing it in place while keeping its id is rejected.
 */
public class BundleTamperException extends RuntimeException {
    public BundleTamperException(String message) {
        super(message);
    }
}
