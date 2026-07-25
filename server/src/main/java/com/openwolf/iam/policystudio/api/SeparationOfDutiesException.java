package com.openwolf.iam.policystudio.api;

/**
 * The acting approver is the same principal that authored the artifact under review — author≠approver
 * is violated (Axiom C1.2). Enforced regardless of role, so a {@code platform_admin} is never an
 * auto-approver of their own draft (C1.3). Surfaced as 409 Conflict.
 */
class SeparationOfDutiesException extends RuntimeException {
    SeparationOfDutiesException(String message) {
        super(message);
    }
}
