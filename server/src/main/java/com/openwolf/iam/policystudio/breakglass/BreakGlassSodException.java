package com.openwolf.iam.policystudio.breakglass;

/**
 * Thrown when the expedited break-glass approval path would violate separation of duties (Axiom
 * Story C6.4, inheriting C1's {@code policy_approval} meta-authz): the approver may not be the
 * requester (author≠approver), and the approver must hold the studio approver role (a superuser is
 * not an auto-approver). Emergency access does not relax two-person control.
 */
public class BreakGlassSodException extends RuntimeException {
    public BreakGlassSodException(String message) {
        super(message);
    }
}
