package com.openwolf.iam.policystudio;

/**
 * Thrown when a model proposal cannot be parsed into the allowed, typed policy IR — malformed
 * YAML, a YAML alias/anchor or custom tag (both banned as an injection/aliasing vector), or any
 * document shape other than a single Cerbos resource policy. A parse failure is a hard rejection:
 * nothing is stored (Axiom Story C2).
 */
public class PolicyParseException extends RuntimeException {
    public PolicyParseException(String message) {
        super(message);
    }

    public PolicyParseException(String message, Throwable cause) {
        super(message, cause);
    }
}
