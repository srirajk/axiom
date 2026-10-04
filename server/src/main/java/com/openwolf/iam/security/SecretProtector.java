package com.openwolf.iam.security;

/** Protects secrets that must be recovered for an outbound protocol flow. */
public interface SecretProtector {
    String protect(String plaintext);
    String reveal(String protectedValue);

    /**
     * Keyed, deterministic digest (lowercase hex HMAC-SHA256 under a purpose-specific subkey of the configured
     * master key). Unlike a plain hash it cannot be used to test guesses of {@code value} without that key.
     */
    default String keyedDigest(String purpose, String value) {
        throw new UnsupportedOperationException("keyed digests are not supported by this protector");
    }
}
