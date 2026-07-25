package com.openwolf.iam.security;

/** Protects secrets that must be recovered for an outbound protocol flow. */
public interface SecretProtector {
    String protect(String plaintext);
    String reveal(String protectedValue);
}
