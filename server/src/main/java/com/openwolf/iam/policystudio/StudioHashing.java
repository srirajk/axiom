package com.openwolf.iam.policystudio;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Deterministic hashing for the consequence-diff review surface (Axiom Story C4). Every identity that
 * binds an approval to the exact machine consequences — the {@code fixtureSetHash}, the per-bundle
 * {@code bundleId}, and the top-level {@code consequenceReviewHash} — is a SHA-256 over a canonical
 * string, so the same inputs always produce the same hash on any machine (reproducible evidence).
 */
final class StudioHashing {

    private StudioHashing() {}

    static String sha256Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
