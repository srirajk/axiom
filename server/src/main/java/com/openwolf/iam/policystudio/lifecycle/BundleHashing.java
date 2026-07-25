package com.openwolf.iam.policystudio.lifecycle;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Deterministic SHA-256 hex for the policy-lifecycle content-addressing (Axiom Story C5). The
 * immutable bundle identity ({@code bundleId = b_<sha256>}) is a SHA-256 over the canonical
 * full-bundle bytes, so the same snapshot always yields the same id on any machine (reproducible
 * evidence — the same guarantee {@code StudioHashing} gives the C4 review hash, restated in the
 * lifecycle package so it never has to reach into the C4 authoring internals).
 */
final class BundleHashing {

    private BundleHashing() {}

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
