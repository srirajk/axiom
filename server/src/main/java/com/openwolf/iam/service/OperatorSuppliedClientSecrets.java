package com.openwolf.iam.service;

import com.fasterxml.jackson.databind.JsonNode;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.regex.Pattern;

/**
 * Operator-supplied confidential-client secrets. The operator generates and escrows the secret before calling Axiom,
 * so no credential exists only in an HTTP response. Axiom stores it with the same BCrypt encoding as a generated
 * secret and never returns it. Messages are constant and never contain the value.
 */
public final class OperatorSuppliedClientSecrets {
    public static final String FIELD = "clientSecret";
    public static final String RECOVERY_ID_FIELD = "recoveryId";
    public static final String FORMAT_MESSAGE = "clientSecret must be 43-64 base64url characters";
    static final String PAYLOAD_MESSAGE = "rotation payload must be empty or contain clientSecret and recoveryId";
    static final String RECOVERY_ID_MESSAGE = "recoveryId must be 43 base64url characters";
    private static final String RECOVERY_HASH_DOMAIN = "client-secret-rotation:";
    /** This bounds encoding and BCrypt input size; syntax cannot prove a caller used a CSPRNG. */
    private static final Pattern FORMAT = Pattern.compile("[A-Za-z0-9_-]{43,64}");
    private static final Pattern RECOVERY_ID_FORMAT = Pattern.compile("[A-Za-z0-9_-]{43}");
    /** Rejects trivially repetitive values; a CSPRNG value of this length has far more distinct characters. */
    private static final int MIN_DISTINCT_CHARACTERS = 16;

    private OperatorSuppliedClientSecrets() {}

    public static String requireValid(String value) {
        if (value == null || !FORMAT.matcher(value).matches() || value.chars().distinct().count() < MIN_DISTINCT_CHARACTERS) {
            throw new IllegalArgumentException(FORMAT_MESSAGE);
        }
        return value;
    }

    /** {} or absent: Axiom generates the secret. Supplied rotations require an independent recovery identifier. */
    public static String fromRotationPayload(JsonNode payload) {
        if (payload == null || payload.isNull() || (payload.isObject() && payload.isEmpty())) return null;
        JsonNode value = payload.isObject() && payload.size() == 2 ? payload.get(FIELD) : null;
        if (value == null || !value.isTextual()) throw new IllegalArgumentException(PAYLOAD_MESSAGE);
        requireRecoveryId(payload);
        return requireValid(value.asText());
    }

    /**
     * The public payloadHash for a supplied rotation must not be an offline password oracle. The recovery ID is
     * independent of the encrypted replacement secret; AES-GCM authenticates the payload itself at apply time.
     */
    public static String payloadHash(JsonNode payload, String canonical) {
        if (fromRotationPayload(payload) == null) return sha256(canonical);
        return sha256(RECOVERY_HASH_DOMAIN + requireRecoveryId(payload));
    }

    private static String requireRecoveryId(JsonNode payload) {
        JsonNode node = payload.get(RECOVERY_ID_FIELD);
        if (node == null || !node.isTextual() || !RECOVERY_ID_FORMAT.matcher(node.asText()).matches()) {
            throw new IllegalArgumentException(RECOVERY_ID_MESSAGE);
        }
        return node.asText();
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 unavailable", ex);
        }
    }
}
