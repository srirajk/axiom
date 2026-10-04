package com.openwolf.iam.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.openwolf.iam.entity.IdentityControlRequest;
import com.openwolf.iam.security.SecretProtector;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Identity-control payload rules shared by proposal and apply. Payloads may carry replacement secrets, so they are
 * validated before anything is stored and encrypted at rest. The stored and returned {@code payloadHash} must never be
 * a plain hash of a secret, which would let anyone who can read it test guesses offline:
 * <ul>
 *   <li>supplied application-client rotations: SHA-256 of the independent, random {@code recoveryId}
 *       ({@link OperatorSuppliedClientSecrets#payloadHash}), which the operator's tool can recompute for recovery;</li>
 *   <li>identity-source secret rotations (externally issued secrets of unknown entropy): a keyed HMAC under the
 *       master key, which no reader can recompute;</li>
 *   <li>actions without a payload: SHA-256 of {@code {}}, a constant that reveals nothing.</li>
 * </ul>
 * The encrypted payload itself is authenticated by AES-GCM when it is revealed at apply.
 */
final class IdentityControlPayloads {
    static final String DIGEST_PURPOSE = "identity-control-payload";
    static final String IDENTITY_SOURCE_SECRET_MESSAGE = "rotation payload must contain only a clientSecret of 1-4096 characters";
    static final String EMPTY_PAYLOAD_MESSAGE = "payload is not permitted for this generated mutation";
    private static final int MAX_IDENTITY_SOURCE_SECRET = 4096;

    private IdentityControlPayloads() {}

    /** Rejects a payload the action cannot use; messages are constant and never contain payload values. */
    static void validate(IdentityControlRequest.Action action, JsonNode payload) {
        switch (action) {
            case ROTATE_APPLICATION_CLIENT_SECRET -> OperatorSuppliedClientSecrets.fromRotationPayload(payload);
            case ROTATE_IDENTITY_SOURCE_SECRET -> identitySourceSecret(payload);
            case REPLACE_APPLICATION_CLIENT_KEYS -> ClientAssertionKeys.validate(clientKeys(payload));
            default -> {
                if (!empty(payload)) throw new IllegalArgumentException(EMPTY_PAYLOAD_MESSAGE);
            }
        }
    }

    static String identitySourceSecret(JsonNode payload) {
        JsonNode value = payload != null && payload.isObject() && payload.size() == 1 ? payload.get("clientSecret") : null;
        if (value == null || !value.isTextual() || value.asText().isBlank() || value.asText().length() > MAX_IDENTITY_SOURCE_SECRET) {
            throw new IllegalArgumentException(IDENTITY_SOURCE_SECRET_MESSAGE);
        }
        return value.asText();
    }

    /** {@code {"jwks": {...}}}: public keys only (validated by {@link ClientAssertionKeys}); not secret material. */
    @SuppressWarnings("unchecked")
    static java.util.Map<String, Object> clientKeys(JsonNode payload) {
        JsonNode jwks = payload != null && payload.isObject() && payload.size() == 1 ? payload.get("jwks") : null;
        if (jwks == null || !jwks.isObject()) throw new IllegalArgumentException("payload must contain only a jwks object");
        return new com.fasterxml.jackson.databind.ObjectMapper().convertValue(jwks, java.util.Map.class);
    }

    static boolean empty(JsonNode payload) {
        return payload == null || payload.isNull() || (payload.isObject() && payload.isEmpty());
    }

    static String digest(SecretProtector secrets, IdentityControlRequest.Action action, JsonNode payload,
                         String canonicalPayload) {
        return switch (action) {
            case ROTATE_APPLICATION_CLIENT_SECRET -> OperatorSuppliedClientSecrets.payloadHash(payload, canonicalPayload);
            case ROTATE_IDENTITY_SOURCE_SECRET -> secrets.keyedDigest(DIGEST_PURPOSE, canonicalPayload);
            default -> sha256(canonicalPayload);
        };
    }

    static boolean matches(SecretProtector secrets, IdentityControlRequest.Action action, JsonNode payload,
                           String canonicalPayload, String storedDigest) {
        if (storedDigest == null) return false;
        return MessageDigest.isEqual(digest(secrets, action, payload, canonicalPayload).getBytes(StandardCharsets.US_ASCII),
                storedDigest.getBytes(StandardCharsets.US_ASCII));
    }

    private static String sha256(String value) {
        try {
            return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 unavailable", ex);
        }
    }
}
