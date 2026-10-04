package com.openwolf.iam.service;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Registered public keys for {@code private_key_jwt} client authentication (RFC 7523 section 2.2, OIDC Core section 9).
 * The key set is stored inline in the client's settings; Axiom never holds the private key. One signing algorithm per
 * client: RS256 for RSA keys (at least 2048 bits) or ES256 for P-256 keys.
 */
public final class ClientAssertionKeys {
    public static final String PRIVATE_KEY_JWT = "private_key_jwt";
    /** Client setting holding the public JWK set (JSON). */
    public static final String SETTING = "settings.client.axiom.jwks";
    private static final int MAX_KEYS = 5;

    public record Registered(String json, SignatureAlgorithm algorithm, List<String> keyIds) {}

    private ClientAssertionKeys() {}

    public static Registered validate(Map<String, Object> jwks) {
        if (jwks == null) throw new IllegalArgumentException("private_key_jwt requires a jwks with at least one public key");
        JWKSet set;
        try {
            set = JWKSet.parse(jwks);
        } catch (java.text.ParseException | RuntimeException malformed) {
            throw new IllegalArgumentException("jwks is not a valid JWK set");
        }
        List<JWK> keys = set.getKeys();
        if (keys.isEmpty() || keys.size() > MAX_KEYS) {
            throw new IllegalArgumentException("jwks must contain between 1 and " + MAX_KEYS + " keys");
        }
        SignatureAlgorithm algorithm = null;
        Set<String> ids = new HashSet<>();
        for (JWK key : keys) {
            if (key.isPrivate()) throw new IllegalArgumentException("jwks must contain public keys only");
            if (key.getKeyID() == null || key.getKeyID().isBlank() || !ids.add(key.getKeyID())) {
                throw new IllegalArgumentException("every key needs a unique kid");
            }
            if (key.getKeyUse() != null && !KeyUse.SIGNATURE.equals(key.getKeyUse())) {
                throw new IllegalArgumentException("keys must be signature keys");
            }
            SignatureAlgorithm keyAlgorithm;
            if (key instanceof RSAKey rsa) {
                if (rsa.size() < 2048) throw new IllegalArgumentException("RSA keys must be at least 2048 bits");
                keyAlgorithm = SignatureAlgorithm.RS256;
            } else if (key instanceof ECKey ec && Curve.P_256.equals(ec.getCurve())) {
                keyAlgorithm = SignatureAlgorithm.ES256;
            } else {
                throw new IllegalArgumentException("only RSA (RS256) and P-256 (ES256) keys are supported");
            }
            if (key.getAlgorithm() != null && !keyAlgorithm.getName().equals(key.getAlgorithm().getName())) {
                throw new IllegalArgumentException("a key's alg must match its type");
            }
            if (algorithm != null && algorithm != keyAlgorithm) {
                throw new IllegalArgumentException("all keys of one client must use the same algorithm");
            }
            algorithm = keyAlgorithm;
        }
        JWKSet publicSet = set.toPublicJWKSet();
        return new Registered(publicSet.toString(true), algorithm,
                publicSet.getKeys().stream().map(JWK::getKeyID).sorted().toList());
    }

    public static JWKSet keys(RegisteredClient client) {
        Object json = client.getClientSettings().getSetting(SETTING);
        if (!(json instanceof String text) || text.isBlank()) return null;
        try {
            return JWKSet.parse(text);
        } catch (java.text.ParseException malformed) {
            return null;
        }
    }

    public static List<String> keyIds(RegisteredClient client) {
        JWKSet set = keys(client);
        return set == null ? List.of() : set.getKeys().stream().map(JWK::getKeyID).sorted().toList();
    }
}
