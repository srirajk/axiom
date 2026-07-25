package com.openwolf.iam.federation;

import com.openwolf.iam.dto.CreateIdentitySourceRequest;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThat;

class OidcProviderValidatorTest {
    private static final String ISSUER = "https://idp.example.test";
    private static final OidcMetadata METADATA = new OidcMetadata(ISSUER,
            URI.create(ISSUER + "/authorize"), URI.create(ISSUER + "/token"),
            URI.create(ISSUER + "/userinfo"), URI.create(ISSUER + "/jwks"),
            List.of("RS256"), List.of("openid", "profile", "email"),
            List.of("sub", "iss", "aud", "exp", "iat", "nonce", "email"), List.of("urn:acr:strong"));

    @Test
    void acceptsExactHttpsDiscoveryAndConfiguredSecurityPosture() {
        OidcProviderValidator validator = new OidcProviderValidator(uri -> METADATA);
        var result = validator.validate(request(ISSUER, "https://idp.example.test/.well-known/openid-configuration"));
        assertThat(result.metadata().issuer()).isEqualTo(ISSUER);
    }

    @Test
    void rejectsIssuerMismatchAndUnsafeMetadata() {
        OidcProviderValidator mismatch = new OidcProviderValidator(uri -> METADATA);
        assertThatThrownBy(() -> mismatch.validate(request("https://other.example.test", "https://idp.example.test/.well-known/openid-configuration")))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("issuer");
        OidcProviderValidator unsafe = new OidcProviderValidator(uri -> new OidcMetadata(ISSUER,
                URI.create("http://idp.example.test/authorize"), METADATA.tokenEndpoint(), METADATA.userinfoEndpoint(),
                METADATA.jwksUri(), METADATA.idTokenSigningAlgorithms(), METADATA.scopes(), METADATA.claims(), METADATA.acrValues()));
        assertThatThrownBy(() -> unsafe.validate(request(ISSUER, "https://idp.example.test/.well-known/openid-configuration")))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("HTTPS");
    }

    @Test
    void rejectsUnsupportedAlgorithmClaimAndAcrRequirements() {
        OidcProviderValidator validator = new OidcProviderValidator(uri -> METADATA);
        assertThatThrownBy(() -> validator.validate(new CreateIdentitySourceRequest("IdP", ISSUER,
                "https://idp.example.test/.well-known/openid-configuration", "client", "secret",
                List.of("openid"), List.of("HS256"), List.of("sub", "iss", "aud", "exp", "iat", "nonce"), List.of())))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("algorithms");
        assertThatThrownBy(() -> validator.validate(new CreateIdentitySourceRequest("IdP", ISSUER,
                "https://idp.example.test/.well-known/openid-configuration", "client", "secret",
                List.of("openid"), List.of("RS256"), List.of("sub", "iss", "aud", "exp", "iat", "nonce", "missing"), List.of())))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("claims");
        assertThatThrownBy(() -> validator.validate(new CreateIdentitySourceRequest("IdP", ISSUER,
                "https://idp.example.test/.well-known/openid-configuration", "client", "secret",
                List.of("openid"), List.of("RS256"), List.of("sub", "iss", "aud", "exp", "iat", "nonce"), List.of("urn:acr:missing"))))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("authentication context");
    }

    private static CreateIdentitySourceRequest request(String issuer, String discovery) {
        return new CreateIdentitySourceRequest("Customer IdP", issuer, discovery, "client", "secret",
                List.of("openid", "profile", "email"), List.of("RS256"),
                List.of("sub", "iss", "aud", "exp", "iat", "nonce"), List.of("urn:acr:strong"));
    }
}
