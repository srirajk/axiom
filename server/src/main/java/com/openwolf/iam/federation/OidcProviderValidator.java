package com.openwolf.iam.federation;

import com.openwolf.iam.dto.CreateIdentitySourceRequest;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Autowired;

import java.net.URI;
import java.util.List;
import java.util.Set;

@Component
public final class OidcProviderValidator {
    private static final Set<String> SUPPORTED_ALGORITHMS = Set.of("RS256", "PS256", "ES256");
    private static final Set<String> REQUIRED_DISCOVERY_CLAIMS = Set.of("sub", "iss", "aud", "exp", "iat", "nonce");
    private final OidcMetadataFetcher metadataFetcher;
    private final OidcNetworkAddressPolicy networkPolicy;

    public OidcProviderValidator(OidcMetadataFetcher metadataFetcher) {
        this(metadataFetcher, null);
    }

    @Autowired
    public OidcProviderValidator(OidcMetadataFetcher metadataFetcher, OidcNetworkAddressPolicy networkPolicy) {
        this.metadataFetcher = metadataFetcher;
        this.networkPolicy = networkPolicy;
    }

    public ValidatedProvider validate(CreateIdentitySourceRequest request) {
        URI discoveryUri = URI.create(request.discoveryUri());
        HttpOidcMetadataFetcher.requireSafeHttps(discoveryUri);
        validateIssuer(request.issuer());
        OidcMetadata metadata = metadataFetcher.fetch(discoveryUri);
        if (!request.issuer().equals(metadata.issuer())) throw new IllegalArgumentException("OIDC discovery issuer does not exactly match configured issuer");
        validateEndpoint(metadata.authorizationEndpoint(), "authorization endpoint");
        validateEndpoint(metadata.tokenEndpoint(), "token endpoint");
        validateEndpoint(metadata.userinfoEndpoint(), "userinfo endpoint");
        validateEndpoint(metadata.jwksUri(), "JWKS endpoint");
        if (!metadata.idTokenSigningAlgorithms().containsAll(request.allowedSigningAlgorithms())
                || !SUPPORTED_ALGORITHMS.containsAll(request.allowedSigningAlgorithms())) {
            throw new IllegalArgumentException("configured signing algorithms are not supported by the provider");
        }
        if (request.requestedScopes().stream().anyMatch(scope -> !metadata.scopes().isEmpty() && !metadata.scopes().contains(scope))) {
            throw new IllegalArgumentException("requested OIDC scope is not supported by the provider");
        }
        if (!metadata.claims().containsAll(REQUIRED_DISCOVERY_CLAIMS)
                || !metadata.claims().containsAll(request.requiredClaims())) {
            throw new IllegalArgumentException("required OIDC claims are not advertised by the provider");
        }
        if (!request.requiredAcrValues().isEmpty()
                && !metadata.acrValues().containsAll(request.requiredAcrValues())) {
            throw new IllegalArgumentException("required authentication context is not advertised by the provider");
        }
        return new ValidatedProvider(metadata);
    }

    private static void requireExactHttps(String value, String label) {
        URI uri = URI.create(value);
        HttpOidcMetadataFetcher.requireSafeHttps(uri);
        if (!value.equals(uri.toString())) throw new IllegalArgumentException(label + " must be a canonical exact URI");
    }

    private void validateIssuer(String value) {
        URI uri = URI.create(value);
        if (networkPolicy == null) {
            requireExactHttps(value, "issuer");
        } else {
            networkPolicy.validate(uri, "issuer");
        }
        if (!value.equals(uri.toString())) throw new IllegalArgumentException("issuer must be a canonical exact URI");
    }

    private void validateEndpoint(URI uri, String label) {
        if (networkPolicy == null) {
            HttpOidcMetadataFetcher.requireSafeHttps(uri);
            if (uri.getHost() == null) throw new IllegalArgumentException(label + " is invalid");
            return;
        }
        networkPolicy.validate(uri, label);
    }

    public record ValidatedProvider(OidcMetadata metadata) {
        public List<String> signingAlgorithms() { return metadata.idTokenSigningAlgorithms(); }
    }
}
