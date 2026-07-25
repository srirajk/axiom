package com.openwolf.iam.federation;

import java.util.List;

/** OIDC audience and authorized-party rules shared by ID-token validation paths. */
public final class OidcAudienceRules {
    private OidcAudienceRules() {
    }

    public static boolean matches(List<String> audiences, String clientId, String authorizedParty) {
        if (audiences == null || clientId == null || !audiences.contains(clientId)) {
            return false;
        }
        if (audiences.size() > 1) {
            return clientId.equals(authorizedParty);
        }
        return authorizedParty == null || authorizedParty.isBlank() || clientId.equals(authorizedParty);
    }
}
