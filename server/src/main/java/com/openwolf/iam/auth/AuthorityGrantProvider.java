package com.openwolf.iam.auth;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.web.authentication.AuthenticationConverter;

/**
 * A Phase 3 token-endpoint extension grant (standing-grant redemption, approved-action redemption, workload
 * federation). The authorization server registers each one's converter and provider; a converter returns null for
 * any other {@code grant_type}, so existing grants are unaffected.
 */
public interface AuthorityGrantProvider extends AuthenticationProvider {
    String grantType();

    AuthenticationConverter converter();
}
