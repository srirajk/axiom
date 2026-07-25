package com.openwolf.iam.policystudio.api;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.util.Arrays;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;

/** Test helpers: build an authenticated principal (subject + tenant_id claim + roles) for MockMvc. */
final class StudioMvc {

    private StudioMvc() {}

    private static GrantedAuthority[] roleAuthorities(String... roles) {
        return Arrays.stream(roles)
                .map(r -> (GrantedAuthority) new SimpleGrantedAuthority("ROLE_" + r))
                .toArray(GrantedAuthority[]::new);
    }

    /** A principal with the given subject id, {@code tenant_id} claim, and roles (no ROLE_ prefix). */
    static RequestPostProcessor principal(String subject, String tenant, String... roles) {
        return jwt()
                .jwt(j -> j.subject(subject).claim("tenant_id", tenant))
                .authorities(roleAuthorities(roles));
    }

    /** A principal with a subject and roles but NO tenant_id claim (for the fail-closed tenant test). */
    static RequestPostProcessor principalNoTenant(String subject, String... roles) {
        return jwt().jwt(j -> j.subject(subject)).authorities(roleAuthorities(roles));
    }
}
