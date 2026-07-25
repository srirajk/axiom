package com.openwolf.iam.policystudio.api;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Minimal security for the studio @WebMvcTest slices: it enables {@code @PreAuthorize} method security
 * (the gate under test) and permits all requests at the filter level, so the authenticated principal is
 * supplied purely by the {@code jwt()} request post-processor in each test. This deliberately does NOT
 * load the production {@code SecurityConfig} (which needs a {@code JwtDecoder}/issuer) — the tests target
 * the method-level role gate and tenant derivation, not the resource-server wiring.
 */
@TestConfiguration
@EnableMethodSecurity
class StudioTestSecurityConfig {

    @Bean
    SecurityFilterChain testFilterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        return http.build();
    }
}
