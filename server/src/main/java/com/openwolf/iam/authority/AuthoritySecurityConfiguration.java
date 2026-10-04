package com.openwolf.iam.authority;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.openwolf.iam.authority.standing.StandingGrantAuthenticationProvider;
import com.openwolf.iam.authority.standing.StandingGrantService;
import com.openwolf.iam.authority.task.DurableTaskService;
import com.openwolf.iam.service.AuditService;
import com.openwolf.iam.service.TenantApplicationService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Duration;

/**
 * Phase 3 wiring: the workload API (client-credentials tokens of confidential clients only), the unauthenticated
 * callback intake (authenticated per request by the callback verifier), and the extension grants.
 */
@Configuration
public class AuthoritySecurityConfiguration {

    @Value("${spring.security.oauth2.authorizationserver.issuer:http://localhost:8084}")
    private String issuerUrl;

    @Bean
    public JwtDecoder workloadApiJwtDecoder(JWKSource<SecurityContext> jwkSource, TenantApplicationService applications) {
        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource));
        processor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("at+jwt")));
        NimbusJwtDecoder decoder = new NimbusJwtDecoder(processor);
        // Client-credentials tokens carry no Axiom session; liveness is the client's current active state, checked
        // on every request (disabling the client stops its workload API access immediately).
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(JwtValidators.createDefaultWithIssuer(issuerUrl),
                new WorkloadClientTokenValidator(applications)));
        return decoder;
    }

    @Bean
    @Order(4)
    public SecurityFilterChain workloadAuthorityFilterChain(
            HttpSecurity http, @Qualifier("workloadApiJwtDecoder") JwtDecoder decoder) throws Exception {
        http.securityMatcher(new AntPathRequestMatcher("/api/v1/workload/**"))
                .csrf(csrf -> csrf.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.decoder(decoder)));
        return http.build();
    }

    /** Callbacks carry no bearer token; each is authenticated by {@code TaskCallbackVerifier} (default: deny). */
    @Bean
    @Order(4)
    public SecurityFilterChain taskCallbackFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher(new AntPathRequestMatcher("/api/v1/callbacks/**"))
                .csrf(csrf -> csrf.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        return http.build();
    }

    @Bean
    public com.openwolf.iam.authority.approval.ApprovedActionAuthenticationProvider approvedActionAuthenticationProvider(
            com.openwolf.iam.authority.approval.ActionApprovalService approvals, TenantApplicationService applications,
            OAuth2AuthorizationService authorizations, JwtEncoder encoder,
            OAuth2TokenCustomizer<JwtEncodingContext> customizer, AuditService audit,
            PlatformTransactionManager transactions,
            @Value("${iam.action-approval.token-ttl:PT5M}") Duration ttl) {
        JwtGenerator generator = new JwtGenerator(encoder);
        generator.setJwtCustomizer(customizer);
        return new com.openwolf.iam.authority.approval.ApprovedActionAuthenticationProvider(approvals, applications,
                new AuthorityTokenIssuer(authorizations, generator), audit, new TransactionTemplate(transactions), ttl);
    }

    @Bean
    public StandingGrantAuthenticationProvider standingGrantAuthenticationProvider(
            StandingGrantService grants, DurableTaskService tasks, TenantApplicationService applications,
            OAuth2AuthorizationService authorizations, JwtEncoder encoder,
            OAuth2TokenCustomizer<JwtEncodingContext> customizer, AuditService audit,
            PlatformTransactionManager transactions,
            @Value("${iam.standing-grant.token-ttl:PT5M}") Duration ttl) {
        JwtGenerator generator = new JwtGenerator(encoder);
        generator.setJwtCustomizer(customizer);
        return new StandingGrantAuthenticationProvider(grants, tasks, applications,
                new AuthorityTokenIssuer(authorizations, generator), audit, new TransactionTemplate(transactions), ttl);
    }
}
