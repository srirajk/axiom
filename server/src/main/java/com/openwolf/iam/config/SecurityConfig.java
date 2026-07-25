package com.openwolf.iam.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import com.openwolf.iam.auth.AxiomApiJwtValidator;
import com.openwolf.iam.auth.ApplicationScopes;
import com.openwolf.iam.auth.ApplicationSubjectContextJwtValidator;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import com.openwolf.iam.federation.FederatedAuthenticationFailureHandler;
import com.openwolf.iam.federation.FederatedOidcUserService;
import com.openwolf.iam.federation.FederatedAuthorizationCodeAccessTokenResponseClient;
import com.openwolf.iam.scim.ScimAuthenticationFilter;
import com.openwolf.iam.service.SigningKeyLifecycleService;
import com.openwolf.iam.service.IamSessionService;
import com.openwolf.iam.auth.SessionTokenValidator;
import com.openwolf.iam.auth.RecoveryScopeFilter;
import com.openwolf.iam.auth.SessionAwareIntrospectionAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.sql.DataSource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.List;
import java.util.LinkedHashSet;
import java.util.Collection;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Primary;

/**
 * Security configuration for the IAM service.
 * <p>
 * Two filter chains:
 * <ol>
 *   <li>Order 1 — Spring Authorization Server: handles /oauth/authorize, /oauth/token,
 *       /.well-known/openid-configuration, /oauth2/jwks, OIDC userinfo.</li>
 *   <li>Order 2 — Resource server + API: protects /users/**, /roles/**, /admin/**, etc.
 *       via JWT bearer tokens.</li>
 * </ol>
 * </p>
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    @Value("${spring.security.oauth2.authorizationserver.issuer:http://localhost:8084}")
    private String issuerUrl;

    // Persistent location of the RSA signing key (full JWK JSON, incl. private params + stable kid).
    // The key is loaded if present, else generated once and written here. Persisting it means the
    // signing key + its kid survive restarts, so live sessions are not invalidated on every restart.
    @Value("${iam.signing-key-path:/app/keys/signing-key.json}")
    private String signingKeyPath;

    /** Key creation is restricted to the explicit one-shot bootstrap/development mode. */
    @Value("${iam.signing-key-allow-generation:false}")
    private boolean signingKeyAllowGeneration;

    // Standalone bootstrap permits only Axiom Admin. Ordinary applications add their browser
    // origins alongside their persisted client registration at deployment time.
    @Value("${iam.cors.allowed-origins:http://localhost:5180,http://localhost:5173}")
    private List<String> corsAllowedOrigins;

    @Value("${iam.oauth2.axiom-admin.redirect-uri:http://localhost:5180/callback}")
    private String axiomAdminRedirectUri;

    @Value("${iam.oauth2.axiom-admin.post-logout-redirect-uri:http://localhost:5180/login}")
    private String axiomAdminPostLogoutRedirectUri;

    private final S256PkceEnforcementFilter s256PkceEnforcementFilter;
    private final FederatedOidcUserService federatedOidcUserService;
    private final FederatedAuthenticationFailureHandler federatedAuthenticationFailureHandler;
    private final FederatedAuthorizationCodeAccessTokenResponseClient federatedTokenClient;
    private final ScimAuthenticationFilter scimAuthenticationFilter;
    private final SigningKeyLifecycleService signingKeyLifecycleService;
    private final IamSessionService iamSessions;

    @Autowired
    public SecurityConfig(S256PkceEnforcementFilter s256PkceEnforcementFilter,
                          FederatedOidcUserService federatedOidcUserService,
                          FederatedAuthenticationFailureHandler federatedAuthenticationFailureHandler,
                          FederatedAuthorizationCodeAccessTokenResponseClient federatedTokenClient,
                          ScimAuthenticationFilter scimAuthenticationFilter,
                          SigningKeyLifecycleService signingKeyLifecycleService,
                          IamSessionService iamSessions) {
        this.s256PkceEnforcementFilter = s256PkceEnforcementFilter;
        this.federatedOidcUserService = federatedOidcUserService;
        this.federatedAuthenticationFailureHandler = federatedAuthenticationFailureHandler;
        this.federatedTokenClient = federatedTokenClient;
        this.scimAuthenticationFilter = scimAuthenticationFilter;
        this.signingKeyLifecycleService = signingKeyLifecycleService;
        this.iamSessions = iamSessions;
    }

    /** Minimal constructor retained for the isolated signing-key unit test. */
    public SecurityConfig(S256PkceEnforcementFilter s256PkceEnforcementFilter) {
        this(s256PkceEnforcementFilter, null, null, null, null, null, null);
    }

    /** Compatibility constructor retained for focused filter-chain tests. */
    public SecurityConfig(S256PkceEnforcementFilter s256PkceEnforcementFilter,
                          FederatedOidcUserService federatedOidcUserService,
                          FederatedAuthenticationFailureHandler federatedAuthenticationFailureHandler,
                          FederatedAuthorizationCodeAccessTokenResponseClient federatedTokenClient,
                          ScimAuthenticationFilter scimAuthenticationFilter,
                          SigningKeyLifecycleService signingKeyLifecycleService) {
        this(s256PkceEnforcementFilter, federatedOidcUserService, federatedAuthenticationFailureHandler,
                federatedTokenClient, scimAuthenticationFilter, signingKeyLifecycleService, null);
    }

    // =========================================================
    // Filter Chain 1 — Spring Authorization Server
    // =========================================================

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http, RegisteredClientRepository registeredClients,
            OAuth2AuthorizationService authorizations,
            @Qualifier("jwtDecoder") JwtDecoder localDecoder) throws Exception {
        // Build the authorization server configurer to get its endpoint matcher
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();
        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();
        SessionAwareIntrospectionAuthenticationProvider introspectionProvider =
                new SessionAwareIntrospectionAuthenticationProvider(registeredClients, authorizations, iamSessions, localDecoder);

        // Include /login in this chain so form login is served here, not by the resource-server
        // chain. Static resources (/css/**) are intentionally NOT in this matcher — they fall
        // to Order-2 which permitAll()s them, avoiding the Bearer 401 from the resource server.
        http
            .securityMatcher(authorizationServerMatcher(endpointsMatcher))
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
            .with(authorizationServerConfigurer, configurer -> configurer
                    .oidc(Customizer.withDefaults())
                    .tokenIntrospectionEndpoint(endpoint -> endpoint.authenticationProviders(providers ->
                            providers.add(0, introspectionProvider))))
            .exceptionHandling(exceptions -> exceptions
                    .defaultAuthenticationEntryPointFor(
                            new LoginUrlAuthenticationEntryPoint("/login"),
                            new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                    )
            )
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
            .formLogin(form -> form.loginPage("/login").permitAll())
            .oauth2Login(oauth -> oauth
                    .loginPage("/login")
                    .tokenEndpoint(token -> token.accessTokenResponseClient(federatedTokenClient))
                    .userInfoEndpoint(userInfo -> userInfo.oidcUserService(federatedOidcUserService))
                    .failureHandler(federatedAuthenticationFailureHandler))
            .addFilterBefore(s256PkceEnforcementFilter,
                    org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    static RequestMatcher authorizationServerMatcher(RequestMatcher endpointsMatcher) {
        return new OrRequestMatcher(
                endpointsMatcher,
                new AntPathRequestMatcher("/login"),
                new AntPathRequestMatcher("/login/**"),
                new AntPathRequestMatcher("/oauth2/authorization/**"));
    }

    // =========================================================
    // Filter Chain 2 — stateless source-bound SCIM bearer API
    // =========================================================

    @Bean
    @Order(2)
    public SecurityFilterChain scimSecurityFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher(new AntPathRequestMatcher("/scim/v2/**"))
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .addFilterBefore(scimAuthenticationFilter,
                        org.springframework.security.web.authentication.AnonymousAuthenticationFilter.class);
        return http.build();
    }

    /** The SCIM filter is inserted only into the SCIM Spring Security chain, never globally by Boot. */
    @Bean
    public FilterRegistrationBean<ScimAuthenticationFilter> scimAuthenticationFilterRegistration() {
        FilterRegistrationBean<ScimAuthenticationFilter> registration = new FilterRegistrationBean<>(scimAuthenticationFilter);
        registration.setEnabled(false);
        return registration;
    }

    // Filter Chain 3 — service-only platform-authorization resource endpoints
    // =========================================================

    @Bean
    @Order(3)
    public SecurityFilterChain subjectContextSecurityFilterChain(
            HttpSecurity http,
            @Qualifier("subjectContextJwtDecoder") JwtDecoder subjectContextJwtDecoder) throws Exception {
        http
                .securityMatcher(new AntPathRequestMatcher("/api/v1/platform-authz/**"))
                .csrf(csrf -> csrf.disable())
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .decoder(subjectContextJwtDecoder)
                                .jwtAuthenticationConverter(jwtAuthenticationConverter())));
        return http.build();
    }

    // =========================================================
    // Filter Chain 4 — Resource Server (API endpoints)
    // =========================================================

    @Bean
    @Order(4)
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeHttpRequests(auth -> auth
                        // Public endpoints — no auth needed
                        .requestMatchers(
                                "/health",
                                "/actuator/**",
                                "/.well-known/**",
                                "/oauth2/**",
                                "/oauth/**",
                                "/auth/login",
                                "/auth/token",
                                "/auth/recovery/session",
                                "/login",
                                "/css/**",
                                "/js/**",
                                "/images/**",
                                "/default-ui.css"
                        ).permitAll()
                        // The /admin/** surface — the audit trail and the Cerbos policy lifecycle —
                        // is administrative, not merely authenticated. Before this rule, any principal
                        // holding a valid token (e.g. a limited operator whose only role is
                        // chat_user) could read the entire audit log and create, approve, or deploy
                        // authorization policies, because only UserController and AuthController#impersonate
                        // carried a @PreAuthorize and every other admin route fell through to
                        // anyRequest().authenticated(). Enforced here rather than per-method so a new
                        // @RequestMapping under /admin cannot silently arrive unguarded.
                        // Policy Studio has its own two-person method gates. Let the seeded studio
                        // roles through this coarse /admin shell filter only for the Studio subtree;
                        // non-studio admin routes remain limited to platform/tenant/domain admins.
                        .requestMatchers("/admin/studio/**")
                        .hasAnyRole("platform_admin", "tenant_admin", "domain_admin", "policy_author", "policy_approver")
                        .requestMatchers("/admin/**")
                        .hasAnyRole("platform_admin", "tenant_admin", "domain_admin")

                        // Identity mutation is administrative. Only UserController#listUsers and
                        // AuthController#impersonate carried a guard; every write below fell through
                        // to anyRequest().authenticated(), so a limited operator whose only role
                        // is chat_user could create users, change coverage books, grant resource
                        // access — and, the escalation that matters, assign roles. Verified live:
                        // rm_jane POST /roles, /teams, /domains all returned 400 (body invalid) rather
                        // than 403 (guard) — i.e. the handler ran.
                        //
                        // Ordered most-specific-first; Spring Security takes the first match. Role
                        // assignment is the narrowest gate: granting a role is how a lesser admin
                        // would climb to platform_admin, so it is platform_admin only — a domain_admin
                        // must not be able to make themselves a platform_admin.
                        .requestMatchers(HttpMethod.POST, "/users/*/roles")
                        .hasRole("platform_admin")
                        .requestMatchers(HttpMethod.DELETE, "/users/*/roles/**")
                        .hasRole("platform_admin")

                        // All other user mutations — create, update, delete, change book, grant
                        // resource access. GET /users/{id} stays reachable (a user reads their own
                        // profile); GET /users (list) keeps its method-level @PreAuthorize.
                        .requestMatchers(HttpMethod.POST, "/users/**").hasAnyRole("platform_admin", "tenant_admin", "domain_admin")
                        .requestMatchers(HttpMethod.PUT, "/users/**").hasAnyRole("platform_admin", "tenant_admin", "domain_admin")
                        .requestMatchers(HttpMethod.PATCH, "/users/**").hasAnyRole("platform_admin", "tenant_admin", "domain_admin")
                        .requestMatchers(HttpMethod.DELETE, "/users/**").hasAnyRole("platform_admin", "tenant_admin", "domain_admin")

                        // Org-structure mutation: roles, teams, domains. Reads stay authenticated;
                        // only the writes are gated.
                        .requestMatchers(HttpMethod.POST, "/roles/**", "/teams/**", "/domains/**").hasAnyRole("platform_admin", "tenant_admin", "domain_admin")
                        .requestMatchers(HttpMethod.PUT, "/roles/**", "/teams/**", "/domains/**").hasAnyRole("platform_admin", "tenant_admin", "domain_admin")
                        .requestMatchers(HttpMethod.DELETE, "/roles/**", "/teams/**", "/domains/**").hasAnyRole("platform_admin", "tenant_admin", "domain_admin")

                        // The stats dashboard is an admin surface (admin-ui only).
                        .requestMatchers("/stats").hasAnyRole("platform_admin", "tenant_admin", "domain_admin")

                        // The subject-context contract is machine-only: the dedicated scope is
                        // necessary but the controller also verifies the exact client and binding.
                        .requestMatchers("/api/v1/platform-authz/subject-context")
                        .hasAuthority("SCOPE_" + ApplicationScopes.SUBJECT_CONTEXT_READ)
                        .requestMatchers("/api/v1/platform-authz/decisions")
                        .hasAuthority("SCOPE_" + ApplicationScopes.PLATFORM_AUTHZ_DECIDE)

                        // Everything else requires a valid JWT
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())));
        http.addFilterBefore(new RecoveryScopeFilter(),
                org.springframework.security.web.access.intercept.AuthorizationFilter.class);

        return http.build();
    }

    /**
     * Extract the "roles" claim from JWT and convert to Spring Security ROLE_ authorities.
     * This enables @PreAuthorize("hasRole('platform_admin')") on controllers.
     */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter rolesConverter = new JwtGrantedAuthoritiesConverter();
        rolesConverter.setAuthoritiesClaimName("roles");
        rolesConverter.setAuthorityPrefix("ROLE_");
        JwtGrantedAuthoritiesConverter scopesConverter = new JwtGrantedAuthoritiesConverter();

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            Collection<GrantedAuthority> authorities = new LinkedHashSet<>();
            authorities.addAll(rolesConverter.convert(jwt));
            authorities.addAll(scopesConverter.convert(jwt));
            return authorities;
        });
        return converter;
    }

    // =========================================================
    // CORS
    // =========================================================

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(corsAllowedOrigins);
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    // =========================================================
    // OAuth2 Clients
    // =========================================================

    @Bean
    public RegisteredClientRepository registeredClientRepository(DataSource dataSource) {
        return new JdbcRegisteredClientRepository(new org.springframework.jdbc.core.JdbcTemplate(dataSource));
    }

    @Bean
    public ApplicationRunner registerSystemClients(
            RegisteredClientRepository repository,
            PasswordEncoder passwordEncoder) {
        return ignored -> requiredSystemClients().forEach(client -> {
            RegisteredClient existing = repository.findByClientId(client.getClientId());
            if (existing == null) {
                repository.save(client);
            } else if (!sameRegisteredClient(existing, client, passwordEncoder)) {
                throw new IllegalStateException("persisted system client drift for " + client.getClientId());
            }
        });
    }

    private boolean sameRegisteredClient(
            RegisteredClient actual,
            RegisteredClient expected,
            PasswordEncoder passwordEncoder) {
        boolean common = actual.getId().equals(expected.getId())
                && actual.getClientId().equals(expected.getClientId())
                && actual.getClientAuthenticationMethods().equals(expected.getClientAuthenticationMethods())
                && actual.getAuthorizationGrantTypes().equals(expected.getAuthorizationGrantTypes())
                && actual.getRedirectUris().equals(expected.getRedirectUris())
                && actual.getPostLogoutRedirectUris().equals(expected.getPostLogoutRedirectUris())
                && actual.getScopes().equals(expected.getScopes())
                && actual.getClientSettings().getSettings().equals(expected.getClientSettings().getSettings())
                && actual.getTokenSettings().getSettings().equals(expected.getTokenSettings().getSettings());
        return common && actual.getClientSecret() == null;
    }

    private List<RegisteredClient> requiredSystemClients() {
        // Axiom Admin is the only deployment-owned browser client. Consumer applications and their
        // clients are persisted through TenantApplicationService instead of compiled into Java.
        RegisteredClient axiomAdminClient = RegisteredClient.withId("axiom-admin-client-id")
                .clientId("axiom-admin")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(axiomAdminRedirectUri)
                .postLogoutRedirectUri(axiomAdminPostLogoutRedirectUri)
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope(OidcScopes.EMAIL)
                .scope("roles")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofHours(1))
                        .build())
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(false)
                        .build())
                .build();

        return List.of(axiomAdminClient);
    }

    // =========================================================
    // JWK Source — RSA 2048, persisted (load-or-generate) so kid is stable across restarts
    // =========================================================

    @Bean
    @Primary
    public JWKSource<SecurityContext> jwkSource() {
        if (signingKeyLifecycleService != null) return signingKeyLifecycleService.verificationSource();
        RSAKey rsaKey = loadOrGenerateRsaKey();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    @Qualifier("tokenSigningJwkSource")
    public JWKSource<SecurityContext> tokenSigningJwkSource() {
        if (signingKeyLifecycleService == null) {
            RSAKey rsaKey = loadOrGenerateRsaKey();
            return new ImmutableJWKSet<>(new JWKSet(rsaKey));
        }
        return signingKeyLifecycleService.signingSource();
    }

    /**
     * Load the RSA signing key (with its stable kid) from {@code signingKeyPath} if it exists. A
     * missing key is a startup error in normal runtime; only the explicit bootstrap/development
     * mode may create the first persistent key. This keeps key creation from silently changing
     * issuer identity after an accidental volume loss.
     */
    private RSAKey loadOrGenerateRsaKey() {
        Path path = Path.of(signingKeyPath);
        if (Files.exists(path)) {
            try {
                RSAKey existing = RSAKey.parse(Files.readString(path));
                if (!JWSAlgorithm.RS256.equals(existing.getAlgorithm()) || !KeyUse.SIGNATURE.equals(existing.getKeyUse())) {
                    throw new IllegalStateException("persisted signing key lacks required alg=RS256/use=sig metadata; rotate the key volume deliberately");
                }
                return existing;
            } catch (Exception ex) {
                throw new IllegalStateException("Failed to load RSA signing key from " + path, ex);
            }
        }
        if (!signingKeyAllowGeneration) {
            throw new IllegalStateException("RSA signing key is missing at " + path
                    + "; initialize it through the explicit Axiom bootstrap mode before starting runtime");
        }
        RSAKey generated = generateRsaKey();
        try {
            if (path.getParent() != null) {
                Files.createDirectories(path.getParent());
            }
            Files.writeString(path, generated.toJSONString());
            // Restrict to owner-read/write only (0600) — the file contains the RSA private key.
            // Best-effort: UnsupportedOperationException is thrown on non-POSIX filesystems
            // (e.g. Windows, certain container overlays) and is silently ignored.
            try {
                Files.setPosixFilePermissions(path,
                        PosixFilePermissions.fromString("rw-------"));
            } catch (UnsupportedOperationException ignored) {
                log.warn("Could not restrict signing-key file permissions to 0600 (non-POSIX filesystem): {}", path);
            }
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to persist RSA signing key to " + path, ex);
        }
        return generated;
    }

    private RSAKey generateRsaKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            return new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(UUID.randomUUID().toString())
                    .algorithm(JWSAlgorithm.RS256)
                    .keyUse(KeyUse.SIGNATURE)
                    .build();
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to generate RSA 2048 key pair for JWT signing", ex);
        }
    }

    // =========================================================
    // JWT Encoder (used by /auth/login to issue RS256 tokens)
    // =========================================================

    @Bean
    public JwtEncoder jwtEncoder(@Qualifier("tokenSigningJwkSource") JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    // =========================================================
    // JWT Decoder (for validating tokens on the resource server side)
    // =========================================================

    @Bean
    @Primary
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        NimbusJwtDecoder decoder = decoderFor(jwkSource);
        if (iamSessions == null) {
            decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                    JwtValidators.createDefaultWithIssuer(issuerUrl), new AxiomApiJwtValidator()));
        } else {
            decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                    JwtValidators.createDefaultWithIssuer(issuerUrl), new AxiomApiJwtValidator(),
                    new SessionTokenValidator(iamSessions)));
        }
        return decoder;
    }

    @Bean
    public JwtDecoder subjectContextJwtDecoder(JWKSource<SecurityContext> jwkSource) {
        NimbusJwtDecoder decoder = decoderFor(jwkSource);
        // Client-credentials grants have no human durable session. Exact active confidential-client,
        // tenant, audience and scope binding is enforced by SubjectContextCaller for every request.
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(issuerUrl), new ApplicationSubjectContextJwtValidator()));
        return decoder;
    }

    private NimbusJwtDecoder decoderFor(JWKSource<SecurityContext> jwkSource) {
        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource));
        processor.setJWSTypeVerifier(
                new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("at+jwt")));
        return new NimbusJwtDecoder(processor);
    }

    // =========================================================
    // Authorization Server Settings
    // =========================================================

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer(issuerUrl)
                // Map to /oauth/* paths to preserve backwards-compatible API paths
                .authorizationEndpoint(S256PkceEnforcementFilter.AUTHORIZATION_ENDPOINT)
                .tokenEndpoint("/oauth/token")
                .tokenIntrospectionEndpoint("/oauth/introspect")
                .tokenRevocationEndpoint("/oauth/revoke")
                .jwkSetEndpoint("/oauth2/jwks")
                .oidcUserInfoEndpoint("/oauth/userinfo")
                .build();
    }

    // =========================================================
    // Password Encoder — BCrypt strength 12
    // =========================================================

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    // =========================================================
    // Authentication Manager (used by /auth/login)
    // =========================================================

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
