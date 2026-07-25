package com.openwolf.iam.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;

/**
 * The minimal IAM OAuth locator cannot leak or cross tenants (Axiom A3.5).
 *
 * <p>{@code findByToken} starts with only an opaque token, so it follows the locator
 * {@code iam:oauth2:token:{sha256(token)} → {tenant, authorizationId}} to the tenant-qualified
 * record {@code iam:t:{tenant}:oauth2:authorization:{id}} and verifies the record's tenant before
 * returning. These tests pin that the locator carries no payload, resolves only to the named
 * tenant-qualified record, and yields nothing when the tenant or id is tampered.
 */
class IamOAuthLocatorIsolationTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String TOKEN = "opaque-access-token-value";

    @SuppressWarnings("unchecked")
    private final RedisOperations<String, OAuth2Authorization> authRedis = mock(RedisOperations.class);
    @SuppressWarnings("unchecked")
    private final ValueOperations<String, OAuth2Authorization> authOps = mock(ValueOperations.class);
    private final StringRedisTemplate stringRedis = mock(StringRedisTemplate.class);
    @SuppressWarnings("unchecked")
    private final ValueOperations<String, String> strOps = mock(ValueOperations.class);
    private final AuthorizationTenantResolver tenantResolver = mock(AuthorizationTenantResolver.class);

    private RedisOAuth2AuthorizationService service;

    @BeforeEach
    void setUp() {
        when(authRedis.opsForValue()).thenReturn(authOps);
        when(stringRedis.opsForValue()).thenReturn(strOps);
        service = new RedisOAuth2AuthorizationService(authRedis, stringRedis, "iam:oauth2", "tenant_id", tenantResolver);
    }

    // ── helpers ─────────────────────────────────────────────────────────────────────────────────

    private static OAuth2Authorization authorization(String id, String tenant) {
        RegisteredClient client = RegisteredClient.withId("client-1")
                .clientId("conduit-chat")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost/cb")
                .scope("openid")
                .build();
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER, TOKEN,
                Instant.now(), Instant.now().plus(Duration.ofMinutes(5)));
        return OAuth2Authorization.withRegisteredClient(client)
                .id(id)
                .principalName("alice")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .token(accessToken, meta ->
                        meta.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, Map.of("tenant_id", tenant)))
                .build();
    }

    private String recordKey(String tenant, String id) {
        return "iam:t:" + tenant + ":oauth2:authorization:" + id;
    }

    private String locatorJson(String tenant, String id) {
        return "{\"tenant\":\"" + tenant + "\",\"authorizationId\":\"" + id + "\"}";
    }

    // ── A3.5 tests ──────────────────────────────────────────────────────────────────────────────

    @Test
    void locatorResolvesOnlyToTheNamedTenantQualifiedRecord() {
        when(strOps.get(anyString())).thenReturn(locatorJson("tenant-a", "auth-1"));
        when(authOps.get(recordKey("tenant-a", "auth-1"))).thenReturn(authorization("auth-1", "tenant-a"));

        OAuth2Authorization found = service.findByToken(TOKEN, OAuth2TokenType.ACCESS_TOKEN);

        assertThat(found).isNotNull();
        assertThat(found.getId()).isEqualTo("auth-1");
        // It read the tenant-qualified record key, not a bare id key.
        verify(authOps).get(recordKey("tenant-a", "auth-1"));
    }

    @Test
    void tamperingTheTenantInTheLocatorYieldsNothing() {
        // Locator points at tenant-b, but only tenant-a's record exists.
        when(strOps.get(anyString())).thenReturn(locatorJson("tenant-b", "auth-1"));
        when(authOps.get(recordKey("tenant-b", "auth-1"))).thenReturn(null);
        when(authOps.get(recordKey("tenant-a", "auth-1"))).thenReturn(authorization("auth-1", "tenant-a"));

        assertThat(service.findByToken(TOKEN, OAuth2TokenType.ACCESS_TOKEN)).isNull();
    }

    @Test
    void tamperingTheIdInTheLocatorYieldsNothing() {
        when(strOps.get(anyString())).thenReturn(locatorJson("tenant-a", "auth-999"));
        when(authOps.get(recordKey("tenant-a", "auth-999"))).thenReturn(null);

        assertThat(service.findByToken(TOKEN, OAuth2TokenType.ACCESS_TOKEN)).isNull();
    }

    @Test
    void aLocatorPointingAtAMismatchedTenantRecordIsRefused() {
        // A planted record sits under the tenant-b key but actually belongs to tenant-a (its claim).
        // The stored-tenant verification catches the disagreement and refuses.
        when(strOps.get(anyString())).thenReturn(locatorJson("tenant-b", "auth-1"));
        when(authOps.get(recordKey("tenant-b", "auth-1"))).thenReturn(authorization("auth-1", "tenant-a"));

        assertThat(service.findByToken(TOKEN, OAuth2TokenType.ACCESS_TOKEN)).isNull();
    }

    @Test
    void anAbsentLocatorYieldsNothing() {
        when(strOps.get(anyString())).thenReturn(null);

        assertThat(service.findByToken(TOKEN, OAuth2TokenType.ACCESS_TOKEN)).isNull();
    }

    @Test
    void theLocatorHasNoPayload_onlyTenantAndAuthorizationId() throws Exception {
        // No existing record on save.
        when(authOps.get(anyString())).thenReturn(null);

        service.save(authorization("auth-1", "tenant-a"));

        // The record is written at the tenant-qualified key.
        verify(authOps).set(eq(recordKey("tenant-a", "auth-1")), any(), any(Duration.class));

        // Capture the locator value written for the access token and prove it is coordinates only.
        ArgumentCaptor<String> value = ArgumentCaptor.forClass(String.class);
        verify(strOps, org.mockito.Mockito.times(2)).set(anyString(), value.capture(), any(Duration.class));

        String locator = value.getAllValues().stream()
                .filter(candidate -> candidate.contains("\"tenant\""))
                .findFirst()
                .orElseThrow();
        JsonNode node = JSON.readTree(locator);
        assertThat(node.fieldNames()).toIterable().containsExactlyInAnyOrder("tenant", "authorizationId");
        assertThat(node.get("tenant").asText()).isEqualTo("tenant-a");
        assertThat(node.get("authorizationId").asText()).isEqualTo("auth-1");
        // No token material, roles, claims, scopes, or principal leaked into the locator.
        assertThat(locator)
                .doesNotContain(TOKEN)
                .doesNotContain("roles")
                .doesNotContain("claims")
                .doesNotContain("scope")
                .doesNotContain("alice");
    }

    @Test
    void byIdUsesOnlyTheHashedAuthorizationLocator() {
        when(strOps.get(anyString())).thenReturn(locatorJson("tenant-a", "auth-1"));
        when(authOps.get(recordKey("tenant-a", "auth-1"))).thenReturn(authorization("auth-1", "tenant-a"));

        assertThat(service.findById("auth-1")).isNotNull();
        verify(authOps).get(recordKey("tenant-a", "auth-1"));
    }
}
