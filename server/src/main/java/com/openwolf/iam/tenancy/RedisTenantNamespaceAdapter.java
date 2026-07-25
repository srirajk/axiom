package com.openwolf.iam.tenancy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

/** Production Redis-backed tenant namespace and routing-index marker. */
@Component
public class RedisTenantNamespaceAdapter implements TenantNamespaceAdapter {

    private static final Logger log = LoggerFactory.getLogger(RedisTenantNamespaceAdapter.class);
    private static final Pattern CANONICAL_TENANT_ID = Pattern.compile("[a-z0-9][a-z0-9-]{0,62}");

    private final StringRedisTemplate redis;
    private final String keyPrefix;

    public RedisTenantNamespaceAdapter(
            StringRedisTemplate redis,
            @Value("${axiom.redis.tenant-namespace-prefix:axiom:tenant:}") String keyPrefix) {
        this.redis = redis;
        this.keyPrefix = normalizePrefix(keyPrefix);
    }

    @Override
    public String createNamespace(String tenantId) {
        requireCanonical(tenantId);
        try {
            redis.opsForValue().set(namespaceKey(tenantId), "active");
            redis.opsForValue().set(indexKey(tenantId), "active");
            log.info("Provisioned Redis namespace '{}' + index '{}' for tenant '{}'",
                    namespaceKey(tenantId), indexKey(tenantId), tenantId);
            return namespaceKey(tenantId);
        } catch (RuntimeException ex) {
            throw unavailable("create", tenantId, ex);
        }
    }

    @Override
    public boolean namespaceExists(String tenantId) {
        requireCanonical(tenantId);
        try {
            Boolean namespace = redis.hasKey(namespaceKey(tenantId));
            Boolean index = redis.hasKey(indexKey(tenantId));
            return Boolean.TRUE.equals(namespace) && Boolean.TRUE.equals(index);
        } catch (RuntimeException ex) {
            // A Redis outage is not an absent namespace: treating it as absent would allow a
            // fail-open activation decision. Surface it as a provisioning failure instead.
            throw unavailable("verify", tenantId, ex);
        }
    }

    @Override
    public void removeNamespace(String tenantId) {
        requireCanonical(tenantId);
        try {
            redis.delete(namespaceKey(tenantId));
            redis.delete(indexKey(tenantId));
            log.info("Removed Redis namespace '{}' + index '{}' for deprovisioned tenant '{}'",
                    namespaceKey(tenantId), indexKey(tenantId), tenantId);
        } catch (RuntimeException ex) {
            throw unavailable("remove", tenantId, ex);
        }
    }

    String namespaceKey(String tenantId) { return keyPrefix + tenantId + ":namespace"; }

    String indexKey(String tenantId) { return keyPrefix + tenantId + ":index"; }

    private ProvisioningException unavailable(String operation, String tenantId, RuntimeException cause) {
        return new ProvisioningException("Redis namespace " + operation + " unavailable for tenant '"
                + tenantId + "' — refusing to continue", cause);
    }

    private static String normalizePrefix(String value) {
        if (value == null || value.isBlank()) return "axiom:tenant:";
        return value.endsWith(":") ? value : value + ":";
    }

    private static void requireCanonical(String tenantId) {
        if (tenantId == null || !CANONICAL_TENANT_ID.matcher(tenantId).matches()) {
            throw new ProvisioningException("illegal tenant id for namespace: " + tenantId);
        }
    }
}
