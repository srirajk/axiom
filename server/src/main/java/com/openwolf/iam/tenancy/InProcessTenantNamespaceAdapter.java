package com.openwolf.iam.tenancy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Single-instance stand-in for the Redis-namespace artifact (Axiom B4). This implementation performs
 * the orchestration and idempotency-tracking half in process so the provision flow (staging, retry
 * reconciliation, cleanup ordering) is real and testable; the name grammar is stable for Axiom consumers.
 */
public class InProcessTenantNamespaceAdapter implements TenantNamespaceAdapter {

    private static final Logger log = LoggerFactory.getLogger(InProcessTenantNamespaceAdapter.class);
    private static final Pattern CANONICAL_TENANT_ID = Pattern.compile("[a-z0-9][a-z0-9-]{0,62}");

    private final Set<String> created = ConcurrentHashMap.newKeySet();

    @Override
    public String createNamespace(String tenantId) {
        requireCanonical(tenantId);
        String prefix = keyPrefix(tenantId);
        created.add(tenantId); // idempotent
        log.info("Provisioned Redis namespace '{}' + index '{}' for tenant '{}' "
                        + "(in-process; the durable Redis adapter is the deployment seam)",
                prefix, indexName(tenantId), tenantId);
        return prefix;
    }

    @Override
    public boolean namespaceExists(String tenantId) {
        return created.contains(tenantId);
    }

    @Override
    public void removeNamespace(String tenantId) {
        created.remove(tenantId);
        log.info("Removed Redis namespace '{}' + index '{}' for deprovisioned tenant '{}'",
                keyPrefix(tenantId), indexName(tenantId), tenantId);
    }

    /** {@code t:{tenant}:} — the Axiom tenant key prefix. */
    static String keyPrefix(String tenantId) {
        return "t:" + tenantId + ":";
    }

    /** {@code intent_idx__{tenant}} — the Axiom per-tenant index name. */
    static String indexName(String tenantId) {
        return "intent_idx__" + tenantId;
    }

    private static void requireCanonical(String tenantId) {
        if (tenantId == null || !CANONICAL_TENANT_ID.matcher(tenantId).matches()) {
            throw new ProvisioningException("illegal tenant id for namespace: " + tenantId);
        }
    }
}
