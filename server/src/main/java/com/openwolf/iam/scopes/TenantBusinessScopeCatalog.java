package com.openwolf.iam.scopes;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/** Durable per-tenant scope vocabulary (table {@code tenant_business_scopes}, V41). Reads are live: no cache. */
@Repository
public class TenantBusinessScopeCatalog {
    public record Entry(UUID id, String tenantId, String scope, String description, String createdBy, Instant createdAt) {}

    private final JdbcTemplate jdbc;

    public TenantBusinessScopeCatalog(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public boolean contains(String tenantId, String scope) {
        Integer found = jdbc.queryForObject(
                "SELECT count(*) FROM tenant_business_scopes WHERE tenant_id = ? AND scope = ?", Integer.class, tenantId, scope);
        return found != null && found > 0;
    }

    /** Inserts unless the (tenant, scope) pair exists; the unique constraint decides concurrent races. */
    public boolean insertIfAbsent(String tenantId, String scope, String description, String createdBy) {
        return jdbc.update("INSERT INTO tenant_business_scopes (id, tenant_id, scope, description, created_by, created_at) "
                        + "VALUES (?, ?, ?, ?, ?, now()) ON CONFLICT ON CONSTRAINT tenant_business_scopes_unique DO NOTHING",
                UUID.randomUUID(), tenantId, scope, description, createdBy) == 1;
    }

    public Optional<Entry> find(String tenantId, String scope) {
        return jdbc.query("SELECT id, tenant_id, scope, description, created_by, created_at FROM tenant_business_scopes "
                + "WHERE tenant_id = ? AND scope = ?", (row, n) -> entry(row), tenantId, scope).stream().findFirst();
    }

    public List<Entry> list(String tenantId) {
        return jdbc.query("SELECT id, tenant_id, scope, description, created_by, created_at FROM tenant_business_scopes "
                + "WHERE tenant_id = ? ORDER BY scope", (row, n) -> entry(row), tenantId);
    }

    private static Entry entry(java.sql.ResultSet row) throws java.sql.SQLException {
        Timestamp created = row.getTimestamp("created_at");
        return new Entry(UUID.fromString(row.getString("id")), row.getString("tenant_id"), row.getString("scope"),
                row.getString("description"), row.getString("created_by"), created == null ? null : created.toInstant());
    }
}
