package com.openwolf.iam.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Entity
@Table(name = "tenant_application_roles")
public class TenantApplicationRole {
    @Id private UUID id;
    @Column(name = "application_id", nullable = false) private UUID applicationId;
    @Column(name = "role_key", nullable = false) private String roleKey;
    @Column(name = "display_name", nullable = false) private String displayName;
    private String description;
    @JdbcTypeCode(SqlTypes.JSON) @Column(nullable = false, columnDefinition = "jsonb")
    private List<String> permissions = new ArrayList<>();
    @JdbcTypeCode(SqlTypes.JSON) @Column(name = "permission_effects", nullable = false, columnDefinition = "jsonb")
    private Map<String, String> permissionEffects = new LinkedHashMap<>();
    @Column(name = "created_at", nullable = false) private Instant createdAt;
    @Column(name = "updated_at", nullable = false) private Instant updatedAt;

    protected TenantApplicationRole() {}

    public TenantApplicationRole(UUID applicationId, String roleKey, String displayName,
                                 String description, List<String> permissions) {
        this(applicationId, roleKey, displayName, description, permissions, defaultEffects(permissions));
    }
    public TenantApplicationRole(UUID applicationId, String roleKey, String displayName,
                                 String description, List<String> permissions, Map<String, String> permissionEffects) {
        this.id = UUID.randomUUID();
        this.applicationId = applicationId;
        this.roleKey = roleKey;
        this.displayName = displayName;
        this.description = description;
        this.permissions = new ArrayList<>(permissions);
        this.permissionEffects = new LinkedHashMap<>(permissionEffects);
        this.createdAt = Instant.now();
        this.updatedAt = createdAt;
    }

    public UUID getId() { return id; }
    public UUID getApplicationId() { return applicationId; }
    public String getRoleKey() { return roleKey; }
    public String getDisplayName() { return displayName; }
    public String getDescription() { return description; }
    public List<String> getPermissions() { return List.copyOf(permissions); }
    public Map<String, String> getPermissionEffects() { return Map.copyOf(permissionEffects); }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }

    public void update(String displayName, String description, List<String> permissions,
                       Map<String, String> permissionEffects) {
        this.displayName = displayName;
        this.description = description;
        this.permissions = new ArrayList<>(permissions);
        this.permissionEffects = new LinkedHashMap<>(permissionEffects);
        this.updatedAt = Instant.now();
    }

    private static Map<String, String> defaultEffects(List<String> permissions) {
        Map<String, String> effects = new LinkedHashMap<>();
        permissions.forEach(permission -> effects.put(permission, "allow"));
        return effects;
    }
}
