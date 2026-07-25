package com.openwolf.iam.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.CascadeType;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * A principal is any authenticated entity in the system (user, service account).
 * <p>
 * Named {@code Principal} to match the domain language. Note: this is NOT
 * {@code java.security.Principal} — that interface is never imported here.
 * </p>
 */
@Entity
@Table(name = "principals")
@EntityListeners(AuditingEntityListener.class)
public class Principal {

    @Id
    private String id;

    @Column(name = "tenant_id", nullable = false)
    private String tenantId;

    @Column(nullable = false, unique = true)
    private String username;

    private String email;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @Column(name = "is_active", nullable = false)
    private boolean isActive = true;

    /**
     * Flexible JSONB attribute bag — stores: classification, segments, clearance,
     * admin_domains, and any future tenant-specific attributes.
     * Parsed in service layer via ObjectMapper.
     */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb", nullable = false)
    private String attributes = "{}";

    @CreatedDate
    @Column(name = "created_at", updatable = false)
    private Instant createdAt;

    @LastModifiedDate
    @Column(name = "updated_at")
    private Instant updatedAt;

    @Column(name = "scim_source_id")
    private UUID scimSourceId;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "scim_managed_fields", nullable = false, columnDefinition = "jsonb")
    private String scimManagedFields = "[]";

    /** Tenant-qualified assignments carry the join-row tenant_id explicitly. */
    @OneToMany(mappedBy = "principal", fetch = FetchType.LAZY, cascade = CascadeType.ALL, orphanRemoval = true)
    private Set<PrincipalRoleAssignment> roleAssignments = new LinkedHashSet<>();

    protected Principal() {}

    public Principal(String id, String tenantId, String username, String email,
                     String passwordHash, boolean isActive, String attributes) {
        this.id = id;
        this.tenantId = tenantId;
        this.username = username;
        this.email = email;
        this.passwordHash = passwordHash;
        this.isActive = isActive;
        this.attributes = attributes;
    }

    // Getters and setters

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getTenantId() { return tenantId; }
    public void setTenantId(String tenantId) { this.tenantId = tenantId; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getPasswordHash() { return passwordHash; }
    public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }

    public boolean isActive() { return isActive; }
    public void setActive(boolean active) { isActive = active; }

    public String getAttributes() { return attributes; }
    public void setAttributes(String attributes) { this.attributes = attributes; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }

    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
    public UUID getScimSourceId() { return scimSourceId; }
    public void setScimSourceId(UUID scimSourceId) { this.scimSourceId = scimSourceId; }
    public String getScimManagedFields() { return scimManagedFields; }
    public void setScimManagedFields(String scimManagedFields) { this.scimManagedFields = scimManagedFields; }

    public Set<Role> getRoles() {
        Set<Role> roles = new LinkedHashSet<>();
        for (PrincipalRoleAssignment assignment : roleAssignments) roles.add(assignment.getRole());
        return roles;
    }

    public void assignRole(Role role) {
        if (!tenantId.equals(role.getTenantId())) {
            throw new IllegalArgumentException("principal and role must belong to the same tenant");
        }
        if (!getRoles().contains(role)) roleAssignments.add(new PrincipalRoleAssignment(this, role));
    }

    public void revokeRole(Role role) {
        roleAssignments.removeIf(assignment -> assignment.getRole().equals(role));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Principal)) return false;
        Principal principal = (Principal) o;
        return Objects.equals(id, principal.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
