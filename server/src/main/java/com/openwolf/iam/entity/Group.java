package com.openwolf.iam.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * A group represents either a team (organisational unit) or a domain (business capability area).
 * The {@code domainId} field identifies the business domain this group belongs to.
 * <p>
 * Table name is {@code groups} — a non-reserved PostgreSQL keyword.
 * </p>
 */
@Entity
@Table(name = "groups")
@EntityListeners(AuditingEntityListener.class)
public class Group {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private String tenantId;

    @Column(nullable = false)
    private String name;

    @Column(name = "domain_id")
    private String domainId;

    private String description;

    /**
     * Flexible JSONB metadata: defaultRoles, segments, allowedDomains, relationships.
     */
    @Column(columnDefinition = "jsonb", nullable = false)
    @JdbcTypeCode(SqlTypes.JSON)
    private String metadata = "{}";

    @CreatedDate
    @Column(name = "created_at", updatable = false)
    private Instant createdAt;

    @Column(name = "scim_source_id")
    private UUID scimSourceId;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "scim_managed_fields", nullable = false, columnDefinition = "jsonb")
    private String scimManagedFields = "[]";

    /**
     * Group members — principals assigned to this group.
     * LAZY — only fetched when accessed within a transaction.
     */
    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "group_members",
            joinColumns = @JoinColumn(name = "group_id"),
            inverseJoinColumns = @JoinColumn(name = "principal_id")
    )
    private Set<Principal> members = new HashSet<>();

    protected Group() {}

    public Group(String tenantId, String name, String domainId, String description, String metadata) {
        this.tenantId = tenantId;
        this.name = name;
        this.domainId = domainId;
        this.description = description;
        this.metadata = metadata != null ? metadata : "{}";
    }

    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public String getTenantId() { return tenantId; }
    public void setTenantId(String tenantId) { this.tenantId = tenantId; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getDomainId() { return domainId; }
    public void setDomainId(String domainId) { this.domainId = domainId; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getMetadata() { return metadata; }
    public void setMetadata(String metadata) { this.metadata = metadata; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public UUID getScimSourceId() { return scimSourceId; }
    public void setScimSourceId(UUID scimSourceId) { this.scimSourceId = scimSourceId; }
    public String getScimManagedFields() { return scimManagedFields; }
    public void setScimManagedFields(String scimManagedFields) { this.scimManagedFields = scimManagedFields; }

    public Set<Principal> getMembers() { return members; }
    public void setMembers(Set<Principal> members) { this.members = members; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Group)) return false;
        Group group = (Group) o;
        return Objects.equals(id, group.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
