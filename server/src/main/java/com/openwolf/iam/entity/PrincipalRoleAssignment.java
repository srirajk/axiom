package com.openwolf.iam.entity;

import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.MapsId;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;

/** A tenant-qualified role assignment; the join row is never inferred by Hibernate. */
@Entity
@Table(name = "principal_roles")
public final class PrincipalRoleAssignment {

    @EmbeddedId
    private PrincipalRoleAssignmentId id;

    @ManyToOne(optional = false)
    @MapsId("principalId")
    @JoinColumn(name = "principal_id", nullable = false)
    private Principal principal;

    @ManyToOne(optional = false)
    @MapsId("roleId")
    @JoinColumn(name = "role_id", nullable = false)
    private Role role;

    @Column(name = "tenant_id", nullable = false)
    private String tenantId;

    protected PrincipalRoleAssignment() {}

    public PrincipalRoleAssignment(Principal principal, Role role) {
        this.id = new PrincipalRoleAssignmentId(principal.getId(), role.getId());
        this.principal = principal;
        this.role = role;
        this.tenantId = principal.getTenantId();
        validateTenantBoundary();
    }

    public Role getRole() { return role; }

    @PrePersist
    void validateTenantBoundary() {
        if (principal == null || role == null || tenantId == null
                || !tenantId.equals(principal.getTenantId()) || !tenantId.equals(role.getTenantId())) {
            throw new IllegalStateException("principal role assignment must remain within one tenant");
        }
    }
}
