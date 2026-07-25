package com.openwolf.iam.entity;

import jakarta.persistence.Embeddable;

import java.io.Serializable;
import java.util.Objects;
import java.util.UUID;

@Embeddable
public final class PrincipalRoleAssignmentId implements Serializable {
    private String principalId;
    private UUID roleId;

    protected PrincipalRoleAssignmentId() {}

    public PrincipalRoleAssignmentId(String principalId, UUID roleId) {
        this.principalId = principalId;
        this.roleId = roleId;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof PrincipalRoleAssignmentId that
                && Objects.equals(principalId, that.principalId)
                && Objects.equals(roleId, that.roleId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(principalId, roleId);
    }
}
