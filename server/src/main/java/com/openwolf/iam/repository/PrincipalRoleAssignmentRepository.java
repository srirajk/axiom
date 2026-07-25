package com.openwolf.iam.repository;

import com.openwolf.iam.entity.PrincipalRoleAssignment;
import com.openwolf.iam.entity.PrincipalRoleAssignmentId;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PrincipalRoleAssignmentRepository extends JpaRepository<PrincipalRoleAssignment, PrincipalRoleAssignmentId> {
}
