package com.openwolf.iam.repository;

import com.openwolf.iam.entity.Group;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface GroupRepository extends JpaRepository<Group, UUID> {

    Optional<Group> findByIdAndTenantId(UUID id, String tenantId);

    List<Group> findByTenantId(String tenantId);

    Optional<Group> findByTenantIdAndName(String tenantId, String name);

    List<Group> findByDomainId(String domainId);

    List<Group> findByTenantIdAndDomainId(String tenantId, String domainId);

    /**
     * Finds all groups that contain the specified principal as a member.
     * Uses a JPQL JOIN on the ManyToMany members collection.
     */
    @Query("SELECT g FROM Group g JOIN g.members m WHERE g.tenantId = :tenantId AND m.id = :principalId")
    List<Group> findByTenantIdAndMemberId(@Param("tenantId") String tenantId, @Param("principalId") String principalId);

    /**
     * Counts members in a group — avoids loading the full member set for the memberCount field.
     */
    @Query("SELECT COUNT(m) FROM Group g JOIN g.members m WHERE g.id = :groupId")
    int countMembersById(@Param("groupId") UUID groupId);
}
