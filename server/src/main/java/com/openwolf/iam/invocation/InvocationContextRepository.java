package com.openwolf.iam.invocation;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface InvocationContextRepository extends JpaRepository<InvocationContext, UUID> {

    Optional<InvocationContext> findByIdAndTenantId(UUID id, String tenantId);

    Optional<InvocationContext> findByTenantIdAndBrokerClientIdAndIdempotencyKey(String tenantId, String brokerClientId,
                                                                                 String idempotencyKey);

    Optional<InvocationContext> findByTenantIdAndEvidenceDigest(String tenantId, String evidenceDigest);

    Optional<InvocationContext> findByParentIdAndBranchRef(UUID parentId, String branchRef);

    long countByParentId(UUID parentId);

    /** Serializes check-then-insert decisions (idempotency, fan-out and per-session caps) inside one transaction. */
    @Query(value = "SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))", nativeQuery = true)
    Object lock(@Param("key") String key);

    @Query(value = "SELECT count(*) FROM invocation_contexts WHERE tenant_id = :tenant AND parent_id IS NULL "
            + "AND status = 'ACTIVE' AND deadline > :now AND originating_subject = :subject "
            + "AND coalesce(root_session_id, '') = coalesce(:session, '')", nativeQuery = true)
    long countActiveRoots(@Param("tenant") String tenantId, @Param("subject") String subject,
                          @Param("session") String rootSessionId, @Param("now") Instant now);

    /**
     * Ancestor chain, explicitly ordered self first (hop 0), then parent, grandparent ... root. Callers rely on
     * element 0 being the requested context; {@code InvocationContextService} also verifies the shape.
     */
    @Query(value = "WITH RECURSIVE chain(id, parent_id, hop) AS ("
            + "SELECT id, parent_id, 0 FROM invocation_contexts WHERE id = :id AND tenant_id = :tenant "
            + "UNION ALL SELECT p.id, p.parent_id, c.hop + 1 FROM invocation_contexts p JOIN chain c ON p.id = c.parent_id "
            + "WHERE p.tenant_id = :tenant) "
            + "SELECT ic.* FROM chain JOIN invocation_contexts ic ON ic.id = chain.id ORDER BY chain.hop ASC", nativeQuery = true)
    List<InvocationContext> chain(@Param("id") UUID id, @Param("tenant") String tenantId);

    /**
     * Number of non-ACTIVE contexts in the ancestor chain (self included), as a scalar read of current committed rows.
     * Used after taking the root lock: an entity read inside the same transaction could return instances already held
     * in the persistence context with a stale status.
     */
    @Query(value = "WITH RECURSIVE chain(id, parent_id) AS ("
            + "SELECT id, parent_id FROM invocation_contexts WHERE id = :id AND tenant_id = :tenant "
            + "UNION ALL SELECT p.id, p.parent_id FROM invocation_contexts p JOIN chain c ON p.id = c.parent_id "
            + "WHERE p.tenant_id = :tenant) "
            + "SELECT count(*) FROM chain JOIN invocation_contexts ic ON ic.id = chain.id WHERE ic.status <> 'ACTIVE'",
            nativeQuery = true)
    long inactiveInChain(@Param("id") UUID id, @Param("tenant") String tenantId);

    /**
     * Row lock on a root context. Branch creation and every revocation path take it first, so a revocation cascade
     * always runs after (and therefore sees) any branch inserted concurrently, and a branch is never created under a
     * root whose revocation has committed.
     */
    @Query(value = "SELECT CAST(id AS text) FROM invocation_contexts WHERE id = :root AND tenant_id = :tenant "
            + "AND parent_id IS NULL FOR UPDATE", nativeQuery = true)
    Optional<String> lockRoot(@Param("root") UUID rootId, @Param("tenant") String tenantId);

    /** Locks every root of a session in a fixed (id) order before a session-wide revocation. */
    @Query(value = "SELECT CAST(id AS text) FROM invocation_contexts WHERE tenant_id = :tenant AND parent_id IS NULL "
            + "AND root_session_id = :session ORDER BY id FOR UPDATE", nativeQuery = true)
    List<String> lockRootsForSession(@Param("tenant") String tenantId, @Param("session") String rootSessionId);

    /** Locks every root a subject originated in a fixed (id) order before a subject-wide revocation. */
    @Query(value = "SELECT CAST(id AS text) FROM invocation_contexts WHERE tenant_id = :tenant AND parent_id IS NULL "
            + "AND originating_subject = :subject ORDER BY id FOR UPDATE", nativeQuery = true)
    List<String> lockRootsForSubject(@Param("tenant") String tenantId, @Param("subject") String subject);

    /**
     * Revokes a context and every descendant in one statement: status and version change together, and only rows that
     * are still ACTIVE change (a revoked row is never re-activated or re-versioned by a later revoke).
     */
    @Modifying
    @Query(value = "WITH RECURSIVE tree AS (SELECT id FROM invocation_contexts WHERE id = :id AND tenant_id = :tenant "
            + "UNION ALL SELECT c.id FROM invocation_contexts c JOIN tree t ON c.parent_id = t.id) "
            + "UPDATE invocation_contexts SET status = 'REVOKED', version = version + 1, revoked_at = :now, "
            + "revocation_reason = :reason WHERE id IN (SELECT id FROM tree) AND status = 'ACTIVE'", nativeQuery = true)
    int revokeTree(@Param("id") UUID id, @Param("tenant") String tenantId, @Param("reason") String reason,
                   @Param("now") Instant now);

    /**
     * Phase 3.6: cancels a context and every descendant in one statement (status CANCELLED, version moves). Like
     * {@link #revokeTree}, only ACTIVE rows change, so cancellation never re-activates or re-versions an ended row.
     */
    @Modifying
    @Query(value = "WITH RECURSIVE tree AS (SELECT id FROM invocation_contexts WHERE id = :id AND tenant_id = :tenant "
            + "UNION ALL SELECT c.id FROM invocation_contexts c JOIN tree t ON c.parent_id = t.id) "
            + "UPDATE invocation_contexts SET status = 'CANCELLED', version = version + 1, cancelled_at = :now, "
            + "revocation_reason = :reason WHERE id IN (SELECT id FROM tree) AND status = 'ACTIVE'", nativeQuery = true)
    int cancelTree(@Param("id") UUID id, @Param("tenant") String tenantId, @Param("reason") String reason,
                   @Param("now") Instant now);

    @Modifying
    @Query(value = "UPDATE invocation_contexts SET status = 'REVOKED', version = version + 1, revoked_at = :now, "
            + "revocation_reason = :reason WHERE tenant_id = :tenant AND root_session_id = :session AND status = 'ACTIVE'",
            nativeQuery = true)
    int revokeForRootSession(@Param("tenant") String tenantId, @Param("session") String rootSessionId,
                             @Param("reason") String reason, @Param("now") Instant now);

    @Modifying
    @Query(value = "UPDATE invocation_contexts SET status = 'REVOKED', version = version + 1, revoked_at = :now, "
            + "revocation_reason = :reason WHERE tenant_id = :tenant AND originating_subject = :subject "
            + "AND status = 'ACTIVE'", nativeQuery = true)
    int revokeForSubject(@Param("tenant") String tenantId, @Param("subject") String subject,
                         @Param("reason") String reason, @Param("now") Instant now);
}
