package com.openwolf.iam.repository;

import com.openwolf.iam.entity.Principal;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface PrincipalRepository extends JpaRepository<Principal, String> {

    Optional<Principal> findByUsername(String username);

    Optional<Principal> findByIdAndTenantId(String id, String tenantId);

    List<Principal> findByTenantId(String tenantId);

    Page<Principal> findByTenantId(String tenantId, Pageable pageable);

    List<Principal> findByTenantIdAndIsActiveTrue(String tenantId);

    /**
     * Finds principals whose canonical domain union contains the exact domain: an
     * {@code admin_domains} array element or a {@code segments} array element/map key,
     * and who is active for live subject context.
     */
    @Query(value = """
            SELECT * FROM principals
            WHERE tenant_id = :tenantId
              AND is_active = true
              AND (jsonb_exists(COALESCE(attributes -> 'admin_domains', '[]'::jsonb), :domain)
                   OR jsonb_exists(COALESCE(attributes -> 'segments', '[]'::jsonb), :domain))
            """, nativeQuery = true)
    List<Principal> findByTenantIdAndCanonicalDomain(@Param("tenantId") String tenantId,
                                                      @Param("domain") String domain);

    /**
     * Find all principals whose password_hash equals the given placeholder (used by DataSeeder).
     */
    @Query("SELECT p FROM Principal p WHERE p.passwordHash = :placeholder")
    List<Principal> findByPasswordHashPlaceholder(@Param("placeholder") String placeholder);
}
