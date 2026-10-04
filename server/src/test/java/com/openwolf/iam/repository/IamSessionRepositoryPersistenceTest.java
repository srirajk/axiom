package com.openwolf.iam.repository;

import com.openwolf.iam.entity.IamSession;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest(properties = "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect")
@ActiveProfiles("test")
class IamSessionRepositoryPersistenceTest {
    private static final String TENANT = "tenant-a";
    private static final Instant NOW = Instant.parse("2026-07-25T12:00:00Z");

    @Autowired
    private IamSessionRepository sessions;

    @Autowired
    private EntityManager entityManager;

    @Test
    void touchCoalescesRecentWritesAndNeverTouchesRevokedSession() {
        IamSession session = new IamSession(UUID.randomUUID(), TENANT, "user-1", null,
                "browser-client", NOW, NOW.plusSeconds(600));
        sessions.saveAndFlush(session);
        entityManager.clear();

        assertThat(sessions.touch(session.getId(), TENANT, NOW.plusSeconds(20),
                IamSession.Status.ACTIVE, NOW.minusSeconds(10))).isZero();
        assertThat(sessions.touch(session.getId(), TENANT, NOW.plusSeconds(31),
                IamSession.Status.ACTIVE, NOW.plusSeconds(1))).isEqualTo(1);
        entityManager.clear();
        IamSession updated = sessions.findById(session.getId()).orElseThrow();
        assertThat(updated.getLastSeenAt()).isEqualTo(NOW.plusSeconds(31));

        updated.revoke();
        sessions.saveAndFlush(updated);
        entityManager.clear();
        assertThat(sessions.touch(session.getId(), TENANT, NOW.plusSeconds(100),
                IamSession.Status.ACTIVE, NOW.plusSeconds(100))).isZero();
    }

    @Test
    void selectsOnlyActiveRecoverySessionsForOperatorAndTenant() {
        UUID operator = UUID.randomUUID();
        IamSession active = recoverySession(operator, UUID.randomUUID());
        IamSession otherOperator = recoverySession(UUID.randomUUID(), UUID.randomUUID());
        IamSession revoked = recoverySession(operator, UUID.randomUUID());
        revoked.revoke();
        IamSession otherTenant = new IamSession(UUID.randomUUID(), "tenant-b", "recovery:other", "recovery",
                NOW, NOW.plusSeconds(600), "identity-admin", operator, UUID.randomUUID());

        sessions.saveAll(List.of(active, otherOperator, revoked, otherTenant));
        sessions.flush();

        assertThat(sessions.findActiveRecoverySessionsForOperatorForUpdate(
                TENANT, operator, IamSession.Status.ACTIVE))
                .extracting(IamSession::getId)
                .containsExactly(active.getId());
    }

    private static IamSession recoverySession(UUID operatorA, UUID operatorB) {
        return new IamSession(UUID.randomUUID(), TENANT, "recovery:session", "recovery",
                NOW, NOW.plusSeconds(600), "identity-admin", operatorA, operatorB);
    }
}
