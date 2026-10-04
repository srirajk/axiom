package com.openwolf.iam.authority.lifecycle;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * Phase 3.15 rotation overlap: after a confidential-client secret rotation, the previous secret's (BCrypt) hash stays
 * valid until {@code valid_until}, then never again. The overlap is a declared deployment policy
 * ({@code iam.client-secret-rotation.overlap}, default zero = immediate cut-over, i.e. the existing behaviour) and is
 * capped at 24 hours. Revocation removes it immediately.
 */
@Service
public class ClientSecretOverlapStore {
    private final JdbcTemplate jdbc;
    private final Duration overlap;
    private final Clock clock = Clock.systemUTC();

    public ClientSecretOverlapStore(JdbcTemplate jdbc,
                                    @Value("${iam.client-secret-rotation.overlap:PT0S}") Duration overlap) {
        if (overlap.isNegative() || overlap.compareTo(Duration.ofHours(24)) > 0) {
            throw new IllegalArgumentException("client secret rotation overlap must be between zero and 24 hours");
        }
        this.jdbc = jdbc;
        this.overlap = overlap;
    }

    /** Called inside the rotation transaction with the hash being replaced. */
    public void rotated(String clientId, String previousSecretHash) {
        jdbc.update("DELETE FROM client_secret_overlaps WHERE client_id = ?", clientId);
        if (overlap.isZero() || previousSecretHash == null) return;
        Instant now = clock.instant();
        jdbc.update("INSERT INTO client_secret_overlaps (client_id, previous_secret_hash, valid_until, rotated_at) "
                + "VALUES (?, ?, ?, ?)", clientId, previousSecretHash, Timestamp.from(now.plus(overlap)), Timestamp.from(now));
    }

    public void revoked(String clientId) {
        jdbc.update("DELETE FROM client_secret_overlaps WHERE client_id = ?", clientId);
    }

    public Optional<String> previousHash(String clientId) {
        return jdbc.query("SELECT previous_secret_hash FROM client_secret_overlaps WHERE client_id = ? AND valid_until > ?",
                rs -> rs.next() ? Optional.of(rs.getString(1)) : Optional.<String>empty(), clientId,
                Timestamp.from(clock.instant()));
    }
}
