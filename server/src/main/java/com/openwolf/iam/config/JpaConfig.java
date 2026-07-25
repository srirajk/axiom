package com.openwolf.iam.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

/**
 * Enables JPA auditing so that {@code @CreatedDate} and {@code @LastModifiedDate}
 * on entity fields are populated automatically by {@code AuditingEntityListener}.
 */
@Configuration
@EnableJpaAuditing
public class JpaConfig {
    // All configuration driven by annotations.
    // AuditingEntityListener is registered via @EntityListeners on each entity.
}
