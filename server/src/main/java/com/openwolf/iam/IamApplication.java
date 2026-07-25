package com.openwolf.iam;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * OpenWolf IAM Service — OIDC provider, user management, entitlements.
 * <p>
 * Virtual threads are enabled via {@code spring.threads.virtual.enabled=true} in application.yml.
 * Spring MVC (Tomcat) runs on virtual threads — reactive/WebFlux is intentionally NOT used.
 * </p>
 */
@SpringBootApplication
public class IamApplication {

    public static void main(String[] args) {
        SpringApplication.run(IamApplication.class, args);
    }
}
