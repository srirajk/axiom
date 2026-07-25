package com.openwolf.iam.test;

import java.nio.file.Files;
import java.nio.file.Path;

/** Single test-only authority for the isolated Axiom platform-policy bundle and Cerbos image. */
public final class AxiomTestPolicyRoot {
    private static final String PINNED_CERBOS =
            "ghcr.io/cerbos/cerbos:0.53.0@sha256:c3fe64202e3793b7e9c41c5cbfcf390a51fb28ebce0a7d70754155e70db839c4";

    private AxiomTestPolicyRoot() {}

    public static Path policies() {
        String configured = System.getProperty("axiom.platform.policy.root");
        if (configured != null && !configured.isBlank()) return checked(Path.of(configured));
        Path cursor = Path.of("").toAbsolutePath();
        for (int depth = 0; depth < 6 && cursor != null; depth++, cursor = cursor.getParent()) {
            Path candidate = cursor.resolve("axiom-platform-policy/policies");
            if (Files.isDirectory(candidate)) return candidate;
        }
        throw new IllegalStateException("isolated axiom-platform-policy/policies package is unavailable");
    }

    public static String cerbosImage() {
        return System.getProperty("axiom.platform.cerbos.image", PINNED_CERBOS);
    }

    private static Path checked(Path path) {
        if (!Files.isDirectory(path)) throw new IllegalStateException("invalid Axiom platform policy root: " + path);
        return path.toAbsolutePath().normalize();
    }
}
