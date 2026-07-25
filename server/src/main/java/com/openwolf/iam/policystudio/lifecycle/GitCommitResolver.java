package com.openwolf.iam.policystudio.lifecycle;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

/**
 * Resolves the Git commit a promoted bundle is anchored to (Axiom Story C5). The immutable bundle record
 * maps {@code bundleId → Git commit}; the examiner walks that edge. The default implementation reads the
 * current {@code HEAD} best-effort; tests inject a deterministic stub.
 */
@FunctionalInterface
public interface GitCommitResolver {

    /** The commit the bundle content is anchored to, or {@code null} if it cannot be resolved. */
    String currentCommit();

    /**
     * The default resolver — {@code git rev-parse HEAD}, best-effort. Never throws: an unresolved commit
     * is a {@code null} anchor the examiner surfaces, not a crash.
     */
    @Component
    class GitHeadResolver implements GitCommitResolver {

        private static final Logger log = LoggerFactory.getLogger(GitHeadResolver.class);

        @Override
        public String currentCommit() {
            try {
                Process p = new ProcessBuilder("git", "rev-parse", "HEAD")
                        .redirectErrorStream(true).start();
                String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
                boolean done = p.waitFor(10, TimeUnit.SECONDS);
                if (!done) {
                    p.destroyForcibly();
                    return null;
                }
                return (p.exitValue() == 0 && !out.isBlank()) ? out : null;
            } catch (Exception e) {
                if (e instanceof InterruptedException) {
                    Thread.currentThread().interrupt();
                }
                log.debug("could not resolve git HEAD for bundle anchor", e);
                return null;
            }
        }
    }
}
