package com.openwolf.iam.policystudio.breakglass;

import com.openwolf.iam.policystudio.StudioGroundingProvider;
import com.openwolf.iam.policystudio.StudioGroundingSnapshot;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Production trust-root resolver. Vocabulary and ceiling come from the same manifest/base-bundle
 * grounding used by the normal Studio path. The narrower emergency surface is an explicit server
 * configuration, never request data.
 *
 * <p>{@code iam.break-glass.allowed-grants} is a comma-separated list of exact
 * {@code tenant|resourceKind|action} triples. It has no permissive default: an empty or malformed
 * configuration leaves break-glass authoring closed. Exact tenant entries avoid one tenant inheriting
 * another tenant's emergency surface, while the grounded vocabulary and ceiling still independently
 * verify every configured value.
 */
@Component
public class GroundedBreakGlassTrustRootProvider implements BreakGlassTrustRootProvider {

    private final StudioGroundingProvider grounding;
    private final Set<AllowedGrant> configured;

    public GroundedBreakGlassTrustRootProvider(
            StudioGroundingProvider grounding,
            @Value("${iam.break-glass.allowed-grants:}") String allowedGrants) {
        this.grounding = grounding;
        this.configured = parse(allowedGrants);
    }

    @Override
    public TrustRoots resolve(String tenantId, String resourceKind) {
        StudioGroundingSnapshot snapshot = grounding.snapshot(tenantId, resourceKind);
        Set<String> actions = new LinkedHashSet<>();
        configured.stream()
                .filter(entry -> entry.tenantId().equals(tenantId) && entry.resourceKind().equals(resourceKind))
                .map(AllowedGrant::action)
                .sorted()
                .forEach(actions::add);

        if (actions.isEmpty()) {
            throw new IllegalStateException("no trusted break-glass allowlist is configured for tenant '"
                    + tenantId + "' and resource '" + resourceKind + "' (fail-closed)");
        }
        return new TrustRoots(snapshot.vocabulary(), snapshot.baseCeiling(),
                new BreakGlassAllowlist(Set.of(resourceKind), actions));
    }

    private static Set<AllowedGrant> parse(String value) {
        if (value == null || value.isBlank()) {
            return Set.of();
        }
        Set<AllowedGrant> parsed = new LinkedHashSet<>();
        Arrays.stream(value.split(","))
                .map(String::trim)
                .filter(entry -> !entry.isEmpty())
                .forEach(entry -> {
                    String[] fields = entry.split("\\|", -1);
                    if (fields.length != 3 || Arrays.stream(fields).anyMatch(String::isBlank)) {
                        throw new IllegalArgumentException("invalid iam.break-glass.allowed-grants entry '"
                                + entry + "'; expected tenant|resourceKind|action");
                    }
                    if (Arrays.stream(fields).anyMatch("*"::equals)) {
                        throw new IllegalArgumentException("wildcards are forbidden in "
                                + "iam.break-glass.allowed-grants entry '" + entry + "'");
                    }
                    parsed.add(new AllowedGrant(fields[0], fields[1], fields[2]));
                });
        return Set.copyOf(parsed);
    }

    private record AllowedGrant(String tenantId, String resourceKind, String action) {
    }
}
