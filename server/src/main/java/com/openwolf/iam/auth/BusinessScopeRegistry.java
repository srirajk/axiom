package com.openwolf.iam.auth;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

/** Deployment-owned vocabulary of business scopes eligible for tenant client registration. */
@Component
public final class BusinessScopeRegistry {
    private static final Pattern SYNTAX = Pattern.compile("[a-z][a-z0-9-]*(?:[.:][a-z][a-z0-9-]*)+");
    private final Set<String> approved;

    public BusinessScopeRegistry(@Value("${iam.oauth2.approved-business-scopes:}") String configured) {
        TreeSet<String> values = new TreeSet<>();
        Arrays.stream(configured.split(",")).map(String::trim).filter(value -> !value.isBlank()).forEach(value -> {
            if (value.startsWith("axiom.") || !SYNTAX.matcher(value).matches()) {
                throw new IllegalStateException("invalid approved business scope configuration");
            }
            values.add(value);
        });
        this.approved = Set.copyOf(values);
    }

    public boolean isApproved(String scope) { return approved.contains(scope); }
    public Set<String> approvedScopes() { return approved; }
}
