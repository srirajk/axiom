package com.openwolf.iam.policystudio.lifecycle;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Proves that the serving Cerbos instance has indexed a candidate tenant policy before the active
 * bundle pointer is made visible. A successful storage write is insufficient because both the disk
 * watcher and blob poller reload asynchronously and may reject a snapshot.
 */
@Component
public class CerbosRuntimeActivationProbe {

    private final HttpClient http;
    private final ObjectMapper json;
    private final URI checkResourcesUri;
    private final long timeoutMs;
    private final long intervalMs;

    @Autowired
    public CerbosRuntimeActivationProbe(
            ObjectMapper json,
            @Value("${CERBOS_HOST:cerbos}") String host,
            @Value("${CERBOS_HTTP_PORT:3592}") int port,
            @Value("${iam.policy-studio.runtime-activation-probe-timeout-ms:15000}") long timeoutMs,
            @Value("${iam.policy-studio.runtime-activation-probe-interval-ms:250}") long intervalMs) {
        this(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build(), json,
                URI.create("http://" + host + ":" + port + "/api/check/resources"),
                timeoutMs, intervalMs);
    }

    CerbosRuntimeActivationProbe(HttpClient http, ObjectMapper json, URI checkResourcesUri,
                                 long timeoutMs, long intervalMs) {
        this.http = http;
        this.json = json;
        this.checkResourcesUri = checkResourcesUri;
        this.timeoutMs = Math.max(1L, timeoutMs);
        this.intervalMs = Math.max(1L, intervalMs);
    }

    /** Poll until Cerbos reports the exact candidate resource-policy identity as the matched policy. */
    public void awaitLoaded(PolicyBundle bundle) {
        for (ProbeTarget target : targets(bundle)) {
            awaitTarget(bundle, target);
        }
    }

    private void awaitTarget(PolicyBundle bundle, ProbeTarget target) {
        String expectedPolicy = "resource." + cerbosFqnResource(target.resourceKind()) + ".v" + bundle.bundleId()
                + "/" + target.scope();
        long deadline = System.nanoTime() + Duration.ofMillis(timeoutMs).toNanos();
        Throwable lastFailure = null;

        do {
            try {
                if (matches(bundle, target, expectedPolicy)) {
                    return;
                }
            } catch (Exception e) {
                lastFailure = e;
            }
            sleep();
        } while (System.nanoTime() < deadline);

        throw new PromotedBundleLoadException(bundle.bundleId(), checkResourcesUri.toString(),
                new IllegalStateException("serving Cerbos did not report matchedPolicy='"
                        + expectedPolicy + "' for scope='" + target.scope() + "' before timeout",
                        lastFailure));
    }

    private boolean matches(PolicyBundle bundle, ProbeTarget target, String expectedPolicy) throws Exception {
        ObjectNode root = json.createObjectNode();
        root.put("requestId", "policy-activation-" + bundle.bundleId());
        root.put("includeMeta", true);

        ObjectNode principal = root.putObject("principal");
        principal.put("id", "policy-activation-probe");
        principal.put("policyVersion", bundle.bundleId());
        principal.putArray("roles").add("policy_activation_probe");
        principal.putObject("attr").put("tenant_id", bundle.tenantId());

        ObjectNode entry = root.putArray("resources").addObject();
        entry.putArray("actions").add(target.action());
        ObjectNode resource = entry.putObject("resource");
        resource.put("id", "policy-activation-probe");
        resource.put("kind", target.resourceKind());
        resource.put("policyVersion", bundle.bundleId());
        resource.put("scope", target.scope());
        resource.putObject("attr").put("tenant_id", bundle.tenantId());

        HttpRequest request = HttpRequest.newBuilder(checkResourcesUri)
                .timeout(Duration.ofSeconds(4))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json.writeValueAsString(root)))
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() / 100 != 2) {
            return false;
        }
        JsonNode body = json.readTree(response.body());
        JsonNode result = body.path("results").path(0);
        String matched = result.path("meta").path("actions").path(target.action())
                .path("matchedPolicy").asText("");
        return bundle.bundleId().equals(result.path("resource").path("policyVersion").asText())
                && expectedPolicy.equals(matched);
    }

    /** Select every exact tenant child; the full snapshot must be serving before its pointer is visible. */
    private List<ProbeTarget> targets(PolicyBundle bundle) {
        Map<String, ProbeTarget> targets = new LinkedHashMap<>();
        for (BundleFile file : bundle.renderedFiles()) {
            Object loaded;
            try {
                LoaderOptions options = new LoaderOptions();
                options.setAllowDuplicateKeys(false);
                options.setMaxAliasesForCollections(0);
                loaded = new Yaml(new SafeConstructor(options)).load(file.yaml());
            } catch (RuntimeException ignored) {
                continue;
            }
            if (!(loaded instanceof Map<?, ?> doc)
                    || !(doc.get("resourcePolicy") instanceof Map<?, ?> policy)) {
                continue;
            }
            String scope = scalar(policy.get("scope"));
            String kind = scalar(policy.get("resource"));
            if (!bundle.tenantId().equals(scope) || kind.isBlank()) {
                continue;
            }
            String action = firstAction(policy.get("rules"));
            if (!action.isBlank()) {
                targets.put(kind, new ProbeTarget(kind, scope, action));
            }
        }
        if (targets.isEmpty()) {
            throw new PromotedBundleLoadException(bundle.bundleId(), checkResourcesUri.toString(),
                    new IllegalStateException("candidate contains no exact-tenant resource child with an action"));
        }
        return new ArrayList<>(targets.values());
    }

    private static String firstAction(Object rawRules) {
        if (!(rawRules instanceof List<?> rules)) return "";
        for (Object rawRule : rules) {
            if (!(rawRule instanceof Map<?, ?> rule)) continue;
            Object rawActions = rule.get("actions");
            if (rawActions instanceof List<?> actions && !actions.isEmpty()) {
                return scalar(actions.getFirst());
            }
        }
        return "";
    }

    private static String scalar(Object value) {
        return value == null ? "" : String.valueOf(value).trim();
    }

    /** Cerbos normalizes hyphens to underscores in the resource component of matchedPolicy FQNs. */
    static String cerbosFqnResource(String resourceKind) {
        return resourceKind.replace('-', '_');
    }

    private void sleep() {
        try {
            Thread.sleep(intervalMs);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new PromotedBundleLoadException("runtime-publication-barrier",
                    checkResourcesUri.toString(), e);
        }
    }

    private record ProbeTarget(String resourceKind, String scope, String action) { }
}
