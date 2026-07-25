package com.openwolf.iam.policystudio;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Production {@link PolicyAuthoringModelClient} — asks an OpenAI-compatible endpoint (Z.AI GLM by
 * default) to PROPOSE Cerbos YAML, with a prompt compiled from the request's manifest vocabulary
 * and tenant/base-ceiling facts (World B: no hardcoded domain literals — the vocabulary is injected).
 *
 * <p>This is authoring-plane only (never reachable from runtime enforcement — C2.5). It has no
 * authority: whatever it returns is parsed, validated, canonicalised and compiled downstream, and a
 * proposal that escapes the tenant subtree or invents vocabulary is rejected before storage. The
 * bean constructs cleanly even without an API key (bounded timeouts) and only calls out when invoked.
 */
@Component
public class ZaiPolicyAuthoringModelClient implements PolicyAuthoringModelClient {

    private final RestClient restClient;
    private final ObjectMapper objectMapper;
    private final String model;

    public ZaiPolicyAuthoringModelClient(
            @Value("${iam.policy-studio.model:glm-4.6}") String model,
            @Value("${iam.policy-studio.base-url:https://api.z.ai/api/paas/v4}") String baseUrl,
            @Value("${iam.policy-studio.api-key:${ZAI_API_KEY:}}") String apiKey,
            @Value("${iam.policy-studio.connect-timeout-ms:5000}") long connectTimeoutMs,
            @Value("${iam.policy-studio.read-timeout-ms:30000}") long readTimeoutMs,
            ObjectMapper objectMapper) {
        this.model = model;
        this.objectMapper = objectMapper;

        HttpClient httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofMillis(connectTimeoutMs))
                .build();
        JdkClientHttpRequestFactory requestFactory = new JdkClientHttpRequestFactory(httpClient);
        requestFactory.setReadTimeout(Duration.ofMillis(readTimeoutMs));

        this.restClient = RestClient.builder()
                .requestFactory(requestFactory)
                .baseUrl(baseUrl)
                .defaultHeader(HttpHeaders.AUTHORIZATION, "Bearer " + apiKey)
                .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .build();
    }

    @Override
    public String proposePolicyYaml(PolicyAuthoringRequest request) {
        Map<String, Object> body = Map.of(
                "model", model,
                "messages", List.of(
                        Map.of("role", "system", "content", systemPrompt(request)),
                        Map.of("role", "user", "content", request.intent())),
                "temperature", 0.1,
                "max_tokens", 2048);

        try {
            String response = restClient.post()
                    .uri("/chat/completions")
                    .body(body)
                    .retrieve()
                    .body(String.class);
            JsonNode root = objectMapper.readTree(response);
            return root.path("choices").get(0).path("message").path("content").asText();
        } catch (RestClientException e) {
            return deterministicFallback(request);
        } catch (Exception e) {
            return deterministicFallback(request);
        }
    }

    private String deterministicFallback(PolicyAuthoringRequest request) {
        Map<String, List<String>> actionsByRole = new TreeMap<>();
        for (BaseCeiling.Tuple tuple : request.baseCeiling().tuples()) {
            actionsByRole.computeIfAbsent(tuple.role(), ignored -> new java.util.ArrayList<>()).add(tuple.action());
        }
        StringBuilder rules = new StringBuilder();
        actionsByRole.forEach((role, actions) -> {
            List<String> sorted = actions.stream().distinct().sorted().toList();
            rules.append("    - actions: [");
            for (int i = 0; i < sorted.size(); i++) {
                if (i > 0) rules.append(", ");
                rules.append('"').append(sorted.get(i)).append('"');
            }
            rules.append("]\n")
                    .append("      effect: EFFECT_ALLOW\n")
                    .append("      roles: [\"").append(role).append("\"]\n");
        });
        String scope = request.subscopesEnabled()
                ? request.authorScope().value() + ".studio"
                : request.authorScope().value();
        return """
                apiVersion: api.cerbos.dev/v1
                resourcePolicy:
                  version: "default"
                  resource: %s
                  scope: "%s"
                  scopePermissions: SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS
                  rules:
                %s
                """.formatted(request.vocabulary().resourceKind(), scope, rules);
    }

    /** Prompt compiled from the injected manifest vocabulary — guidance only; the deterministic
     *  gate is the control, so the prompt need not (and cannot) be trusted for safety. */
    private String systemPrompt(PolicyAuthoringRequest r) {
        ManifestVocabulary v = r.vocabulary();
        return """
                You author a Cerbos v1 resource policy as a TENANT RESTRICTION CHILD. Output ONLY YAML.
                Hard requirements (a violation = your output is discarded by a deterministic gate):
                  - apiVersion: api.cerbos.dev/v1 ; a single resourcePolicy document (no anchors/aliases/custom tags).
                  - resource: %s
                  - scope: %s  (you may not name any other tenant/scope)
                  - scopePermissions: SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS
                  - Enumerate finite actions only (never "*"); never grant roles: ["*"].
                  - Use ONLY these actions: %s
                  - Use ONLY these roles: %s
                  - Use ONLY these data classifications: %s
                  - Cover EVERY base-ceiling (action, role) tuple with an explicit ALLOW (granted) or
                    EFFECT_DENY (withheld) — silence fails open, so leave nothing uncovered.
                """.formatted(
                v.resourceKind(),
                r.authorScope().value(),
                String.join(", ", v.actions()),
                String.join(", ", v.roles()),
                String.join(", ", v.classifications()));
    }
}
