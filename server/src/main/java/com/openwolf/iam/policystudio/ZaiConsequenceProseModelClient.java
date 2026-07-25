package com.openwolf.iam.policystudio;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * Display-only consequence prose client. It phrases an already-final PDP delta; absence or failure of
 * this call never changes the review hash, alarm, deltas, approval, or promotion decision.
 */
@Component
public class ZaiConsequenceProseModelClient implements ConsequenceProseModelClient {

    private final RestClient restClient;
    private final ObjectMapper objectMapper;
    private final String model;
    private final String apiKey;

    public ZaiConsequenceProseModelClient(
            @Value("${iam.policy-studio.prose.model:${IAM_POLICY_STUDIO_PROSE_MODEL:glm-4.6}}") String model,
            @Value("${iam.policy-studio.prose.base-url:${IAM_POLICY_STUDIO_PROSE_BASE_URL:https://api.z.ai/api/paas/v4}}") String baseUrl,
            @Value("${iam.policy-studio.prose.api-key:${IAM_POLICY_STUDIO_PROSE_API_KEY:${ZAI_API_KEY:}}}") String apiKey,
            @Value("${iam.policy-studio.prose.connect-timeout-ms:5000}") long connectTimeoutMs,
            @Value("${iam.policy-studio.prose.read-timeout-ms:15000}") long readTimeoutMs,
            ObjectMapper objectMapper) {
        this.model = model;
        this.apiKey = apiKey;
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
    public String phrase(ConsequenceReview review) {
        if (apiKey == null || apiKey.isBlank()) {
            throw new IllegalStateException("consequence prose LLM is not configured");
        }
        String machine = review.deltas().stream()
                .map(d -> d.direction() + ": " + d.businessConsequence())
                .reduce((a, b) -> a + "\n" + b)
                .orElse("No sampled access decision changed.");
        Map<String, Object> body = Map.of(
                "model", model,
                "messages", List.of(
                        Map.of("role", "system", "content", """
                                You explain already-computed authorization consequences in plain business English.
                                Do not add, remove, or reinterpret consequences. Do not say this is a formal proof.
                                Return 2-4 short sentences for a human approver.
                                """),
                        Map.of("role", "user", "content", "Resource kind: " + review.resourceKind()
                                + "\nOver-permission alarm: " + review.overPermissionAlarm()
                                + "\nSampled cells: " + review.disclosure().sampledCellCount()
                                + "\nMachine consequences:\n" + machine)),
                "temperature", 0.0,
                "max_tokens", 220);
        String response = restClient.post().uri("/chat/completions").body(body).retrieve().body(String.class);
        try {
            JsonNode root = objectMapper.readTree(response);
            return root.path("choices").path(0).path("message").path("content").asText();
        } catch (Exception e) {
            throw new RuntimeException("failed to parse consequence prose response", e);
        }
    }
}
