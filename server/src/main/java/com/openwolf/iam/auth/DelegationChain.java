package com.openwolf.iam.auth;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The RFC 8693 section 4.1 {@code act} chain of an exchanged token. The outermost object is the current actor (the acting
 * workload chosen server-side by the exchange profile); nested {@code act} objects are prior actors, least recent deepest.
 * Prior actors are informational only: Axiom's own validators read the top-level members alone.
 *
 * <ul>
 *   <li>A service acting only for itself (a workload subject with no prior actor, exchanged by that same workload) has
 *   no {@code act} at all.</li>
 *   <li>The current actor is always written from server-side identity ({@code sub}, {@code client_id},
 *   {@code workload_id}), never copied from the request.</li>
 *   <li>Same actor (identical {@code sub}, {@code client_id} and {@code workload_id}; e.g. a broker hop or a continuation
 *   by the same workload): the subject's prior chain is kept unchanged under the regenerated current actor.</li>
 *   <li>Actor change: the subject token's whole {@code act} object, copied verbatim from the verified subject token,
 *   becomes the new {@code act.act}.</li>
 *   <li>A malformed subject chain, or a resulting chain deeper than {@link #MAX_DEPTH}, is refused with
 *   {@code invalid_grant}; it is never truncated or repaired.</li>
 * </ul>
 */
public final class DelegationChain {
    /** Maximum number of {@code act} levels in an issued token (current actor included). */
    public static final int MAX_DEPTH = 5;
    private static final OAuth2Error INVALID_GRANT = new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT);

    private DelegationChain() {}

    /**
     * The {@code act} claim for an exchange result.
     *
     * @param subjectAct the verified subject token's {@code act} claim, or null when the subject has no actor
     */
    public static Map<String, Object> build(Object subjectAct, String actorSub, String actorClientId, String workloadId) {
        if (blank(actorSub) || blank(actorClientId) || blank(workloadId)) fail();
        Map<String, Object> current = new LinkedHashMap<>();
        current.put("sub", actorSub);
        current.put("client_id", actorClientId);
        current.put("workload_id", workloadId);
        if (subjectAct == null) return current;
        int priorDepth = depth(subjectAct);
        Map<?, ?> prior = (Map<?, ?>) subjectAct;
        int depth;
        if (actorSub.equals(prior.get("sub")) && actorClientId.equals(prior.get("client_id"))
                && workloadId.equals(prior.get("workload_id"))) {
            Object earlier = prior.get("act");
            if (earlier != null) current.put("act", earlier);
            depth = priorDepth;
        } else {
            current.put("act", subjectAct);
            depth = priorDepth + 1;
        }
        if (depth > MAX_DEPTH) fail();
        return current;
    }

    /**
     * The {@code act} claim for an exchange of a verified subject token, or {@code null} when the acting workload is the
     * subject itself: a service acting only for itself has no actor (RFC 8693 section 4.1 names a distinct party acting
     * for {@code sub}), including after it exchanges its own token. Only a workload subject without a prior actor whose
     * {@code sub} is the acting client qualifies; any other subject gets the chain from {@link #build}.
     */
    public static Map<String, Object> forSubject(Map<String, Object> subjectClaims, String actorSub, String actorClientId,
                                                 String workloadId) {
        Object subjectAct = subjectClaims.get("act");
        if (subjectAct == null && "workload".equals(subjectClaims.get("identity_kind"))
                && actorClientId != null && actorClientId.equals(subjectClaims.get("sub"))) {
            if (blank(actorSub) || blank(workloadId)) fail();
            return null;
        }
        return build(subjectAct, actorSub, actorClientId, workloadId);
    }

    /**
     * Number of {@code act} levels; refuses any malformed level (not a JSON object, missing or blank string {@code sub},
     * non-string {@code client_id}, nested {@code act} that is not an object) and any chain deeper than {@link #MAX_DEPTH}.
     */
    public static int depth(Object act) {
        int levels = 0;
        Object level = act;
        while (level != null) {
            if (!(level instanceof Map<?, ?>) || ++levels > MAX_DEPTH) fail();
            Map<?, ?> object = (Map<?, ?>) level;
            if (!(object.get("sub") instanceof String sub) || sub.isBlank()) fail();
            Object clientId = object.get("client_id");
            if (clientId != null && !(clientId instanceof String)) fail();
            level = object.get("act");
        }
        return levels;
    }

    private static boolean blank(String value) { return value == null || value.isBlank(); }

    private static void fail() { throw new OAuth2AuthenticationException(INVALID_GRANT); }
}
