package com.openwolf.iam.policystudio;

import java.util.Optional;

/**
 * The trusted source of a consequence review's AUTHOR — the verified {@code sub} recorded server-side at
 * the moment the review was computed (Axiom H3, C1.2/C1.3). {@link ConsequenceApprovalService#approve}
 * consults it to enforce author≠approver from a value the caller cannot supply or forge, rather than from a
 * method argument or request body.
 *
 * <p>The lookup is tenant-scoped: a review is keyed by (tenantId, {@code consequenceReviewHash}), so a
 * cross-tenant reviewId never resolves and an author recorded for one tenant never shadows another's.
 */
public interface ReviewAuthorRegistry {

    /**
     * @return the verified author of the review, or empty if none was recorded for this tenant/hash.
     */
    Optional<String> authorFor(String tenantId, String consequenceReviewHash);
}
