package com.openwolf.iam.policystudio.api;

import com.openwolf.iam.policystudio.ConsequenceReview;
import com.openwolf.iam.policystudio.lifecycle.PolicyBundle;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class StudioSessionStoreTest {

    private static ConsequenceReview review(String tenant, String hash) {
        return new ConsequenceReview(tenant, "agent", "b0", "b1", "fs-1", List.of(), false,
                0, "cd", hash, null, null, Instant.now(), null);
    }

    private static PolicyBundle candidate(String tenant) {
        return new PolicyBundle("b1", tenant, List.of(), List.of(), null, "content");
    }

    @Test
    void pendingInboxIsTenantFilteredAndCompletionRetiresOnlyThatReview() {
        StudioSessionStore store = new StudioSessionStore();
        StudioSessionStore.StoredReview meridian =
                store.putReview("meridian", "alice", review("meridian", "rev-m"), candidate("meridian"));
        store.putReview("acme", "eve", review("acme", "rev-a"), candidate("acme"));

        assertThat(store.pendingReviews("meridian")).extracting(StudioSessionStore.StoredReview::reviewId)
                .containsExactly("rev-m");
        assertThat(store.pendingReviews("meridian").getFirst().candidate()).isEqualTo(candidate("meridian"));

        store.markReviewCompleted(meridian);

        assertThat(store.pendingReviews("meridian")).isEmpty();
        assertThat(store.pendingReviews("acme")).extracting(StudioSessionStore.StoredReview::reviewId)
                .containsExactly("rev-a");
    }

    @Test
    void refusesCandidateThatIsNotTheReviewedBundle() {
        StudioSessionStore store = new StudioSessionStore();
        PolicyBundle wrong = new PolicyBundle("b-other", "meridian", List.of(), List.of(), null, "content");

        assertThatThrownBy(() -> store.putReview(
                "meridian", "alice", review("meridian", "rev-m"), wrong))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("same handoff");
    }

    @Test
    void identicalHashCannotBeReassignedToAnotherAuthor() {
        StudioSessionStore store = new StudioSessionStore();
        ConsequenceReview review = review("meridian", "rev-m");
        PolicyBundle candidate = candidate("meridian");
        StudioSessionStore.StoredReview first = store.putReview("meridian", "alice", review, candidate);

        assertThat(store.putReview("meridian", "alice", review, candidate)).isSameAs(first);
        assertThatThrownBy(() -> store.putReview("meridian", "mallory", review, candidate))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("another author");
        assertThat(store.authorFor("meridian", "rev-m")).contains("alice");
    }

    @Test
    void concurrentAuthorsCannotRaceToRewriteReviewOwnership() throws Exception {
        StudioSessionStore store = new StudioSessionStore();
        ConsequenceReview review = review("meridian", "rev-race");
        PolicyBundle candidate = candidate("meridian");
        CountDownLatch start = new CountDownLatch(1);

        try (var workers = Executors.newFixedThreadPool(2)) {
            var alice = workers.submit(() -> {
                start.await();
                return capture(() -> store.putReview("meridian", "alice", review, candidate));
            });
            var mallory = workers.submit(() -> {
                start.await();
                return capture(() -> store.putReview("meridian", "mallory", review, candidate));
            });
            start.countDown();

            List<Object> outcomes = List.of(alice.get(), mallory.get());
            assertThat(outcomes.stream().filter(StudioSessionStore.StoredReview.class::isInstance)).hasSize(1);
            assertThat(outcomes.stream().filter(IllegalStateException.class::isInstance)).hasSize(1);
            String owner = store.authorFor("meridian", "rev-race").orElseThrow();
            assertThat(owner).isIn("alice", "mallory");
        }
    }

    private static Object capture(java.util.concurrent.Callable<StudioSessionStore.StoredReview> action) {
        try {
            return action.call();
        } catch (Exception e) {
            return e;
        }
    }
}
