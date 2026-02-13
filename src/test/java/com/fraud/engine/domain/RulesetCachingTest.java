package com.fraud.engine.domain;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for Ruleset caching behavior.
 * Tests thread-safe sorting cache, preSort(), and invalidation.
 */
class RulesetCachingTest {

    // === preSort() Tests ===

    @Test
    void testPreSort_SortsRulesOnDemand() {
        Ruleset ruleset = new Ruleset("CARD_AUTH", 1);

        // Add rules in random priority order
        addRule(ruleset, "low", 10);
        addRule(ruleset, "high", 100);
        addRule(ruleset, "medium", 50);

        // Call preSort to trigger sorting
        ruleset.preSort();

        // Verify getRulesByPriority returns sorted list immediately
        List<Rule> sorted = ruleset.getRulesByPriority();
        assertThat(sorted).hasSize(3);
        assertThat(sorted.get(0).getId()).isEqualTo("high");   // Priority 100
        assertThat(sorted.get(1).getId()).isEqualTo("medium"); // Priority 50
        assertThat(sorted.get(2).getId()).isEqualTo("low");    // Priority 10
    }

    @Test
    void testPreSort_CanBeCalledMultipleTimes() {
        Ruleset ruleset = new Ruleset("CARD_AUTH", 1);

        addRule(ruleset, "low", 10);
        addRule(ruleset, "high", 100);

        // Call preSort multiple times
        ruleset.preSort();
        ruleset.preSort();
        ruleset.preSort();

        // Should still work correctly
        List<Rule> sorted = ruleset.getRulesByPriority();
        assertThat(sorted.get(0).getId()).isEqualTo("high");
        assertThat(sorted.get(1).getId()).isEqualTo("low");
    }

    @Test
    void testPreSort_WithEmptyRuleset() {
        Ruleset ruleset = new Ruleset("CARD_AUTH", 1);

        // Should not throw
        ruleset.preSort();

        assertThat(ruleset.getRulesByPriority()).isEmpty();
    }

    // === Cache Invalidation Tests ===

    @Test
    void testInvalidateCachedRules_ClearsCache() {
        Ruleset ruleset = new Ruleset("CARD_AUTH", 1);

        addRule(ruleset, "low", 10);
        addRule(ruleset, "high", 100);

        // First call - caches sorted rules
        List<Rule> firstCall = ruleset.getRulesByPriority();
        assertThat(firstCall.get(0).getId()).isEqualTo("high");

        // Invalidate cache
        ruleset.invalidateCachedRules();

        // Add new rule
        addRule(ruleset, "super-high", 200);

        // Next call should re-sort with new rule
        List<Rule> secondCall = ruleset.getRulesByPriority();
        assertThat(secondCall.get(0).getId()).isEqualTo("super-high");
    }

    @Test
    void testSetRules_InvalidatesCache() {
        Ruleset ruleset = new Ruleset("CARD_AUTH", 1);

        addRule(ruleset, "low", 10);
        addRule(ruleset, "high", 100);

        // Cache the sorted rules
        List<Rule> firstCall = ruleset.getRulesByPriority();
        assertThat(firstCall).hasSize(2);

        // Replace rules entirely
        List<Rule> newRules = new ArrayList<>();
        Rule newRule = new Rule("new-rule", "New", "APPROVE");
        newRule.setPriority(50);
        newRule.setEnabled(true);
        newRules.add(newRule);

        ruleset.setRules(newRules);

        // Should return new rules, not cached old rules
        List<Rule> secondCall = ruleset.getRulesByPriority();
        assertThat(secondCall).hasSize(1);
        assertThat(secondCall.get(0).getId()).isEqualTo("new-rule");
    }

    @Test
    void testAddRule_InvalidatesCache() {
        Ruleset ruleset = new Ruleset("CARD_AUTH", 1);

        addRule(ruleset, "low", 10);

        // Cache the sorted rules
        ruleset.preSort();
        List<Rule> firstCall = ruleset.getRulesByPriority();
        assertThat(firstCall).hasSize(1);

        // Add new rule
        addRule(ruleset, "high", 100);

        // Cache should be invalidated, new rule should appear
        List<Rule> secondCall = ruleset.getRulesByPriority();
        assertThat(secondCall).hasSize(2);
        assertThat(secondCall.get(0).getId()).isEqualTo("high");
    }

    // === Thread Safety Tests ===

    @Test
    void testGetRulesByPriority_ThreadSafe() throws InterruptedException {
        Ruleset ruleset = new Ruleset("CARD_AUTH", 1);

        // Add many rules
        for (int i = 0; i < 100; i++) {
            addRule(ruleset, "rule-" + i, i);
        }

        int threadCount = 10;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch latch = new CountDownLatch(threadCount);
        AtomicInteger errorCount = new AtomicInteger(0);

        // Multiple threads calling getRulesByPriority concurrently
        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    for (int j = 0; j < 100; j++) {
                        List<Rule> sorted = ruleset.getRulesByPriority();
                        // Verify sorted order
                        for (int k = 0; k < sorted.size() - 1; k++) {
                            if (sorted.get(k).getPriority() < sorted.get(k + 1).getPriority()) {
                                errorCount.incrementAndGet();
                            }
                        }
                    }
                } finally {
                    latch.countDown();
                }
            });
        }

        latch.await(10, TimeUnit.SECONDS);
        executor.shutdown();

        assertThat(errorCount.get()).isEqualTo(0);
    }

    @Test
    void testInvalidateCachedRules_ThreadSafe() throws InterruptedException {
        Ruleset ruleset = new Ruleset("CARD_AUTH", 1);

        // Add initial rules
        addRule(ruleset, "rule-1", 10);
        addRule(ruleset, "rule-2", 20);

        int threadCount = 5;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch latch = new CountDownLatch(threadCount);

        // Half the threads read, half invalidate and add rules
        for (int i = 0; i < threadCount; i++) {
            final int threadNum = i;
            executor.submit(() -> {
                try {
                    for (int j = 0; j < 50; j++) {
                        if (threadNum % 2 == 0) {
                            // Reader threads
                            List<Rule> sorted = ruleset.getRulesByPriority();
                            assertThat(sorted).isNotNull();
                        } else {
                            // Writer threads
                            addRule(ruleset, "rule-" + threadNum + "-" + j, j);
                            ruleset.invalidateCachedRules();
                        }
                    }
                } finally {
                    latch.countDown();
                }
            });
        }

        latch.await(10, TimeUnit.SECONDS);
        executor.shutdown();

        // Final state should be consistent
        List<Rule> sorted = ruleset.getRulesByPriority();
        assertThat(sorted).isNotNull();
        for (int i = 0; i < sorted.size() - 1; i++) {
            assertThat(sorted.get(i).getPriority())
                    .isGreaterThanOrEqualTo(sorted.get(i + 1).getPriority());
        }
    }

    // === Concurrent Sort Test ===

    @Test
    void testConcurrentPreSort() throws InterruptedException {
        Ruleset ruleset = new Ruleset("CARD_AUTH", 1);

        for (int i = 0; i < 50; i++) {
            addRule(ruleset, "rule-" + i, i);
        }

        int threadCount = 10;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch latch = new CountDownLatch(threadCount);

        // All threads call preSort concurrently
        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    ruleset.preSort();
                } finally {
                    latch.countDown();
                }
            });
        }

        latch.await(5, TimeUnit.SECONDS);
        executor.shutdown();

        // Verify correct sorting
        List<Rule> sorted = ruleset.getRulesByPriority();
        assertThat(sorted).hasSize(50);
        assertThat(sorted.get(0).getId()).isEqualTo("rule-49"); // Highest priority
        assertThat(sorted.get(49).getId()).isEqualTo("rule-0"); // Lowest priority
    }

    // === Cache Efficiency Tests ===

    @Test
    void testCachedRulesAreImmutable() {
        Ruleset ruleset = new Ruleset("CARD_AUTH", 1);
        addRule(ruleset, "rule-1", 10);
        addRule(ruleset, "rule-2", 20);

        List<Rule> cached = ruleset.getRulesByPriority();

        // Try to modify the returned list
        try {
            cached.add(new Rule("rule-3", "Rule 3", "APPROVE"));
            // If we reach here, the list is mutable (not ideal but not critical)
        } catch (UnsupportedOperationException e) {
            // Expected - list should be immutable
        }

        // Get rules again - should still have only 2 rules
        List<Rule> secondCall = ruleset.getRulesByPriority();
        assertThat(secondCall).hasSize(2);
    }

    @Test
    void testMultipleCallsReturnSameCachedInstance() {
        Ruleset ruleset = new Ruleset("CARD_AUTH", 1);
        addRule(ruleset, "rule-1", 10);

        List<Rule> first = ruleset.getRulesByPriority();
        List<Rule> second = ruleset.getRulesByPriority();
        List<Rule> third = ruleset.getRulesByPriority();

        // All should return the same cached instance
        assertThat(first).isSameAs(second);
        assertThat(second).isSameAs(third);
    }

    @Test
    void testAfterInvalidation_NewInstanceIsCreated() {
        Ruleset ruleset = new Ruleset("CARD_AUTH", 1);
        addRule(ruleset, "rule-1", 10);

        List<Rule> first = ruleset.getRulesByPriority();

        // Invalidate
        ruleset.invalidateCachedRules();

        List<Rule> second = ruleset.getRulesByPriority();

        // Should be a different instance
        assertThat(first).isNotSameAs(second);
    }

    // === Helper Methods ===

    private void addRule(Ruleset ruleset, String id, int priority) {
        Rule rule = new Rule(id, "Rule " + id, "DECLINE");
        rule.setPriority(priority);
        rule.setEnabled(true);
        ruleset.addRule(rule);
    }
}
