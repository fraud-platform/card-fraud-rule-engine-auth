package com.fraud.engine.engine;

import com.fraud.engine.config.EvaluationConfig;
import com.fraud.engine.domain.Decision;
import com.fraud.engine.domain.Rule;
import com.fraud.engine.domain.Ruleset;
import com.fraud.engine.domain.TransactionContext;
import com.fraud.engine.util.EngineMetrics;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests that {@link RuleEvaluator} samples the detailed {@code TimingBreakdown} instead of
 * recording it on every request (Task 4).
 * <p>
 * These are plain unit tests (no CDI container) so the sampling config can be manipulated
 * directly and deterministically per test.
 */
class RuleEvaluatorTimingSamplingTest {

    private RuleEvaluator newEvaluator(int timingSampleEveryN) {
        RuleEvaluator evaluator = new RuleEvaluator();

        AuthEvaluator authEvaluator = new AuthEvaluator();
        authEvaluator.evaluationConfig = new EvaluationConfig();

        EvaluationConfig config = new EvaluationConfig();
        config.timingSampleEveryN = timingSampleEveryN;

        evaluator.authEvaluator = authEvaluator;
        evaluator.evaluationConfig = config;
        evaluator.engineMetrics = new EngineMetrics();
        return evaluator;
    }

    private Ruleset newRuleset() {
        Ruleset ruleset = new Ruleset("TEST_AUTH", 1);
        ruleset.setEvaluationType("AUTH");
        Rule rule = new Rule("r1", "always-decline", "DECLINE");
        rule.setPriority(100);
        ruleset.addRule(rule);
        return ruleset;
    }

    private TransactionContext newTransaction() {
        TransactionContext txn = new TransactionContext();
        txn.setTransactionId("txn-1");
        return txn;
    }

    @Test
    void sampleRateOne_recordsDetailedTimingOnEveryRequest() {
        RuleEvaluator evaluator = newEvaluator(1);
        Ruleset ruleset = newRuleset();

        for (int i = 0; i < 5; i++) {
            Decision decision = evaluator.evaluate(newTransaction(), ruleset);
            assertThat(decision.getTimingBreakdown()).isNotNull();
            assertThat(decision.getProcessingTimeMs()).isGreaterThanOrEqualTo(0);
            assertThat(decision.getEngineMetadata()).isNotNull();
        }
    }

    @Test
    void sampleRateZero_neverRecordsDetailedTimingButCoreFieldsStillSet() {
        RuleEvaluator evaluator = newEvaluator(0);
        Ruleset ruleset = newRuleset();

        Decision decision = evaluator.evaluate(newTransaction(), ruleset);

        assertThat(decision.getTimingBreakdown()).isNull();
        assertThat(decision.getProcessingTimeMs()).isGreaterThanOrEqualTo(0);
        assertThat(decision.getEngineMetadata()).isNotNull();
        assertThat(decision.getDecision()).isEqualTo(Decision.DECISION_DECLINE);
    }

    @Test
    void sampleRateZero_replayModeForcesDetailedTiming() {
        RuleEvaluator evaluator = newEvaluator(0);
        Ruleset ruleset = newRuleset();

        Decision decision = evaluator.evaluate(newTransaction(), ruleset, true);

        assertThat(decision.getTimingBreakdown()).isNotNull();
    }

    @Test
    void sampleRateZero_debugCaptureForcesDetailedTiming() {
        RuleEvaluator evaluator = newEvaluator(0);
        // RuleEvaluator reads its OWN evaluationConfig field (not authEvaluator's) for the
        // debug-capture check, so only this instance's flags matter here.
        evaluator.evaluationConfig.debugEnabled = true;
        evaluator.evaluationConfig.debugSampleRate = 100;
        Ruleset ruleset = newRuleset();

        Decision decision = evaluator.evaluate(newTransaction(), ruleset, false);

        assertThat(decision.getTimingBreakdown()).isNotNull();
    }

    @Test
    void sampleRateN_recordsRoughlyOneOfN() {
        RuleEvaluator evaluator = newEvaluator(5);
        Ruleset ruleset = newRuleset();

        int sampled = 0;
        int iterations = 1000;
        for (int i = 0; i < iterations; i++) {
            Decision decision = evaluator.evaluate(newTransaction(), ruleset);
            if (decision.getTimingBreakdown() != null) {
                sampled++;
            }
        }

        // Loose statistical bound per brief: strictly between 50 and 500 for N=5 over 1000 runs.
        assertThat(sampled).isStrictlyBetween(50, 500);
    }
}
