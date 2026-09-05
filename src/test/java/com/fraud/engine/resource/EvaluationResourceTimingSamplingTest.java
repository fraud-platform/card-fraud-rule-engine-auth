package com.fraud.engine.resource;

import com.fraud.engine.config.EvaluationConfig;
import com.fraud.engine.domain.Decision;
import com.fraud.engine.domain.Rule;
import com.fraud.engine.domain.Ruleset;
import com.fraud.engine.domain.TimingBreakdown;
import com.fraud.engine.domain.TransactionContext;
import com.fraud.engine.engine.AuthEvaluator;
import com.fraud.engine.engine.RuleEvaluator;
import com.fraud.engine.outbox.AsyncOutboxDispatcher;
import com.fraud.engine.ruleset.RulesetRegistry;
import com.fraud.engine.util.EngineMetrics;
import com.fraud.engine.util.RulesetKeyResolver;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import java.lang.reflect.Field;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;

/**
 * Covers the Task 4 reviewer fix: {@code EvaluationResource}'s own detailed-timing sample
 * decision must fold in the non-probabilistic "debug enabled" flag, not just the config sample
 * rate. Otherwise, when {@code app.evaluation.debug.enabled=true} forces RuleEvaluator to create
 * a non-null {@code TimingBreakdown} (regardless of the sample roll), the resource would still
 * have skipped its own lookup/rule-evaluation instrumentation, leaving those fields unset on an
 * otherwise-present breakdown.
 * <p>
 * This is a plain unit test (no CDI container) that drives the real
 * {@code EvaluationResource.evaluateAuth(...)} code path directly, with the heavy S3/Kafka/Redis
 * dependency ({@code AsyncOutboxDispatcher}) mocked out via Mockito. The AUTH HTTP response body
 * ({@code SlimAuthResult}) never surfaces the timing breakdown by design, so the only place to
 * observe it end-to-end is the {@link Decision} actually handed to the outbox dispatcher -
 * captured here via {@link ArgumentCaptor}.
 */
class EvaluationResourceTimingSamplingTest {

    /**
     * {@code RuleEvaluator}'s CDI-injected fields are package-private in {@code
     * com.fraud.engine.engine} (by design, so same-package unit tests can wire them directly -
     * see {@code RuleEvaluatorTimingSamplingTest}). This test lives in {@code
     * com.fraud.engine.resource} to exercise the real {@code EvaluationResource} code path, so it
     * reaches across the package boundary via reflection rather than widening production field
     * visibility just for a test.
     */
    private static void setField(Object target, String fieldName, Object value) {
        try {
            Field field = target.getClass().getDeclaredField(fieldName);
            field.setAccessible(true);
            field.set(target, value);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException("Failed to set test field " + fieldName, e);
        }
    }

    private EvaluationResource newResource(EvaluationConfig sharedConfig, Ruleset ruleset,
                                            AsyncOutboxDispatcher outboxDispatcher) {
        EvaluationResource resource = new EvaluationResource();

        AuthEvaluator authEvaluator = new AuthEvaluator();
        setField(authEvaluator, "evaluationConfig", new EvaluationConfig());

        RuleEvaluator ruleEvaluator = new RuleEvaluator();
        setField(ruleEvaluator, "authEvaluator", authEvaluator);
        setField(ruleEvaluator, "evaluationConfig", sharedConfig);
        setField(ruleEvaluator, "engineMetrics", new EngineMetrics());

        RulesetRegistry rulesetRegistry = new RulesetRegistry();
        rulesetRegistry.register(ruleset);

        resource.ruleEvaluator = ruleEvaluator;
        resource.rulesetRegistry = rulesetRegistry;
        resource.rulesetKeyResolver = new RulesetKeyResolver();
        resource.engineMetrics = new EngineMetrics();
        resource.evaluationConfig = sharedConfig;
        resource.asyncOutboxDispatcher = outboxDispatcher;
        return resource;
    }

    private Ruleset newAuthRuleset() {
        Ruleset ruleset = new Ruleset("CARD_AUTH", 1);
        ruleset.setEvaluationType("AUTH");
        Rule rule = new Rule("r1", "always-decline", "DECLINE");
        rule.setPriority(100);
        ruleset.addRule(rule);
        return ruleset;
    }

    private TransactionContext newTransaction() {
        TransactionContext txn = new TransactionContext();
        txn.setTransactionId("txn-resource-1");
        return txn;
    }

    @Test
    void sampleRateZero_debugEnabled_stillRecordsFullTimingIncludingLookup() {
        EvaluationConfig config = new EvaluationConfig();
        config.timingSampleEveryN = 0;   // sampling roll alone would skip
        config.debugEnabled = true;      // but debug mode is globally on
        config.debugSampleRate = 0;      // and the per-request debug-capture roll always says "no"

        AsyncOutboxDispatcher outboxDispatcher = Mockito.mock(AsyncOutboxDispatcher.class);
        EvaluationResource resource = newResource(config, newAuthRuleset(), outboxDispatcher);

        Response response = resource.evaluateAuth(newTransaction());
        assertThat(response.getStatus()).isEqualTo(200);

        ArgumentCaptor<Decision> captor = ArgumentCaptor.forClass(Decision.class);
        Mockito.verify(outboxDispatcher).enqueueAuth(any(TransactionContext.class), captor.capture());

        TimingBreakdown breakdown = captor.getValue().getTimingBreakdown();
        assertThat(breakdown).isNotNull();
        assertThat(breakdown.getRulesetLookupTimeMs()).isNotNull();
        assertThat(breakdown.getRuleEvaluationTimeMs()).isNotNull();
    }

    @Test
    void sampleRateZero_debugDisabled_leavesTimingBreakdownNull() {
        EvaluationConfig config = new EvaluationConfig();
        config.timingSampleEveryN = 0;
        config.debugEnabled = false;

        AsyncOutboxDispatcher outboxDispatcher = Mockito.mock(AsyncOutboxDispatcher.class);
        EvaluationResource resource = newResource(config, newAuthRuleset(), outboxDispatcher);

        Response response = resource.evaluateAuth(newTransaction());
        assertThat(response.getStatus()).isEqualTo(200);

        ArgumentCaptor<Decision> captor = ArgumentCaptor.forClass(Decision.class);
        Mockito.verify(outboxDispatcher).enqueueAuth(any(TransactionContext.class), captor.capture());

        assertThat(captor.getValue().getTimingBreakdown()).isNull();
    }

    @Test
    void sampleRateOne_alwaysRecordsFullTimingRegardlessOfDebugFlag() {
        EvaluationConfig config = new EvaluationConfig();
        config.timingSampleEveryN = 1;
        config.debugEnabled = false;

        AsyncOutboxDispatcher outboxDispatcher = Mockito.mock(AsyncOutboxDispatcher.class);
        EvaluationResource resource = newResource(config, newAuthRuleset(), outboxDispatcher);

        Response response = resource.evaluateAuth(newTransaction());
        assertThat(response.getStatus()).isEqualTo(200);

        ArgumentCaptor<Decision> captor = ArgumentCaptor.forClass(Decision.class);
        Mockito.verify(outboxDispatcher).enqueueAuth(any(TransactionContext.class), captor.capture());

        TimingBreakdown breakdown = captor.getValue().getTimingBreakdown();
        assertThat(breakdown).isNotNull();
        assertThat(breakdown.getRulesetLookupTimeMs()).isNotNull();
        assertThat(breakdown.getRuleEvaluationTimeMs()).isNotNull();
        assertThat(breakdown.getRedisOutboxTimeMs()).isNotNull();
    }
}
