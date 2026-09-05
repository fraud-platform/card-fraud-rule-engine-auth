package com.fraud.engine.engine;

import com.fraud.engine.config.EvaluationConfig;
import com.fraud.engine.domain.DebugInfo;
import com.fraud.engine.domain.Decision;
import com.fraud.engine.domain.EngineMetadata;
import com.fraud.engine.domain.Rule;
import com.fraud.engine.domain.Ruleset;
import com.fraud.engine.domain.TimingBreakdown;
import com.fraud.engine.domain.TransactionContext;
import com.fraud.engine.util.EngineMetrics;
import com.fraud.engine.velocity.VelocityService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.util.List;
import java.util.Map;

@ApplicationScoped
public class RuleEvaluator {

    private static final Logger LOG = Logger.getLogger(RuleEvaluator.class);

    public static final String EVAL_AUTH = "AUTH";
    public static final String EVAL_REPLAY_MODE = "REPLAY";

    private static final boolean STATIC_DEBUG_ENABLED = EvaluationConfig.isStaticDebugEnabled();

    public enum EvaluationType {
        AUTH, REPLAY;

        public String getValue() {
            return name();
        }
    }

    @Inject
    AuthEvaluator authEvaluator;

    @Inject
    VelocityService velocityService;

    @Inject
    EvaluationConfig evaluationConfig;

    @Inject
    EngineMetrics engineMetrics;

    public Decision evaluate(TransactionContext transaction, Ruleset ruleset) {
        return evaluate(transaction, ruleset, false);
    }

    public Decision evaluate(TransactionContext transaction, Ruleset ruleset, boolean replayMode) {
        // Skip the config-driven sample roll entirely when replayMode already forces detailed
        // timing - there's no point spending a ThreadLocalRandom call on the non-hot replay path.
        // A null evaluationConfig (e.g. this class constructed directly, outside CDI) disables
        // detailed timing (breakdown stays null) rather than throwing - intentional.
        boolean sampled = !replayMode
                && evaluationConfig != null
                && evaluationConfig.shouldSampleDetailedTiming();
        return evaluate(transaction, ruleset, replayMode, sampled);
    }

    /**
     * Evaluates a transaction against a ruleset.
     *
     * @param transaction            the transaction to evaluate
     * @param ruleset                the compiled ruleset to evaluate against
     * @param replayMode             true for replay/simulation flows; always forces detailed timing
     * @param detailedTimingSampled  the caller's pre-decided (once per request, not re-rolled here)
     *                               timing-sample outcome; ORed with {@code replayMode} and debug
     *                               capture to produce the final detailed-timing decision for this call
     */
    public Decision evaluate(TransactionContext transaction, Ruleset ruleset, boolean replayMode,
                              boolean detailedTimingSampled) {
        long startNanos = System.nanoTime();

        Decision decision = createDecision(transaction, ruleset, replayMode);
        decision.setRulesetKey(ruleset.getKey());
        decision.setRulesetVersion(ruleset.getVersion());
        decision.setRulesetId(ruleset.getRulesetId());

        boolean debugCapture = shouldCaptureDebug();
        // Detailed per-phase TimingBreakdown is a sampled diagnostic, not a per-request tax:
        // replay/simulation and debug-captured requests always get it; everything else follows
        // the (already-decided-once) sample outcome passed in by the caller.
        boolean detailedTiming = replayMode || debugCapture || detailedTimingSampled;

        // Initialize timing breakdown only when this request is sampled for detailed timing.
        com.fraud.engine.domain.TimingBreakdown breakdown = null;
        if (detailedTiming) {
            breakdown = new com.fraud.engine.domain.TimingBreakdown();
            decision.setTimingBreakdown(breakdown);
        }

        DebugInfo.Builder debugBuilder = debugCapture
                ? createDebugBuilder(ruleset.getKey(), "v" + ruleset.getVersion())
                : null;

        try {
            Map<String, Object> evalContext = null;
            // Keep AUTH map creation lazy: only build evaluation context when a rule/debug path needs it.
            // MONITORING/REPLAY still materialize the context because it's included in decision payloads.
            if (!EVAL_AUTH.equalsIgnoreCase(ruleset.getEvaluationType())) {
                evalContext = transaction.toEvaluationContext();
                decision.setTransactionContext(evalContext);
            }

            // Measure scope traversal (ADR-0015) - only when sampled for detailed timing.
            long scopeStart = detailedTiming ? System.nanoTime() : 0L;
            List<Rule> rulesToEvaluate = ruleset.getApplicableRules(
                    transaction.getCardNetwork(),
                    transaction.getCardBin(),
                    transaction.getMerchantCategoryCode(),
                    transaction.getCardLogo()
            );
            if (detailedTiming) {
                long scopeEnd = System.nanoTime();
                breakdown.setScopeTraversalTimeMs((scopeEnd - scopeStart) / 1_000_000.0);
            }

            if (rulesToEvaluate.isEmpty()) {
                LOG.warnf("No rules to evaluate for ruleset: %s", ruleset.getFullKey());
                decision.setDecision(Decision.DECISION_APPROVE);
                return finalizeDecision(decision, startNanos, debugBuilder, detailedTiming);
            }

            // Measure context creation - only when sampled for detailed timing.
            long contextStart = detailedTiming ? System.nanoTime() : 0L;
            EvaluationContext context = EvaluationContext.create(
                    transaction,
                    ruleset,
                    decision,
                    replayMode,
                        startNanos,
                    decision.getEngineMode(),
                    debugBuilder,
                    rulesToEvaluate,
                    evalContext
            );
            if (detailedTiming) {
                long contextEnd = System.nanoTime();
                breakdown.setContextCreationTimeMs((contextEnd - contextStart) / 1_000_000.0);
            }

            // Measure dispatch evaluation - only when sampled for detailed timing.
            long dispatchStart = detailedTiming ? System.nanoTime() : 0L;
            dispatchEvaluation(context);
            if (detailedTiming) {
                long dispatchEnd = System.nanoTime();
                breakdown.setDispatchEvaluationTimeMs((dispatchEnd - dispatchStart) / 1_000_000.0);
            }

        } catch (Exception e) {
            LOG.errorf(e, "Error during rule evaluation");
            handleEvaluationError(decision, transaction, e);
        }

        // Measure finalization - only when sampled for detailed timing.
        long finalizeStart = detailedTiming ? System.nanoTime() : 0L;
        Decision finalDecision = finalizeDecision(decision, startNanos, debugBuilder, detailedTiming);

        // Update timing breakdown with finalization time
        if (detailedTiming) {
            long finalizeEnd = System.nanoTime();
            if (finalDecision.getTimingBreakdown() != null) {
                finalDecision.getTimingBreakdown().setDecisionFinalizationTimeMs((finalizeEnd - finalizeStart) / 1_000_000.0);
            }
        }

        return finalDecision;
    }

    private Decision createDecision(TransactionContext transaction, Ruleset ruleset, boolean replayMode) {
        Decision decision = new Decision(transaction.getTransactionId(), ruleset.getEvaluationType());
        decision.setEngineMode(replayMode ? Decision.MODE_REPLAY : Decision.MODE_NORMAL);
        return decision;
    }

    private DebugInfo.Builder createDebugBuilder(String rulesetKey, String version) {
        return new DebugInfo.Builder()
                .rulesetKey(rulesetKey)
                .compiledRulesetVersion(version)
                .compilationTimestamp(System.currentTimeMillis());
    }

    private boolean shouldCaptureDebug() {
        if (STATIC_DEBUG_ENABLED) {
            return true;
        }
        return evaluationConfig != null && evaluationConfig.shouldCaptureDebug();
    }

    private void dispatchEvaluation(EvaluationContext context) {
        authEvaluator.evaluate(context);
    }

    private Decision finalizeDecision(Decision decision, long startTimeNanos, DebugInfo.Builder debugBuilder,
                                       boolean detailedTiming) {
        long processingTimeMs = (System.nanoTime() - startTimeNanos) / 1_000_000;
        decision.setProcessingTimeMs(processingTimeMs);

        EngineMetadata engineMetadata = new EngineMetadata(
                decision.getEngineMode(),
                decision.getEngineErrorCode(),
                decision.getEngineErrorMessage(),
                processingTimeMs,
                null
        );
        decision.setEngineMetadata(engineMetadata);

        // Preserve existing timing breakdown and update total. Only create one here if this
        // request was sampled for detailed timing - otherwise leave it null (Task 4).
        TimingBreakdown timingBreakdown = decision.getTimingBreakdown();
        if (timingBreakdown != null) {
            timingBreakdown.setTotalProcessingTimeMs(processingTimeMs);
        } else if (detailedTiming) {
            timingBreakdown = new TimingBreakdown(processingTimeMs);
            decision.setTimingBreakdown(timingBreakdown);
        }

        if (debugBuilder != null) {
            DebugInfo.EvaluationTiming timing = new DebugInfo.EvaluationTiming(
                    null,
                    processingTimeMs * 1_000_000,
                    null
            );
            debugBuilder.timing(timing);
            decision.setDebugInfo(debugBuilder.build());
        }

        if (LOG.isDebugEnabled()) {
            LOG.debugf("Decision complete: id=%s, decision=%s, mode=%s, time=%dms",
                    decision.getDecisionId(),
                    decision.getDecision(),
                    decision.getEngineMode(),
                    decision.getProcessingTimeMs());
        }
        return decision;
    }

    private void handleEvaluationError(Decision decision, TransactionContext transaction, Exception e) {
        decision.setEngineErrorCode("EVALUATION_ERROR");
        decision.setEngineErrorMessage("Error during rule evaluation: " + e.getMessage());
        decision.setEngineMode(Decision.MODE_FAIL_OPEN);
        decision.setDecision(Decision.DECISION_APPROVE);
        engineMetrics.incrementFailOpen();
        LOG.error("Evaluation error, defaulting to APPROVE (fail-open)", e);
    }
}
