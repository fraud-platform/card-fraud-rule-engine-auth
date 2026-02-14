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
        long startTime = System.currentTimeMillis();
        long startNanos = System.nanoTime();

        Decision decision = createDecision(transaction, ruleset, replayMode);
        decision.setRulesetKey(ruleset.getKey());
        decision.setRulesetVersion(ruleset.getVersion());
        decision.setRulesetId(ruleset.getRulesetId());

        // Initialize timing breakdown
        com.fraud.engine.domain.TimingBreakdown breakdown = new com.fraud.engine.domain.TimingBreakdown();
        decision.setTimingBreakdown(breakdown);

        DebugInfo.Builder debugBuilder = shouldCaptureDebug()
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

            // Measure scope traversal (ADR-0015)
            long scopeStart = System.nanoTime();
            List<Rule> rulesToEvaluate = ruleset.getApplicableRules(
                    transaction.getCardNetwork(),
                    transaction.getCardBin(),
                    transaction.getMerchantCategoryCode(),
                    transaction.getCardLogo()
            );
            long scopeEnd = System.nanoTime();
            breakdown.setScopeTraversalTimeMs((scopeEnd - scopeStart) / 1_000_000.0);

            if (rulesToEvaluate.isEmpty()) {
                LOG.warnf("No rules to evaluate for ruleset: %s", ruleset.getFullKey());
                decision.setDecision(Decision.DECISION_APPROVE);
                return finalizeDecision(decision, startTime, debugBuilder);
            }

            // Measure context creation
            long contextStart = System.nanoTime();
            EvaluationContext context = EvaluationContext.create(
                    transaction,
                    ruleset,
                    decision,
                    replayMode,
                    startTime,
                    decision.getEngineMode(),
                    debugBuilder,
                    rulesToEvaluate,
                    evalContext
            );
            long contextEnd = System.nanoTime();
            breakdown.setContextCreationTimeMs((contextEnd - contextStart) / 1_000_000.0);

            // Measure dispatch evaluation
            long dispatchStart = System.nanoTime();
            dispatchEvaluation(context);
            long dispatchEnd = System.nanoTime();
            breakdown.setDispatchEvaluationTimeMs((dispatchEnd - dispatchStart) / 1_000_000.0);

        } catch (Exception e) {
            LOG.errorf(e, "Error during rule evaluation");
            handleEvaluationError(decision, transaction, e);
        }

        // Measure finalization
        long finalizeStart = System.nanoTime();
        Decision finalDecision = finalizeDecision(decision, startTime, debugBuilder);
        long finalizeEnd = System.nanoTime();

        // Update timing breakdown with finalization time
        if (finalDecision.getTimingBreakdown() != null) {
            finalDecision.getTimingBreakdown().setDecisionFinalizationTimeMs((finalizeEnd - finalizeStart) / 1_000_000.0);
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

    private Decision finalizeDecision(Decision decision, long startTime, DebugInfo.Builder debugBuilder) {
        long processingTimeMs = System.currentTimeMillis() - startTime;
        decision.setProcessingTimeMs(processingTimeMs);

        EngineMetadata engineMetadata = new EngineMetadata(
                decision.getEngineMode(),
                decision.getEngineErrorCode(),
                decision.getEngineErrorMessage(),
                processingTimeMs,
                null
        );
        decision.setEngineMetadata(engineMetadata);

        // Preserve existing timing breakdown and update total
        TimingBreakdown timingBreakdown = decision.getTimingBreakdown();
        if (timingBreakdown == null) {
            timingBreakdown = new TimingBreakdown(processingTimeMs);
            decision.setTimingBreakdown(timingBreakdown);
        } else {
            timingBreakdown.setTotalProcessingTimeMs(processingTimeMs);
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
