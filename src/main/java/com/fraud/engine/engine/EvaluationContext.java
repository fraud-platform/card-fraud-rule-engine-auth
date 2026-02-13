package com.fraud.engine.engine;

import com.fraud.engine.domain.DebugInfo;
import com.fraud.engine.domain.Rule;
import com.fraud.engine.domain.Ruleset;
import com.fraud.engine.domain.TransactionContext;
import com.fraud.engine.domain.Decision;

import java.util.List;
import java.util.Map;

public record EvaluationContext(
        TransactionContext transaction,
        Ruleset ruleset,
        Decision decision,
        boolean replayMode,
        long startTimeMs,
        String engineMode,
        DebugInfo.Builder debugBuilder,
        List<Rule> candidateRules,
        Map<String, Object> evalContext
) {
    public static EvaluationContext create(
            TransactionContext transaction,
            Ruleset ruleset,
            Decision decision,
            boolean replayMode,
            long startTimeMs,
            String engineMode,
            DebugInfo.Builder debugBuilder) {
        return new EvaluationContext(
                transaction,
                ruleset,
                decision,
                replayMode,
                startTimeMs,
                engineMode,
                debugBuilder,
                null,
                null
        );
    }

    public static EvaluationContext create(
            TransactionContext transaction,
            Ruleset ruleset,
            Decision decision,
            boolean replayMode,
            long startTimeMs,
            String engineMode,
            DebugInfo.Builder debugBuilder,
            List<Rule> candidateRules) {
        return new EvaluationContext(
                transaction,
                ruleset,
                decision,
                replayMode,
                startTimeMs,
                engineMode,
                debugBuilder,
                candidateRules,
                null
        );
    }

    public static EvaluationContext create(
            TransactionContext transaction,
            Ruleset ruleset,
            Decision decision,
            boolean replayMode,
            long startTimeMs,
            String engineMode,
            DebugInfo.Builder debugBuilder,
            List<Rule> candidateRules,
            Map<String, Object> evalContext) {
        return new EvaluationContext(
                transaction,
                ruleset,
                decision,
                replayMode,
                startTimeMs,
                engineMode,
                debugBuilder,
                candidateRules,
                evalContext
        );
    }

    public String getEvaluationType() {
        return ruleset != null ? ruleset.getEvaluationType() : "AUTH";
    }

    public boolean isDebugEnabled() {
        return debugBuilder != null;
    }

    /**
     * Returns scoped candidate rules if available, otherwise falls back to
     * all rules sorted by priority from the ruleset.
     */
    public List<Rule> getRulesToEvaluate() {
        if (candidateRules != null && !candidateRules.isEmpty()) {
            return candidateRules;
        }
        return ruleset != null ? ruleset.getRulesByPriority() : List.of();
    }
}
