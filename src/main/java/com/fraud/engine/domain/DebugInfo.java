package com.fraud.engine.domain;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Detailed debugging information for rule evaluation.
 * <p>
 * Only populated when {@code app.evaluation.debug.enabled=true}.
 * This ensures production performance is not impacted while providing
 * full debugging capability when needed.
 * <p>
 * Debug mode uses the same compiled ruleset code path - execution
 * is identical to production, only additional information is captured.
 *
 * @see ADR-0009 for details on debug mode design
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class DebugInfo {

    @JsonProperty("condition_evaluations")
    private List<ConditionEvaluation> conditionEvaluations;

    @JsonProperty("field_values")
    private Map<String, Object> fieldValues;

    @JsonProperty("compilation_timestamp")
    private Long compilationTimestamp;

    @JsonProperty("compiled_ruleset_version")
    private String compiledRulesetVersion;

    @JsonProperty("timing")
    private EvaluationTiming timing;

    @JsonProperty("ruleset_key")
    private String rulesetKey;

    public DebugInfo() {
        this.conditionEvaluations = new ArrayList<>();
        this.fieldValues = new HashMap<>();
    }

    public DebugInfo(List<ConditionEvaluation> conditionEvaluations,
                     Map<String, Object> fieldValues,
                     Long compilationTimestamp,
                     String compiledRulesetVersion,
                     EvaluationTiming timing) {
        this.conditionEvaluations = conditionEvaluations != null
                ? new ArrayList<>(conditionEvaluations)
                : new ArrayList<>();
        this.fieldValues = fieldValues != null
                ? new HashMap<>(fieldValues)
                : new HashMap<>();
        this.compilationTimestamp = compilationTimestamp;
        this.compiledRulesetVersion = compiledRulesetVersion;
        this.timing = timing;
    }

    public DebugInfo(List<ConditionEvaluation> conditionEvaluations,
                     Map<String, Object> fieldValues,
                     Long compilationTimestamp,
                     String compiledRulesetVersion,
                     EvaluationTiming timing,
                     String rulesetKey) {
        this(conditionEvaluations, fieldValues, compilationTimestamp, compiledRulesetVersion, timing);
        this.rulesetKey = rulesetKey;
    }

    /**
     * Adds a condition evaluation result.
     */
    public void addConditionEvaluation(ConditionEvaluation evaluation) {
        this.conditionEvaluations.add(evaluation);
    }

    /**
     * Adds a field value.
     */
    public void addFieldValue(String fieldName, Object value) {
        this.fieldValues.put(fieldName, value);
    }

    /**
     * Creates an empty debug info (when debug mode is disabled).
     */
    public static DebugInfo empty() {
        return new DebugInfo(Collections.emptyList(), Collections.emptyMap(), null, null, null);
    }

    // Getters and Setters

    public List<ConditionEvaluation> getConditionEvaluations() {
        return conditionEvaluations;
    }

    public void setConditionEvaluations(List<ConditionEvaluation> conditionEvaluations) {
        this.conditionEvaluations = conditionEvaluations;
    }

    public Map<String, Object> getFieldValues() {
        return fieldValues;
    }

    public void setFieldValues(Map<String, Object> fieldValues) {
        this.fieldValues = fieldValues;
    }

    public Long getCompilationTimestamp() {
        return compilationTimestamp;
    }

    public void setCompilationTimestamp(Long compilationTimestamp) {
        this.compilationTimestamp = compilationTimestamp;
    }

    public String getCompiledRulesetVersion() {
        return compiledRulesetVersion;
    }

    public void setCompiledRulesetVersion(String compiledRulesetVersion) {
        this.compiledRulesetVersion = compiledRulesetVersion;
    }

    public EvaluationTiming getTiming() {
        return timing;
    }

    public void setTiming(EvaluationTiming timing) {
        this.timing = timing;
    }

    public String getRulesetKey() {
        return rulesetKey;
    }

    public void setRulesetKey(String rulesetKey) {
        this.rulesetKey = rulesetKey;
    }

    /**
     * Result of evaluating a single condition.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class ConditionEvaluation {

        @JsonProperty("rule_id")
        private String ruleId;

        @JsonProperty("rule_name")
        private String ruleName;

        @JsonProperty("field")
        private String field;

        @JsonProperty("operator")
        private String operator;

        @JsonProperty("expected_value")
        private Object expectedValue;

        @JsonProperty("actual_value")
        private Object actualValue;

        @JsonProperty("matched")
        private boolean matched;

        @JsonProperty("evaluation_time_nanos")
        private long evaluationTimeNanos;

        @JsonProperty("explanation")
        private String explanation;

        public ConditionEvaluation() {
        }

        public ConditionEvaluation(String ruleId, String ruleName, String field,
                                   String operator, Object expectedValue,
                                   Object actualValue, boolean matched,
                                   long evaluationTimeNanos, String explanation) {
            this.ruleId = ruleId;
            this.ruleName = ruleName;
            this.field = field;
            this.operator = operator;
            this.expectedValue = expectedValue;
            this.actualValue = actualValue;
            this.matched = matched;
            this.evaluationTimeNanos = evaluationTimeNanos;
            this.explanation = explanation;
        }

        // Getters and Setters

        public String getRuleId() {
            return ruleId;
        }

        public void setRuleId(String ruleId) {
            this.ruleId = ruleId;
        }

        public String getRuleName() {
            return ruleName;
        }

        public void setRuleName(String ruleName) {
            this.ruleName = ruleName;
        }

        public String getField() {
            return field;
        }

        public void setField(String field) {
            this.field = field;
        }

        public String getOperator() {
            return operator;
        }

        public void setOperator(String operator) {
            this.operator = operator;
        }

        public Object getExpectedValue() {
            return expectedValue;
        }

        public void setExpectedValue(Object expectedValue) {
            this.expectedValue = expectedValue;
        }

        public Object getActualValue() {
            return actualValue;
        }

        public void setActualValue(Object actualValue) {
            this.actualValue = actualValue;
        }

        public boolean isMatched() {
            return matched;
        }

        public void setMatched(boolean matched) {
            this.matched = matched;
        }

        public long getEvaluationTimeNanos() {
            return evaluationTimeNanos;
        }

        public void setEvaluationTimeNanos(long evaluationTimeNanos) {
            this.evaluationTimeNanos = evaluationTimeNanos;
        }

        public String getExplanation() {
            return explanation;
        }

        public void setExplanation(String explanation) {
            this.explanation = explanation;
        }
    }

    /**
     * Timing breakdown for evaluation phases.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class EvaluationTiming {

        @JsonProperty("compilation_nanos")
        private Long compilationNanos;

        @JsonProperty("evaluation_nanos")
        private Long evaluationNanos;

        @JsonProperty("velocity_nanos")
        private Long velocityNanos;

        @JsonProperty("total_nanos")
        private Long totalNanos;

        public EvaluationTiming() {
        }

        public EvaluationTiming(Long compilationNanos, Long evaluationNanos, Long velocityNanos) {
            this.compilationNanos = compilationNanos;
            this.evaluationNanos = evaluationNanos;
            this.velocityNanos = velocityNanos;
            this.totalNanos = (compilationNanos != null ? compilationNanos : 0)
                    + (evaluationNanos != null ? evaluationNanos : 0)
                    + (velocityNanos != null ? velocityNanos : 0);
        }

        // Getters and Setters

        public Long getCompilationNanos() {
            return compilationNanos;
        }

        public void setCompilationNanos(Long compilationNanos) {
            this.compilationNanos = compilationNanos;
            recalculateTotal();
        }

        public Long getEvaluationNanos() {
            return evaluationNanos;
        }

        public void setEvaluationNanos(Long evaluationNanos) {
            this.evaluationNanos = evaluationNanos;
            recalculateTotal();
        }

        public Long getVelocityNanos() {
            return velocityNanos;
        }

        public void setVelocityNanos(Long velocityNanos) {
            this.velocityNanos = velocityNanos;
            recalculateTotal();
        }

        public Long getTotalNanos() {
            return totalNanos;
        }

        public void setTotalNanos(Long totalNanos) {
            this.totalNanos = totalNanos;
        }

        private void recalculateTotal() {
            this.totalNanos = (compilationNanos != null ? compilationNanos : 0)
                    + (evaluationNanos != null ? evaluationNanos : 0)
                    + (velocityNanos != null ? velocityNanos : 0);
        }
    }

    /**
     * Builder for constructing DebugInfo during evaluation.
     */
    public static class Builder {
        private final List<ConditionEvaluation> conditionEvaluations = new ArrayList<>();
        private final Map<String, Object> fieldValues = new HashMap<>();
        private Long compilationTimestamp;
        private String compiledRulesetVersion;
        private EvaluationTiming timing;
        private String rulesetKey;

        public Builder rulesetKey(String rulesetKey) {
            this.rulesetKey = rulesetKey;
            return this;
        }

        public Builder compilationTimestamp(Long timestamp) {
            this.compilationTimestamp = timestamp;
            return this;
        }

        public Builder compiledRulesetVersion(String version) {
            this.compiledRulesetVersion = version;
            return this;
        }

        public Builder timing(EvaluationTiming timing) {
            this.timing = timing;
            return this;
        }

        public Builder addConditionEvaluation(ConditionEvaluation evaluation) {
            this.conditionEvaluations.add(evaluation);
            return this;
        }

        public Builder addFieldValue(String fieldName, Object value) {
            this.fieldValues.put(fieldName, value);
            return this;
        }

        public int getConditionEvaluationCount() {
            return conditionEvaluations.size();
        }

        public DebugInfo build() {
            return new DebugInfo(
                    conditionEvaluations,
                    fieldValues,
                    compilationTimestamp,
                    compiledRulesetVersion,
                    timing,
                    rulesetKey
            );
        }
    }
}
