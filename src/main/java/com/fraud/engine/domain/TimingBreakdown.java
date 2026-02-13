package com.fraud.engine.domain;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Detailed timing breakdown for evaluation latency analysis.
 * <p>
 * Captures component-level timing to ensure 10-20ms AUTH latency target is met.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TimingBreakdown {

    @JsonProperty("total_processing_time_ms")
    private double totalProcessingTimeMs;

    @JsonProperty("ruleset_lookup_time_ms")
    private Double rulesetLookupTimeMs;

    @JsonProperty("rule_evaluation_time_ms")
    private Double ruleEvaluationTimeMs;

    @JsonProperty("velocity_check_time_ms")
    private Double velocityCheckTimeMs;

    @JsonProperty("velocity_check_count")
    private Integer velocityCheckCount;

    @JsonProperty("decision_build_time_ms")
    private Double decisionBuildTimeMs;

    @JsonProperty("redis_outbox_time_ms")
    private Double redisOutboxTimeMs;

    @JsonProperty("scope_traversal_time_ms")
    private Double scopeTraversalTimeMs;

    @JsonProperty("context_creation_time_ms")
    private Double contextCreationTimeMs;

    @JsonProperty("dispatch_evaluation_time_ms")
    private Double dispatchEvaluationTimeMs;

    @JsonProperty("decision_finalization_time_ms")
    private Double decisionFinalizationTimeMs;

    public TimingBreakdown() {
    }

    public TimingBreakdown(double totalProcessingTimeMs) {
        this.totalProcessingTimeMs = totalProcessingTimeMs;
    }

    public double getTotalProcessingTimeMs() {
        return totalProcessingTimeMs;
    }

    public void setTotalProcessingTimeMs(double totalProcessingTimeMs) {
        this.totalProcessingTimeMs = totalProcessingTimeMs;
    }

    public Double getRulesetLookupTimeMs() {
        return rulesetLookupTimeMs;
    }

    public void setRulesetLookupTimeMs(Double rulesetLookupTimeMs) {
        this.rulesetLookupTimeMs = rulesetLookupTimeMs;
    }

    public Double getRuleEvaluationTimeMs() {
        return ruleEvaluationTimeMs;
    }

    public void setRuleEvaluationTimeMs(Double ruleEvaluationTimeMs) {
        this.ruleEvaluationTimeMs = ruleEvaluationTimeMs;
    }

    public Double getVelocityCheckTimeMs() {
        return velocityCheckTimeMs;
    }

    public void setVelocityCheckTimeMs(Double velocityCheckTimeMs) {
        this.velocityCheckTimeMs = velocityCheckTimeMs;
    }

    public Integer getVelocityCheckCount() {
        return velocityCheckCount;
    }

    public void setVelocityCheckCount(Integer velocityCheckCount) {
        this.velocityCheckCount = velocityCheckCount;
    }

    public Double getDecisionBuildTimeMs() {
        return decisionBuildTimeMs;
    }

    public void setDecisionBuildTimeMs(Double decisionBuildTimeMs) {
        this.decisionBuildTimeMs = decisionBuildTimeMs;
    }

    public Double getRedisOutboxTimeMs() {
        return redisOutboxTimeMs;
    }

    public void setRedisOutboxTimeMs(Double redisOutboxTimeMs) {
        this.redisOutboxTimeMs = redisOutboxTimeMs;
    }

    public Double getScopeTraversalTimeMs() {
        return scopeTraversalTimeMs;
    }

    public void setScopeTraversalTimeMs(Double scopeTraversalTimeMs) {
        this.scopeTraversalTimeMs = scopeTraversalTimeMs;
    }

    public Double getContextCreationTimeMs() {
        return contextCreationTimeMs;
    }

    public void setContextCreationTimeMs(Double contextCreationTimeMs) {
        this.contextCreationTimeMs = contextCreationTimeMs;
    }

    public Double getDispatchEvaluationTimeMs() {
        return dispatchEvaluationTimeMs;
    }

    public void setDispatchEvaluationTimeMs(Double dispatchEvaluationTimeMs) {
        this.dispatchEvaluationTimeMs = dispatchEvaluationTimeMs;
    }

    public Double getDecisionFinalizationTimeMs() {
        return decisionFinalizationTimeMs;
    }

    public void setDecisionFinalizationTimeMs(Double decisionFinalizationTimeMs) {
        this.decisionFinalizationTimeMs = decisionFinalizationTimeMs;
    }

    /**
     * Creates a timing breakdown with nanosecond precision converted to milliseconds.
     */
    public static TimingBreakdown fromNanos(long totalNanos) {
        return new TimingBreakdown(totalNanos / 1_000_000.0);
    }

    @Override
    public String toString() {
        return "TimingBreakdown{" +
                "total=" + totalProcessingTimeMs + "ms" +
                ", rulesetLookup=" + rulesetLookupTimeMs + "ms" +
                ", ruleEvaluation=" + ruleEvaluationTimeMs + "ms" +
                ", velocityCheck=" + velocityCheckTimeMs + "ms" +
                ", velocityCount=" + velocityCheckCount +
                ", redisOutbox=" + redisOutboxTimeMs + "ms" +
                '}';
    }
}
