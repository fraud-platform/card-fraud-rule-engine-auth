package com.fraud.engine.resource.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.eclipse.microprofile.openapi.annotations.media.Schema;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Simulation result response.
 */
@Schema(description = "Simulation result")
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SimulationResult {

    @Schema(description = "Transaction ID")
    @JsonProperty("transaction_id")
    private String transactionId;

    @Schema(description = "Decision result (APPROVE, DECLINE, REVIEW)")
    private String decision;

    @Schema(description = "Ruleset key used")
    private String rulesetKey;

    @Schema(description = "Ruleset version used")
    private Integer rulesetVersion;

    @Schema(description = "Matched rules with details")
    private List<?> matchedRules;

    @Schema(description = "Velocity check results")
    private Map<String, ?> velocityResults;

    @Schema(description = "Human-readable explanations")
    private List<String> explanations;

    @Schema(description = "Primary explanation")
    private String explanation;

    @Schema(description = "When the simulation was evaluated")
    private Instant evaluatedAt;

    @Schema(description = "Evaluation time in milliseconds")
    private long evaluationTimeMs;

    @Schema(description = "Engine mode (NORMAL, DEGRADED, FAIL_OPEN, REPLAY)")
    private String engineMode;

    @Schema(description = "Debug information (if debug mode enabled)")
    private Object debugInfo;

    public String getTransactionId() {
        return transactionId;
    }

    public void setTransactionId(String transactionId) {
        this.transactionId = transactionId;
    }

    public String getDecision() {
        return decision;
    }

    public void setDecision(String decision) {
        this.decision = decision;
    }

    public String getRulesetKey() {
        return rulesetKey;
    }

    public void setRulesetKey(String rulesetKey) {
        this.rulesetKey = rulesetKey;
    }

    public Integer getRulesetVersion() {
        return rulesetVersion;
    }

    public void setRulesetVersion(Integer rulesetVersion) {
        this.rulesetVersion = rulesetVersion;
    }

    public List<?> getMatchedRules() {
        return matchedRules;
    }

    public void setMatchedRules(List<?> matchedRules) {
        this.matchedRules = matchedRules;
    }

    public Map<String, ?> getVelocityResults() {
        return velocityResults;
    }

    public void setVelocityResults(Map<String, ?> velocityResults) {
        this.velocityResults = velocityResults;
    }

    public List<String> getExplanations() {
        return explanations;
    }

    public void setExplanations(List<String> explanations) {
        this.explanations = explanations;
    }

    public String getExplanation() {
        return explanation;
    }

    public void setExplanation(String explanation) {
        this.explanation = explanation;
    }

    public Instant getEvaluatedAt() {
        return evaluatedAt;
    }

    public void setEvaluatedAt(Instant evaluatedAt) {
        this.evaluatedAt = evaluatedAt;
    }

    public long getEvaluationTimeMs() {
        return evaluationTimeMs;
    }

    public void setEvaluationTimeMs(long evaluationTimeMs) {
        this.evaluationTimeMs = evaluationTimeMs;
    }

    public String getEngineMode() {
        return engineMode;
    }

    public void setEngineMode(String engineMode) {
        this.engineMode = engineMode;
    }

    public Object getDebugInfo() {
        return debugInfo;
    }

    public void setDebugInfo(Object debugInfo) {
        this.debugInfo = debugInfo;
    }
}
