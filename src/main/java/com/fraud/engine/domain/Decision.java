package com.fraud.engine.domain;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Represents the decision result from evaluating a transaction.
 *
 * Contains:
 * - The final decision (APPROVE, DECLINE). REVIEW is reserved for rule actions only.
 * - Engine mode (NORMAL, DEGRADED, FAIL_OPEN)
 - Matched rules and their actions
 - Velocity check results
 - Error information if any
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Decision {

    @JsonProperty("decision_id")
    private String decisionId;

    @JsonProperty("transaction_id")
    private String transactionId;

    @JsonProperty("evaluation_type")
    private String evaluationType;

    @JsonProperty("decision")
    private String decision;

    @JsonProperty("engine_mode")
    private String engineMode;

    @JsonProperty("engine_error_code")
    private String engineErrorCode;

    @JsonProperty("engine_error_message")
    private String engineErrorMessage;

    @JsonProperty("ruleset_key")
    private String rulesetKey;

    @JsonProperty("ruleset_version")
    private Integer rulesetVersion;

    @JsonProperty("ruleset_id")
    private String rulesetId;

    @JsonProperty("matched_rules")
    private List<MatchedRule> matchedRules = Collections.emptyList();

    @JsonProperty("velocity_results")
    private Map<String, VelocityResult> velocityResults = Collections.emptyMap();

    @JsonProperty("timestamp")
    private Instant timestamp;

    @JsonProperty("processing_time_ms")
    private long processingTimeMs;

    @JsonProperty("debug_info")
    private DebugInfo debugInfo;

    @JsonProperty("transaction_context")
    private Map<String, Object> transactionContext;

    @JsonProperty("velocity_snapshot")
    private Map<String, VelocityResult> velocitySnapshot;

    @JsonProperty("engine_metadata")
    private EngineMetadata engineMetadata;

    @JsonProperty("timing_breakdown")
    private TimingBreakdown timingBreakdown;

    public Decision() {
        this.decisionId = UUID.randomUUID().toString();
        this.timestamp = Instant.now();
    }

    public Decision(String transactionId, String evaluationType) {
        this();
        this.transactionId = transactionId;
        this.evaluationType = evaluationType;
    }

    public String getDecisionId() {
        return decisionId;
    }

    public void setDecisionId(String decisionId) {
        this.decisionId = decisionId;
    }

    public String getTransactionId() {
        return transactionId;
    }

    public void setTransactionId(String transactionId) {
        this.transactionId = transactionId;
    }

    public String getEvaluationType() {
        return evaluationType;
    }

    public void setEvaluationType(String evaluationType) {
        this.evaluationType = evaluationType;
    }

    public String getDecision() {
        return decision;
    }

    public void setDecision(String decision) {
        this.decision = decision;
    }

    public String getEngineMode() {
        return engineMode;
    }

    public void setEngineMode(String engineMode) {
        this.engineMode = engineMode;
    }

    public String getEngineErrorCode() {
        return engineErrorCode;
    }

    public void setEngineErrorCode(String engineErrorCode) {
        this.engineErrorCode = engineErrorCode;
    }

    public String getEngineErrorMessage() {
        return engineErrorMessage;
    }

    public void setEngineErrorMessage(String engineErrorMessage) {
        this.engineErrorMessage = engineErrorMessage;
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

    public String getRulesetId() {
        return rulesetId;
    }

    public void setRulesetId(String rulesetId) {
        this.rulesetId = rulesetId;
    }

    public List<MatchedRule> getMatchedRules() {
        return matchedRules;
    }

    public void setMatchedRules(List<MatchedRule> matchedRules) {
        this.matchedRules = matchedRules != null ? matchedRules : Collections.emptyList();
    }

    public void addMatchedRule(MatchedRule matchedRule) {
        if (!(this.matchedRules instanceof ArrayList)) {
            this.matchedRules = this.matchedRules.isEmpty()
                    ? new ArrayList<>(2)
                    : new ArrayList<>(this.matchedRules);
        }
        this.matchedRules.add(matchedRule);
    }

    public Map<String, VelocityResult> getVelocityResults() {
        return velocityResults;
    }

    public void setVelocityResults(Map<String, VelocityResult> velocityResults) {
        this.velocityResults = velocityResults != null ? velocityResults : Collections.emptyMap();
    }

    public void addVelocityResult(String key, VelocityResult result) {
        if (!(this.velocityResults instanceof HashMap)) {
            this.velocityResults = this.velocityResults.isEmpty()
                    ? new HashMap<>(2)
                    : new HashMap<>(this.velocityResults);
        }
        this.velocityResults.put(key, result);
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Instant timestamp) {
        this.timestamp = timestamp;
    }

    public long getProcessingTimeMs() {
        return processingTimeMs;
    }

    public void setProcessingTimeMs(long processingTimeMs) {
        this.processingTimeMs = processingTimeMs;
    }

    public DebugInfo getDebugInfo() {
        return debugInfo;
    }

    public void setDebugInfo(DebugInfo debugInfo) {
        this.debugInfo = debugInfo;
    }

    public Map<String, Object> getTransactionContext() {
        return transactionContext;
    }

    public void setTransactionContext(Map<String, Object> transactionContext) {
        this.transactionContext = transactionContext;
    }

    public Map<String, VelocityResult> getVelocitySnapshot() {
        return velocitySnapshot;
    }

    public void setVelocitySnapshot(Map<String, VelocityResult> velocitySnapshot) {
        this.velocitySnapshot = velocitySnapshot;
    }

    public EngineMetadata getEngineMetadata() {
        return engineMetadata;
    }

    public void setEngineMetadata(EngineMetadata engineMetadata) {
        this.engineMetadata = engineMetadata;
    }

    public TimingBreakdown getTimingBreakdown() {
        return timingBreakdown;
    }

    public void setTimingBreakdown(TimingBreakdown timingBreakdown) {
        this.timingBreakdown = timingBreakdown;
    }

    /**
     * Represents a rule that matched during evaluation.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class MatchedRule {

        @JsonProperty("rule_id")
        private String ruleId;

        @JsonProperty("rule_name")
        private String ruleName;

        @JsonProperty("action")
        private String action;

        @JsonProperty("priority")
        private int priority;

        @JsonProperty("conditions_met")
        private List<String> conditionsMet;

        @JsonProperty("condition_values")
        private Map<String, Object> conditionValues;

        @JsonProperty("rule_version")
        private Integer ruleVersion;

        @JsonProperty("rule_version_id")
        private String ruleVersionId;

        @JsonProperty("matched")
        private Boolean matched;

        @JsonProperty("contributing")
        private Boolean contributing;

        public MatchedRule() {
        }

        public MatchedRule(String ruleId, String ruleName, String action) {
            this.ruleId = ruleId;
            this.ruleName = ruleName;
            this.action = action;
        }

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

        public String getAction() {
            return action;
        }

        public void setAction(String action) {
            this.action = action;
        }

        public int getPriority() {
            return priority;
        }

        public void setPriority(int priority) {
            this.priority = priority;
        }

        public List<String> getConditionsMet() {
            return conditionsMet;
        }

        public void setConditionsMet(List<String> conditionsMet) {
            this.conditionsMet = conditionsMet;
        }

        public Map<String, Object> getConditionValues() {
            return conditionValues;
        }

        public void setConditionValues(Map<String, Object> conditionValues) {
            this.conditionValues = conditionValues;
        }

        public Integer getRuleVersion() {
            return ruleVersion;
        }

        public void setRuleVersion(Integer ruleVersion) {
            this.ruleVersion = ruleVersion;
        }

        public String getRuleVersionId() {
            return ruleVersionId;
        }

        public void setRuleVersionId(String ruleVersionId) {
            this.ruleVersionId = ruleVersionId;
        }

        public Boolean getMatched() {
            return matched;
        }

        public void setMatched(Boolean matched) {
            this.matched = matched;
        }

        public Boolean getContributing() {
            return contributing;
        }

        public void setContributing(Boolean contributing) {
            this.contributing = contributing;
        }
    }

    /**
     * Represents the result of a velocity check.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class VelocityResult {

        @JsonProperty("dimension")
        private String dimension;

        @JsonProperty("dimension_value")
        private String dimensionValue;

        @JsonProperty("count")
        private long count;

        @JsonProperty("threshold")
        private int threshold;

        @JsonProperty("window_seconds")
        private int windowSeconds;

        @JsonProperty("exceeded")
        private boolean exceeded;

        @JsonProperty("ttl_remaining")
        private Long ttlRemaining;

        public VelocityResult() {
        }

        public VelocityResult(String dimension, String dimensionValue, long count, int threshold, int windowSeconds) {
            this.dimension = dimension;
            this.dimensionValue = dimensionValue;
            this.count = count;
            this.threshold = threshold;
            this.windowSeconds = windowSeconds;
            this.exceeded = count >= threshold;
        }

        public String getDimension() {
            return dimension;
        }

        public void setDimension(String dimension) {
            this.dimension = dimension;
        }

        public String getDimensionValue() {
            return dimensionValue;
        }

        public void setDimensionValue(String dimensionValue) {
            this.dimensionValue = dimensionValue;
        }

        public long getCount() {
            return count;
        }

        public void setCount(long count) {
            this.count = count;
            this.exceeded = count >= threshold;
        }

        public int getThreshold() {
            return threshold;
        }

        public void setThreshold(int threshold) {
            this.threshold = threshold;
        }

        public int getWindowSeconds() {
            return windowSeconds;
        }

        public void setWindowSeconds(int windowSeconds) {
            this.windowSeconds = windowSeconds;
        }

        public boolean isExceeded() {
            return exceeded;
        }

        public void setExceeded(boolean exceeded) {
            this.exceeded = exceeded;
        }

        public Long getTtlRemaining() {
            return ttlRemaining;
        }

        public void setTtlRemaining(Long ttlRemaining) {
            this.ttlRemaining = ttlRemaining;
        }
    }

    /**
     * Engine mode constants.
     */
    public static final String MODE_NORMAL = "NORMAL";
    public static final String MODE_DEGRADED = "DEGRADED";
    public static final String MODE_FAIL_OPEN = "FAIL_OPEN";
    public static final String MODE_REPLAY = "REPLAY";

    /**
     * Decision constants.
     */
    public static final String DECISION_APPROVE = "APPROVE";
    public static final String DECISION_DECLINE = "DECLINE";
    public static final String DECISION_REVIEW = "REVIEW";

    /**
     * Engine mode enum for type-safe mode handling.
     */
    public enum EngineMode {
        NORMAL,
        DEGRADED,
        FAIL_OPEN,
        REPLAY;

        /**
         * Gets the string value for this mode.
         */
        public String getValue() {
            return name();
        }

        /**
         * Creates an EngineMode from a string value.
         */
        public static EngineMode fromValue(String value) {
            if (value == null) {
                return null;
            }
            try {
                return EngineMode.valueOf(value.toUpperCase());
            } catch (IllegalArgumentException e) {
                return null;
            }
        }
    }

    /**
     * Decision type enum for type-safe decision handling.
     */
    public enum DecisionType {
        APPROVE,
        DECLINE,
        REVIEW;

        /**
         * Gets the string value for this decision type.
         */
        public String getValue() {
            return name();
        }

        /**
         * Creates a DecisionType from a string value.
         */
        public static DecisionType fromValue(String value) {
            if (value == null) {
                return null;
            }
            try {
                return DecisionType.valueOf(value.toUpperCase());
            } catch (IllegalArgumentException e) {
                return null;
            }
        }
    }

    /**
     * Evaluation type enum for type-safe evaluation type handling.
     */
    public enum EvaluationType {
        AUTH,
        MONITORING,
        REPLAY;

        /**
         * Gets the string value for this evaluation type.
         */
        public String getValue() {
            return name();
        }

        /**
         * Creates an EvaluationType from a string value.
         */
        public static EvaluationType fromValue(String value) {
            if (value == null) {
                return null;
            }
            try {
                return EvaluationType.valueOf(value.toUpperCase());
            } catch (IllegalArgumentException e) {
                return null;
            }
        }
    }
}
