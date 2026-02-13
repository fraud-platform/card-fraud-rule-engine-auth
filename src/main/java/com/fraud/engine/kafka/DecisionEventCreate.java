package com.fraud.engine.kafka;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fraud.engine.domain.Decision;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Decision event for publishing to transaction-management via Kafka.
 * Matches the DecisionEventCreate schema from transaction-management's OpenAPI spec.
 *
 * <p>Required fields:
 * - transaction_id: Business transaction ID (idempotency key)
 * - occurred_at: When the transaction occurred
 * - produced_at: When the decision was produced
 * - transaction: Transaction details
 * - decision: APPROVE, DECLINE
 * - decision_reason: RULE_MATCH, VELOCITY_MATCH, SYSTEM_DECLINE, DEFAULT_ALLOW
 *
 * <p>Optional fields:
 * - event_version: Event schema version
 * - matched_rules: List of rules that matched
 * - risk_level: LOW, MEDIUM, HIGH, CRITICAL
 * - transaction_context: Full payload from rule engine
 * - velocity_snapshot: All velocity states at decision time
 * - engine_metadata: Engine mode, timing, errors
 * - raw_payload: Allowlist of original fields (PCI-safe)
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class DecisionEventCreate {

    @JsonProperty("event_version")
    private String eventVersion = "1.0";

    @JsonProperty("transaction_id")
    private String transactionId;

    @JsonProperty("occurred_at")
    private String occurredAt;

    @JsonProperty("produced_at")
    private String producedAt;

    @JsonProperty("transaction")
    private TransactionDetails transaction;

    @JsonProperty("decision")
    private String decision;

    @JsonProperty("decision_reason")
    private String decisionReason;

    @JsonProperty("evaluation_type")
    private String evaluationType;

    @JsonProperty("ruleset_key")
    private String rulesetKey;

    @JsonProperty("ruleset_version")
    private Integer rulesetVersion;

    @JsonProperty("ruleset_id")
    private String rulesetId;


    @JsonProperty("matched_rules")
    private List<RuleMatch> matchedRules;

    @JsonProperty("risk_level")
    private String riskLevel;

    @JsonProperty("transaction_context")
    private Map<String, Object> transactionContext;

    @JsonProperty("velocity_results")
    private Map<String, Decision.VelocityResult> velocityResults;

    @JsonProperty("velocity_snapshot")
    private Map<String, Decision.VelocityResult> velocitySnapshot;

    @JsonProperty("engine_metadata")
    private EngineMetadata engineMetadata;

    @JsonProperty("raw_payload")
    private Map<String, Object> rawPayload;

    // ========== Getters/Setters ==========

    public String getEventVersion() {
        return eventVersion;
    }

    public void setEventVersion(String eventVersion) {
        this.eventVersion = eventVersion;
    }

    public String getTransactionId() {
        return transactionId;
    }

    public void setTransactionId(String transactionId) {
        this.transactionId = transactionId;
    }

    public String getOccurredAt() {
        return occurredAt;
    }

    public void setOccurredAt(String occurredAt) {
        this.occurredAt = occurredAt;
    }

    public String getProducedAt() {
        return producedAt;
    }

    public void setProducedAt(String producedAt) {
        this.producedAt = producedAt;
    }

    public TransactionDetails getTransaction() {
        return transaction;
    }

    public void setTransaction(TransactionDetails transaction) {
        this.transaction = transaction;
    }

    public String getDecision() {
        return decision;
    }

    public void setDecision(String decision) {
        this.decision = decision;
    }

    public String getDecisionReason() {
        return decisionReason;
    }

    public void setDecisionReason(String decisionReason) {
        this.decisionReason = decisionReason;
    }

    public String getEvaluationType() {
        return evaluationType;
    }

    public void setEvaluationType(String evaluationType) {
        this.evaluationType = evaluationType;
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

    public List<RuleMatch> getMatchedRules() {
        return matchedRules;
    }

    public void setMatchedRules(List<RuleMatch> matchedRules) {
        this.matchedRules = matchedRules;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(String riskLevel) {
        this.riskLevel = riskLevel;
    }

    public Map<String, Object> getTransactionContext() {
        return transactionContext;
    }

    public void setTransactionContext(Map<String, Object> transactionContext) {
        this.transactionContext = transactionContext;
    }

    public Map<String, Decision.VelocityResult> getVelocityResults() {
        return velocityResults;
    }

    public void setVelocityResults(Map<String, Decision.VelocityResult> velocityResults) {
        this.velocityResults = velocityResults;
    }

    public Map<String, Decision.VelocityResult> getVelocitySnapshot() {
        return velocitySnapshot;
    }

    public void setVelocitySnapshot(Map<String, Decision.VelocityResult> velocitySnapshot) {
        this.velocitySnapshot = velocitySnapshot;
    }

    public EngineMetadata getEngineMetadata() {
        return engineMetadata;
    }

    public void setEngineMetadata(EngineMetadata engineMetadata) {
        this.engineMetadata = engineMetadata;
    }

    public Map<String, Object> getRawPayload() {
        return rawPayload;
    }

    public void setRawPayload(Map<String, Object> rawPayload) {
        this.rawPayload = rawPayload;
    }

    // ========== Nested Classes ==========

    /**
     * Transaction details for the decision event.
     * PCI-safe - contains only tokenized identifiers.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class TransactionDetails {

        @JsonProperty("card_id")
        private String cardId;

        @JsonProperty("card_last4")
        private String cardLast4;

        @JsonProperty("card_network")
        private String cardNetwork;

        @JsonProperty("amount")
        private Object amount;

        @JsonProperty("currency")
        private String currency;

        @JsonProperty("country")
        private String country;

        @JsonProperty("merchant_id")
        private String merchantId;

        @JsonProperty("mcc")
        private String mcc;

        @JsonProperty("ip_address")
        private String ipAddress;

        // ========== Getters/Setters ==========

        public String getCardId() {
            return cardId;
        }

        public void setCardId(String cardId) {
            this.cardId = cardId;
        }

        public String getCardLast4() {
            return cardLast4;
        }

        public void setCardLast4(String cardLast4) {
            this.cardLast4 = cardLast4;
        }

        public String getCardNetwork() {
            return cardNetwork;
        }

        public void setCardNetwork(String cardNetwork) {
            this.cardNetwork = cardNetwork;
        }

        public Object getAmount() {
            return amount;
        }

        public void setAmount(Object amount) {
            this.amount = amount;
        }

        public String getCurrency() {
            return currency;
        }

        public void setCurrency(String currency) {
            this.currency = currency;
        }

        public String getCountry() {
            return country;
        }

        public void setCountry(String country) {
            this.country = country;
        }

        public String getMerchantId() {
            return merchantId;
        }

        public void setMerchantId(String merchantId) {
            this.merchantId = merchantId;
        }

        public String getMcc() {
            return mcc;
        }

        public void setMcc(String mcc) {
            this.mcc = mcc;
        }

        public String getIpAddress() {
            return ipAddress;
        }

        public void setIpAddress(String ipAddress) {
            this.ipAddress = ipAddress;
        }
    }

    /**
     * Rule match details for the decision event.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class RuleMatch {

        @JsonProperty("rule_id")
        private String ruleId;

        @JsonProperty("rule_version")
        private Integer ruleVersion;

        @JsonProperty("rule_version_id")
        private String ruleVersionId;

        @JsonProperty("rule_name")
        private String ruleName;

        @JsonProperty("priority")
        private Integer priority;

        @JsonProperty("matched_at")
        private String matchedAt;

        @JsonProperty("rule_type")
        private String ruleType;

        @JsonProperty("match_reason_text")
        private String matchReasonText;

        @JsonProperty("rule_action")
        private String ruleAction;

        @JsonProperty("conditions_met")
        private List<String> conditionsMet;

        @JsonProperty("condition_values")
        private Map<String, Object> conditionValues;

        // ========== Getters/Setters ==========

        public String getRuleId() {
            return ruleId;
        }

        public void setRuleId(String ruleId) {
            this.ruleId = ruleId;
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

        public String getRuleName() {
            return ruleName;
        }

        public void setRuleName(String ruleName) {
            this.ruleName = ruleName;
        }

        public Integer getPriority() {
            return priority;
        }

        public void setPriority(Integer priority) {
            this.priority = priority;
        }

        public String getMatchedAt() {
            return matchedAt;
        }

        public void setMatchedAt(String matchedAt) {
            this.matchedAt = matchedAt;
        }

        public String getRuleType() {
            return ruleType;
        }

        public void setRuleType(String ruleType) {
            this.ruleType = ruleType;
        }

        public String getMatchReasonText() {
            return matchReasonText;
        }

        public void setMatchReasonText(String matchReasonText) {
            this.matchReasonText = matchReasonText;
        }

        public String getRuleAction() {
            return ruleAction;
        }

        public void setRuleAction(String ruleAction) {
            this.ruleAction = ruleAction;
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
    }

    /**
     * Engine metadata for the decision event.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class EngineMetadata {

        @JsonProperty("engine_mode")
        private String engineMode;

        @JsonProperty("error_code")
        private String errorCode;

        @JsonProperty("error_message")
        private String errorMessage;

        @JsonProperty("processing_time_ms")
        private Double processingTimeMs;

        @JsonProperty("rule_engine_version")
        private String ruleEngineVersion;

        // ========== Getters/Setters ==========

        public String getEngineMode() {
            return engineMode;
        }

        public void setEngineMode(String engineMode) {
            this.engineMode = engineMode;
        }

        public String getErrorCode() {
            return errorCode;
        }

        public void setErrorCode(String errorCode) {
            this.errorCode = errorCode;
        }

        public String getErrorMessage() {
            return errorMessage;
        }

        public void setErrorMessage(String errorMessage) {
            this.errorMessage = errorMessage;
        }

        public Double getProcessingTimeMs() {
            return processingTimeMs;
        }

        public void setProcessingTimeMs(Double processingTimeMs) {
            this.processingTimeMs = processingTimeMs;
        }

        public String getRuleEngineVersion() {
            return ruleEngineVersion;
        }

        public void setRuleEngineVersion(String ruleEngineVersion) {
            this.ruleEngineVersion = ruleEngineVersion;
        }
    }
}
