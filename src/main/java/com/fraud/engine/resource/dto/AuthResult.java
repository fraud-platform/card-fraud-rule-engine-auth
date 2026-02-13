package com.fraud.engine.resource.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fraud.engine.domain.Decision;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthResult {

    @JsonProperty("decision_id")
    private String decisionId;

    @JsonProperty("transaction_id")
    private String transactionId;

    @JsonProperty("decision")
    private String decision;

    @JsonProperty("engine_mode")
    private String engineMode;

    @JsonProperty("engine_error_code")
    private String engineErrorCode;

    @JsonProperty("processing_time_ms")
    private long processingTimeMs;

    @JsonProperty("ruleset_key")
    private String rulesetKey;

    @JsonProperty("ruleset_version")
    private Integer rulesetVersion;

    public AuthResult() {
    }

    public static AuthResult from(Decision d) {
        AuthResult r = new AuthResult();
        r.decisionId = d.getDecisionId();
        r.transactionId = d.getTransactionId();
        r.decision = d.getDecision();
        r.engineMode = d.getEngineMode();
        r.engineErrorCode = d.getEngineErrorCode();
        r.processingTimeMs = d.getProcessingTimeMs();
        r.rulesetKey = d.getRulesetKey();
        r.rulesetVersion = d.getRulesetVersion();
        return r;
    }

    public String getDecisionId() {
        return decisionId;
    }

    public String getTransactionId() {
        return transactionId;
    }

    public String getDecision() {
        return decision;
    }

    public String getEngineMode() {
        return engineMode;
    }

    public String getEngineErrorCode() {
        return engineErrorCode;
    }

    public long getProcessingTimeMs() {
        return processingTimeMs;
    }

    public String getRulesetKey() {
        return rulesetKey;
    }

    public Integer getRulesetVersion() {
        return rulesetVersion;
    }
}
