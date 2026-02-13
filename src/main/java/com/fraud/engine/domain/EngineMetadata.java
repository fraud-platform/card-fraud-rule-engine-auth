package com.fraud.engine.domain;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Objects;

/**
 * Metadata about the engine that processed a decision.
 * Contains operational details like mode, timing, errors, and version.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class EngineMetadata {

    @JsonProperty("engine_mode")
    private String engineMode;

    @JsonProperty("error_code")
    private String errorCode;

    @JsonProperty("error_message")
    private String errorMessage;

    @JsonProperty("processing_time_ms")
    private double processingTimeMs;

    @JsonProperty("rule_engine_version")
    private String ruleEngineVersion;

    public EngineMetadata() {
    }

    public EngineMetadata(String engineMode, double processingTimeMs) {
        this.engineMode = engineMode;
        this.processingTimeMs = processingTimeMs;
    }

    public EngineMetadata(String engineMode, String errorCode, String errorMessage, 
                          double processingTimeMs, String ruleEngineVersion) {
        this.engineMode = engineMode;
        this.errorCode = errorCode;
        this.errorMessage = errorMessage;
        this.processingTimeMs = processingTimeMs;
        this.ruleEngineVersion = ruleEngineVersion;
    }

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

    public double getProcessingTimeMs() {
        return processingTimeMs;
    }

    public void setProcessingTimeMs(double processingTimeMs) {
        this.processingTimeMs = processingTimeMs;
    }

    public String getRuleEngineVersion() {
        return ruleEngineVersion;
    }

    public void setRuleEngineVersion(String ruleEngineVersion) {
        this.ruleEngineVersion = ruleEngineVersion;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EngineMetadata that = (EngineMetadata) o;
        return Double.compare(that.processingTimeMs, processingTimeMs) == 0 &&
                Objects.equals(engineMode, that.engineMode) &&
                Objects.equals(errorCode, that.errorCode) &&
                Objects.equals(errorMessage, that.errorMessage) &&
                Objects.equals(ruleEngineVersion, that.ruleEngineVersion);
    }

    @Override
    public int hashCode() {
        return Objects.hash(engineMode, errorCode, errorMessage, processingTimeMs, ruleEngineVersion);
    }

    @Override
    public String toString() {
        return "EngineMetadata{" +
                "engineMode='" + engineMode + '\'' +
                ", errorCode='" + errorCode + '\'' +
                ", errorMessage='" + errorMessage + '\'' +
                ", processingTimeMs=" + processingTimeMs +
                ", ruleEngineVersion='" + ruleEngineVersion + '\'' +
                '}';
    }
}
