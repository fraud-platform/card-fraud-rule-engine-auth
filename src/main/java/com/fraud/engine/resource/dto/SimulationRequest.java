package com.fraud.engine.resource.dto;

import com.fraud.engine.domain.TransactionContext;
import org.eclipse.microprofile.openapi.annotations.media.Schema;

/**
 * Simulation request.
 */
@Schema(description = "Simulation request")
public class SimulationRequest {

    @Schema(description = "Transaction context")
    public TransactionContext transaction;

    @Schema(description = "Ruleset YAML content")
    public String rulesetYaml;

    @Schema(description = "Include debug info in response", defaultValue = "false")
    public boolean includeDebug = false;

    public TransactionContext getTransaction() {
        return transaction;
    }

    public void setTransaction(TransactionContext transaction) {
        this.transaction = transaction;
    }

    public String getRulesetYaml() {
        return rulesetYaml;
    }

    public void setRulesetYaml(String rulesetYaml) {
        this.rulesetYaml = rulesetYaml;
    }

    public boolean isIncludeDebug() {
        return includeDebug;
    }

    public void setIncludeDebug(boolean includeDebug) {
        this.includeDebug = includeDebug;
    }
}
