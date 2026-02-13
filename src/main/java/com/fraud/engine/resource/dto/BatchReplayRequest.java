package com.fraud.engine.resource.dto;

import com.fraud.engine.domain.TransactionContext;
import org.eclipse.microprofile.openapi.annotations.media.Schema;

import java.util.List;

/**
 * Batch replay request.
 */
@Schema(description = "Batch replay request")
public class BatchReplayRequest {

    @Schema(description = "List of transactions to replay")
    public List<TransactionContext> transactions;

    @Schema(description = "Ruleset key", example = "CARD_AUTH")
    public String rulesetKey;

    @Schema(description = "Ruleset version (optional)")
    public Integer version;

    public List<TransactionContext> getTransactions() {
        return transactions;
    }

    public void setTransactions(List<TransactionContext> transactions) {
        this.transactions = transactions;
    }

    public String getRulesetKey() {
        return rulesetKey;
    }

    public void setRulesetKey(String rulesetKey) {
        this.rulesetKey = rulesetKey;
    }

    public Integer getVersion() {
        return version;
    }

    public void setVersion(Integer version) {
        this.version = version;
    }
}
