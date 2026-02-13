package com.fraud.engine.resource.dto;

import com.fraud.engine.domain.TransactionContext;
import org.eclipse.microprofile.openapi.annotations.media.Schema;

/**
 * Replay request.
 */
@Schema(description = "Replay request")
public class ReplayRequest {

    @Schema(description = "Transaction ID", example = "txn-12345")
    public String transactionId;

    @Schema(description = "Transaction context")
    public TransactionContext transaction;

    @Schema(description = "Ruleset key (optional, defaults to CARD_AUTH)", example = "CARD_AUTH")
    public String rulesetKey;

    @Schema(description = "Specific ruleset version (optional, defaults to latest)", example = "1")
    public Integer version;

    public String getTransactionId() {
        return transactionId;
    }

    public void setTransactionId(String transactionId) {
        this.transactionId = transactionId;
    }

    public TransactionContext getTransaction() {
        return transaction;
    }

    public void setTransaction(TransactionContext transaction) {
        this.transaction = transaction;
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
