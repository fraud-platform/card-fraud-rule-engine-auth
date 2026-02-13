package com.fraud.engine.resource.dto;

import com.fraud.engine.domain.Decision;
import org.eclipse.microprofile.openapi.annotations.media.Schema;

import java.util.ArrayList;
import java.util.List;

/**
 * Batch replay response.
 */
@Schema(description = "Batch replay response")
public class BatchReplayResponse {

    @Schema(description = "Total transactions")
    public int totalCount;

    @Schema(description = "Failed count")
    public int failureCount;

    @Schema(description = "Results")
    public List<BatchResult> results = new ArrayList<>();

    public int getTotalCount() {
        return totalCount;
    }

    public void setTotalCount(int totalCount) {
        this.totalCount = totalCount;
    }

    public int getFailureCount() {
        return failureCount;
    }

    public void setFailureCount(int failureCount) {
        this.failureCount = failureCount;
    }

    public List<BatchResult> getResults() {
        return results;
    }

    public void setResults(List<BatchResult> results) {
        this.results = results;
    }

    /**
     * Batch result.
     */
    @Schema(description = "Batch result")
    public static class BatchResult {

        @Schema(description = "Transaction ID")
        public String transactionId;

        @Schema(description = "Decision (if successful)")
        public Decision decision;

        @Schema(description = "Error message (if failed)")
        public String error;

        public BatchResult(String transactionId, Decision decision, String error) {
            this.transactionId = transactionId;
            this.decision = decision;
            this.error = error;
        }

        public String getTransactionId() {
            return transactionId;
        }

        public void setTransactionId(String transactionId) {
            this.transactionId = transactionId;
        }

        public Decision getDecision() {
            return decision;
        }

        public void setDecision(Decision decision) {
            this.decision = decision;
        }

        public String getError() {
            return error;
        }

        public void setError(String error) {
            this.error = error;
        }
    }
}
