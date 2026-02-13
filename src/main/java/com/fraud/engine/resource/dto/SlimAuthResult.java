package com.fraud.engine.resource.dto;

import com.fraud.engine.domain.Decision;

/**
 * Ultra-slim AUTH response - only critical fields to minimize serialization overhead.
 *
 * Load test validates: decision, transaction_id
 * Callers need: decision, engine_mode, engine_error_code
 *
 * Estimated size: ~80 bytes (vs ~200 bytes for AuthResult, ~2-3KB for full Decision)
 * Serialization time with jsoniter: <0.1ms (vs 5ms with Jackson)
 */
public class SlimAuthResult {

    public String transaction_id;
    public String decision;           // APPROVE, DECLINE, REVIEW
    public String engine_mode;        // NORMAL, FAIL_OPEN, DEGRADED
    public String engine_error_code;  // null for success, error code on failure

    public SlimAuthResult() {
    }

    public static SlimAuthResult from(Decision d) {
        SlimAuthResult r = new SlimAuthResult();
        r.transaction_id = d.getTransactionId();
        r.decision = d.getDecision();
        r.engine_mode = d.getEngineMode();
        r.engine_error_code = d.getEngineErrorCode();
        return r;
    }
}
