package com.fraud.engine.resource.dto;

import com.fraud.engine.domain.Decision;
import org.eclipse.microprofile.openapi.annotations.media.Schema;

/**
 * Replay response.
 */
@Schema(description = "Replay response")
public class ReplayResponse {

    @Schema(description = "Decision result")
    public Decision decision;

    @Schema(description = "Ruleset version used")
    public int rulesetVersion;

    public ReplayResponse(Decision decision, int rulesetVersion) {
        this.decision = decision;
        this.rulesetVersion = rulesetVersion;
    }

    public Decision getDecision() {
        return decision;
    }

    public void setDecision(Decision decision) {
        this.decision = decision;
    }

    public int getRulesetVersion() {
        return rulesetVersion;
    }

    public void setRulesetVersion(int rulesetVersion) {
        this.rulesetVersion = rulesetVersion;
    }
}
