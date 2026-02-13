package com.fraud.engine.resource.dto;

import org.eclipse.microprofile.openapi.annotations.media.Schema;
import com.fraud.engine.ruleset.RulesetRegistry;

import java.util.List;

/**
 * Bulk load request.
 */
@Schema(description = "Bulk load request")
public class BulkLoadRequest {

    @Schema(description = "List of rulesets to load")
    public List<RulesetRegistry.RulesetSpec> rulesets;

    public List<RulesetRegistry.RulesetSpec> getRulesets() {
        return rulesets;
    }

    public void setRulesets(List<RulesetRegistry.RulesetSpec> rulesets) {
        this.rulesets = rulesets;
    }
}
