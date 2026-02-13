package com.fraud.engine.domain;

import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class DecisionTest {

    @Test
    void testDecisionCreation() {
        Decision decision = new Decision("txn-123", "AUTH");

        assertThat(decision.getDecisionId()).isNotNull();
        assertThat(decision.getTransactionId()).isEqualTo("txn-123");
        assertThat(decision.getEvaluationType()).isEqualTo("AUTH");
        assertThat(decision.getTimestamp()).isNotNull();
    }

    @Test
    void testDecisionModes() {
        Decision decision = new Decision("txn-123", "AUTH");

        assertThat(decision.getEngineMode()).isNull();

        decision.setEngineMode(Decision.MODE_NORMAL);
        assertThat(decision.getEngineMode()).isEqualTo("NORMAL");

        decision.setEngineMode(Decision.MODE_DEGRADED);
        assertThat(decision.getEngineMode()).isEqualTo("DEGRADED");

        decision.setEngineMode(Decision.MODE_FAIL_OPEN);
        assertThat(decision.getEngineMode()).isEqualTo("FAIL_OPEN");
    }

    @Test
    void testDecisionConstants() {
        assertThat(Decision.MODE_NORMAL).isEqualTo("NORMAL");
        assertThat(Decision.MODE_DEGRADED).isEqualTo("DEGRADED");
        assertThat(Decision.MODE_FAIL_OPEN).isEqualTo("FAIL_OPEN");
        assertThat(Decision.DECISION_APPROVE).isEqualTo("APPROVE");
        assertThat(Decision.DECISION_DECLINE).isEqualTo("DECLINE");
        assertThat(Decision.DECISION_REVIEW).isEqualTo("REVIEW");
    }

    @Test
    void testMatchedRule() {
        Decision.MatchedRule matchedRule = new Decision.MatchedRule(
                "rule-001", "High Amount", "REVIEW"
        );
        matchedRule.setPriority(100);
        matchedRule.setConditionsMet(List.of("amount > 100"));

        assertThat(matchedRule.getRuleId()).isEqualTo("rule-001");
        assertThat(matchedRule.getRuleName()).isEqualTo("High Amount");
        assertThat(matchedRule.getAction()).isEqualTo("REVIEW");
        assertThat(matchedRule.getPriority()).isEqualTo(100);
        assertThat(matchedRule.getConditionsMet()).hasSize(1);
    }

    @Test
    void testVelocityResult() {
        Decision.VelocityResult velocityResult = new Decision.VelocityResult(
                "card_hash", "abc123hash", 5, 10, 3600
        );

        assertThat(velocityResult.getDimension()).isEqualTo("card_hash");
        assertThat(velocityResult.getDimensionValue()).isEqualTo("abc123hash");
        assertThat(velocityResult.getCount()).isEqualTo(5);
        assertThat(velocityResult.getThreshold()).isEqualTo(10);
        assertThat(velocityResult.getWindowSeconds()).isEqualTo(3600);
        assertThat(velocityResult.isExceeded()).isFalse();

        velocityResult.setCount(15);
        assertThat(velocityResult.isExceeded()).isTrue();
    }

    @Test
    void testAddMatchedRule() {
        Decision decision = new Decision("txn-123", "AUTH");
        Decision.MatchedRule matchedRule = new Decision.MatchedRule(
                "rule-001", "High Amount", "REVIEW"
        );

        decision.addMatchedRule(matchedRule);

        assertThat(decision.getMatchedRules()).hasSize(1);
        assertThat(decision.getMatchedRules().get(0)).isEqualTo(matchedRule);
    }

    @Test
    void testAddVelocityResult() {
        Decision decision = new Decision("txn-123", "AUTH");
        Decision.VelocityResult velocityResult = new Decision.VelocityResult(
                "card_hash", "abc123hash", 5, 10, 3600
        );

        decision.addVelocityResult("rule-001", velocityResult);

        assertThat(decision.getVelocityResults()).containsKey("rule-001");
        assertThat(decision.getVelocityResults().get("rule-001")).isEqualTo(velocityResult);
    }

    @Test
    void testProcessingTime() {
        Decision decision = new Decision("txn-123", "AUTH");

        assertThat(decision.getProcessingTimeMs()).isEqualTo(0);

        decision.setProcessingTimeMs(150);
        assertThat(decision.getProcessingTimeMs()).isEqualTo(150);
    }

    @Test
    void testRulesetInfo() {
        Decision decision = new Decision("txn-123", "AUTH");

        decision.setRulesetKey("CARD_AUTH");
        decision.setRulesetVersion(5);

        assertThat(decision.getRulesetKey()).isEqualTo("CARD_AUTH");
        assertThat(decision.getRulesetVersion()).isEqualTo(5);
    }

    @Test
    void testErrorInfo() {
        Decision decision = new Decision("txn-123", "AUTH");

        decision.setEngineErrorCode("RULESET_NOT_FOUND");
        decision.setEngineErrorMessage("Ruleset CARD_AUTH not found");

        assertThat(decision.getEngineErrorCode()).isEqualTo("RULESET_NOT_FOUND");
        assertThat(decision.getEngineErrorMessage()).isEqualTo("Ruleset CARD_AUTH not found");
    }

    @Test
    void testDecisionSetters() {
        Decision decision = new Decision("txn-123", "AUTH");

        decision.setDecision(Decision.DECISION_DECLINE);

        assertThat(decision.getDecision()).isEqualTo("DECLINE");
    }

    @Test
    void testMatchedRuleConditionsMet() {
        Decision.MatchedRule matchedRule = new Decision.MatchedRule();

        matchedRule.setConditionsMet(List.of("amount > 100", "country_code = US"));

        assertThat(matchedRule.getConditionsMet()).hasSize(2);
    }
}
