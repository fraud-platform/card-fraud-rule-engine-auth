package com.fraud.engine.util;

import com.fraud.engine.domain.Decision;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class DecisionNormalizerTest {

    @Test
    void testNormalizeDecisionValue_ApproveVariants() {
        assertThat(DecisionNormalizer.normalizeDecisionValue("APPROVE")).isEqualTo(Decision.DECISION_APPROVE);
        assertThat(DecisionNormalizer.normalizeDecisionValue("approve")).isEqualTo(Decision.DECISION_APPROVE);
        assertThat(DecisionNormalizer.normalizeDecisionValue("ALLOW")).isEqualTo(Decision.DECISION_APPROVE);
    }

    @Test
    void testNormalizeDecisionValue_DeclineVariants() {
        assertThat(DecisionNormalizer.normalizeDecisionValue("DECLINE")).isEqualTo(Decision.DECISION_DECLINE);
        assertThat(DecisionNormalizer.normalizeDecisionValue("decline")).isEqualTo(Decision.DECISION_DECLINE);
        assertThat(DecisionNormalizer.normalizeDecisionValue("BLOCK")).isEqualTo(Decision.DECISION_DECLINE);
    }

    @Test
    void testNormalizeDecisionValue_ReviewVariants() {
        assertThat(DecisionNormalizer.normalizeDecisionValue("REVIEW")).isEqualTo(Decision.DECISION_REVIEW);
        assertThat(DecisionNormalizer.normalizeDecisionValue("review")).isEqualTo(Decision.DECISION_REVIEW);
        assertThat(DecisionNormalizer.normalizeDecisionValue("FLAG")).isEqualTo(Decision.DECISION_REVIEW);
    }

    @Test
    void testNormalizeDecisionValue_UnknownValue() {
        assertThat(DecisionNormalizer.normalizeDecisionValue("UNKNOWN")).isEqualTo("UNKNOWN");
        assertThat(DecisionNormalizer.normalizeDecisionValue("random")).isEqualTo("RANDOM");
    }

    @Test
    void testNormalizeDecisionValue_Null() {
        assertThat(DecisionNormalizer.normalizeDecisionValue(null)).isNull();
    }

    @Test
    void testNormalizeDecisionValue_Empty() {
        assertThat(DecisionNormalizer.normalizeDecisionValue("")).isNull();
        assertThat(DecisionNormalizer.normalizeDecisionValue("   ")).isNull();
    }

    @Test
    void testNormalizeDecisionValue_WithWhitespace() {
        assertThat(DecisionNormalizer.normalizeDecisionValue("  APPROVE  ")).isEqualTo(Decision.DECISION_APPROVE);
        assertThat(DecisionNormalizer.normalizeDecisionValue("\tDECLINE\t")).isEqualTo(Decision.DECISION_DECLINE);
    }

    @Test
    void testNormalizeDecisionType_WithValidValue() {
        assertThat(DecisionNormalizer.normalizeDecisionType("APPROVE", "REVIEW")).isEqualTo(Decision.DECISION_APPROVE);
        assertThat(DecisionNormalizer.normalizeDecisionType("DECLINE", "REVIEW")).isEqualTo(Decision.DECISION_DECLINE);
        assertThat(DecisionNormalizer.normalizeDecisionType("REVIEW", "APPROVE")).isEqualTo(Decision.DECISION_REVIEW);
    }

    @Test
    void testNormalizeDecisionType_WithFallback() {
        assertThat(DecisionNormalizer.normalizeDecisionType("INVALID", "REVIEW")).isEqualTo("REVIEW");
        assertThat(DecisionNormalizer.normalizeDecisionType(null, "APPROVE")).isEqualTo("APPROVE");
        assertThat(DecisionNormalizer.normalizeDecisionType("", "DECLINE")).isEqualTo("DECLINE");
    }

    @Test
    void testNormalizeMONITORINGDecision_ApproveVariants() {
        assertThat(DecisionNormalizer.normalizeMONITORINGDecision("APPROVE")).isEqualTo(Decision.DECISION_APPROVE);
        assertThat(DecisionNormalizer.normalizeMONITORINGDecision("APPROVED")).isEqualTo(Decision.DECISION_APPROVE);
        assertThat(DecisionNormalizer.normalizeMONITORINGDecision("ALLOW")).isEqualTo(Decision.DECISION_APPROVE);
    }

    @Test
    void testNormalizeMONITORINGDecision_DeclineVariants() {
        assertThat(DecisionNormalizer.normalizeMONITORINGDecision("DECLINE")).isEqualTo(Decision.DECISION_DECLINE);
        assertThat(DecisionNormalizer.normalizeMONITORINGDecision("DECLINED")).isEqualTo(Decision.DECISION_DECLINE);
        assertThat(DecisionNormalizer.normalizeMONITORINGDecision("BLOCK")).isEqualTo(Decision.DECISION_DECLINE);
    }

    @Test
    void testNormalizeMONITORINGDecision_InvalidValue() {
        assertThat(DecisionNormalizer.normalizeMONITORINGDecision("REVIEW")).isNull();
        assertThat(DecisionNormalizer.normalizeMONITORINGDecision("INVALID")).isNull();
    }

    @Test
    void testNormalizeMONITORINGDecision_Null() {
        assertThat(DecisionNormalizer.normalizeMONITORINGDecision(null)).isNull();
    }

    @Test
    void testNormalizeMONITORINGDecision_Empty() {
        assertThat(DecisionNormalizer.normalizeMONITORINGDecision("")).isNull();
        assertThat(DecisionNormalizer.normalizeMONITORINGDecision("   ")).isNull();
    }

    @Test
    void testNormalizeAction() {
        assertThat(DecisionNormalizer.normalizeAction("approve")).isEqualTo("APPROVE");
        assertThat(DecisionNormalizer.normalizeAction("  DECLINE  ")).isEqualTo("DECLINE");
        assertThat(DecisionNormalizer.normalizeAction(null)).isNull();
        assertThat(DecisionNormalizer.normalizeAction("")).isNull();
    }

    @Test
    void testNormalizeRuleAction_Approve() {
        assertThat(DecisionNormalizer.normalizeRuleAction("APPROVE")).isEqualTo("APPROVE");
        assertThat(DecisionNormalizer.normalizeRuleAction("approve")).isEqualTo("APPROVE");
        assertThat(DecisionNormalizer.normalizeRuleAction("ALLOW")).isEqualTo("APPROVE");
        assertThat(DecisionNormalizer.normalizeRuleAction("APPROVED")).isEqualTo("APPROVE");
    }

    @Test
    void testNormalizeRuleAction_Decline() {
        assertThat(DecisionNormalizer.normalizeRuleAction("DECLINE")).isEqualTo("DECLINE");
        assertThat(DecisionNormalizer.normalizeRuleAction("decline")).isEqualTo("DECLINE");
        assertThat(DecisionNormalizer.normalizeRuleAction("BLOCK")).isEqualTo("DECLINE");
        assertThat(DecisionNormalizer.normalizeRuleAction("DECLINED")).isEqualTo("DECLINE");
    }

    @Test
    void testNormalizeRuleAction_Review() {
        assertThat(DecisionNormalizer.normalizeRuleAction("REVIEW")).isEqualTo("REVIEW");
        assertThat(DecisionNormalizer.normalizeRuleAction("FLAG")).isEqualTo("REVIEW");
    }

    @Test
    void testNormalizeRuleAction_InvalidValue() {
        assertThat(DecisionNormalizer.normalizeRuleAction("INVALID")).isNull();
        assertThat(DecisionNormalizer.normalizeRuleAction("random")).isNull();
    }

    @Test
    void testNormalizeRuleAction_Null() {
        assertThat(DecisionNormalizer.normalizeRuleAction(null)).isNull();
    }

    @Test
    void testNormalizeRuleAction_Empty() {
        assertThat(DecisionNormalizer.normalizeRuleAction("")).isNull();
        assertThat(DecisionNormalizer.normalizeRuleAction("   ")).isNull();
    }
}
