package com.fraud.engine.domain;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for DebugInfo domain model.
 */
class DebugInfoTest {

    @Test
    void testEmptyDebugInfo() {
        DebugInfo empty = DebugInfo.empty();

        assertNotNull(empty);
        assertNotNull(empty.getConditionEvaluations());
        assertNotNull(empty.getFieldValues());
        assertTrue(empty.getConditionEvaluations().isEmpty());
        assertTrue(empty.getFieldValues().isEmpty());
    }

    @Test
    void testDebugInfoBuilder() {
        DebugInfo.Builder builder = new DebugInfo.Builder();

        builder.rulesetKey("TEST_KEY")
                .compiledRulesetVersion("v1")
                .compilationTimestamp(123456789L);

        DebugInfo.ConditionEvaluation eval = new DebugInfo.ConditionEvaluation();
        eval.setRuleId("rule1");
        eval.setField("amount");
        eval.setOperator("GT");
        eval.setExpectedValue(1000);
        eval.setActualValue(5000);
        eval.setMatched(true);
        eval.setEvaluationTimeNanos(1000);
        eval.setExplanation("amount(5000) > 1000 = true");

        builder.addConditionEvaluation(eval);
        builder.addFieldValue("amount", 5000);
        builder.addFieldValue("currency", "USD");

        DebugInfo debugInfo = builder.build();

        assertEquals("TEST_KEY", debugInfo.getRulesetKey());
        assertEquals("v1", debugInfo.getCompiledRulesetVersion());
        assertEquals(123456789L, debugInfo.getCompilationTimestamp());
        assertEquals(1, debugInfo.getConditionEvaluations().size());
        assertEquals(2, debugInfo.getFieldValues().size());
        assertEquals(5000, debugInfo.getFieldValues().get("amount"));
    }

    @Test
    void testConditionEvaluation() {
        DebugInfo.ConditionEvaluation eval = new DebugInfo.ConditionEvaluation(
                "rule-1",
                "Test Rule",
                "amount",
                "GT",
                1000,
                5000,
                true,
                1500,
                "amount(5000) > 1000 = true"
        );

        assertEquals("rule-1", eval.getRuleId());
        assertEquals("Test Rule", eval.getRuleName());
        assertEquals("amount", eval.getField());
        assertEquals("GT", eval.getOperator());
        assertEquals(1000, eval.getExpectedValue());
        assertEquals(5000, eval.getActualValue());
        assertTrue(eval.isMatched());
        assertEquals(1500, eval.getEvaluationTimeNanos());
        assertEquals("amount(5000) > 1000 = true", eval.getExplanation());
    }

    @Test
    void testEvaluationTiming() {
        DebugInfo.EvaluationTiming timing = new DebugInfo.EvaluationTiming();

        timing.setCompilationNanos(1000L);
        timing.setEvaluationNanos(2000L);
        timing.setVelocityNanos(500L);

        assertNotNull(timing.getCompilationNanos());
        assertNotNull(timing.getEvaluationNanos());
        assertNotNull(timing.getVelocityNanos());
        assertNotNull(timing.getTotalNanos());

        // Total should be calculated
        assertEquals(3500L, timing.getTotalNanos());

        // Constructor version
        DebugInfo.EvaluationTiming timing2 = new DebugInfo.EvaluationTiming(100L, 200L, 50L);
        assertEquals(350L, timing2.getTotalNanos());
    }

    @Test
    void testDebugInfoJsonFields() {
        DebugInfo debugInfo = new DebugInfo();

        debugInfo.setRulesetKey("CARD_AUTH");
        debugInfo.setCompiledRulesetVersion("v5");
        debugInfo.setCompilationTimestamp(System.currentTimeMillis());

        DebugInfo.ConditionEvaluation eval = new DebugInfo.ConditionEvaluation();
        eval.setRuleId("rule1");
        eval.setMatched(true);
        debugInfo.addConditionEvaluation(eval);

        // Verify the data is set correctly
        assertEquals("CARD_AUTH", debugInfo.getRulesetKey());
        assertEquals("v5", debugInfo.getCompiledRulesetVersion());
        assertFalse(debugInfo.getConditionEvaluations().isEmpty());
        assertEquals("rule1", debugInfo.getConditionEvaluations().get(0).getRuleId());
    }
}
