package com.fraud.engine.domain;

import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class RuleTest {

    @Test
    void testRuleCreation() {
        Rule rule = new Rule("rule-001", "High Amount", "DECLINE");

        assertThat(rule.getId()).isEqualTo("rule-001");
        assertThat(rule.getName()).isEqualTo("High Amount");
        assertThat(rule.getAction()).isEqualTo("DECLINE");
        assertThat(rule.isEnabled()).isTrue();
        assertThat(rule.getPriority()).isZero();
    }

    @Test
    void testRuleWithConditions() {
        Rule rule = new Rule("rule-001", "High Amount", "DECLINE");
        rule.setPriority(100);

        Condition condition1 = new Condition("amount", "gt", 1000);
        Condition condition2 = new Condition("country_code", "eq", "US");

        rule.addCondition(condition1);
        rule.addCondition(condition2);

        assertThat(rule.getConditions()).hasSize(2);
    }

    @Test
    void testDisabledRuleMatchesReturnsFalse() {
        Rule rule = new Rule("rule-001", "Test Rule", "DECLINE");
        rule.setEnabled(false);

        java.util.Map<String, Object> context = new java.util.HashMap<>();
        context.put("amount", 100);

        assertThat(rule.matches(context)).isFalse();
    }

    @Test
    void testRuleWithNoConditionsMatchesReturnsFalse() {
        Rule rule = new Rule("rule-001", "Test Rule", "DECLINE");

        java.util.Map<String, Object> context = new java.util.HashMap<>();
        context.put("amount", 100);

        assertThat(rule.matches(context)).isFalse();
    }

    @Test
    void testRuleMatchesWhenAllConditionsMet() {
        Rule rule = new Rule("rule-001", "Test Rule", "DECLINE");
        rule.addCondition(new Condition("amount", "gt", 100));
        rule.addCondition(new Condition("country_code", "eq", "US"));

        java.util.Map<String, Object> context = new java.util.HashMap<>();
        context.put("amount", 200);
        context.put("country_code", "US");

        assertThat(rule.matches(context)).isTrue();
    }

    @Test
    void testRuleDoesNotMatchWhenOneConditionFails() {
        Rule rule = new Rule("rule-001", "Test Rule", "DECLINE");
        rule.addCondition(new Condition("amount", "gt", 100));
        rule.addCondition(new Condition("country_code", "eq", "US"));

        java.util.Map<String, Object> context = new java.util.HashMap<>();
        context.put("amount", 200);
        context.put("country_code", "DE"); // Different country

        assertThat(rule.matches(context)).isFalse();
    }

    @Test
    void testVelocityConfig() {
        Rule rule = new Rule("rule-001", "Test Rule", "DECLINE");
        rule.setPriority(100);

        com.fraud.engine.domain.VelocityConfig velocityConfig = new com.fraud.engine.domain.VelocityConfig(
                "card_hash",
                3600,
                10
        );
        velocityConfig.setAction("REVIEW");
        rule.setVelocity(velocityConfig);

        assertThat(rule.getVelocity()).isNotNull();
        assertThat(rule.getVelocity().getDimension()).isEqualTo("card_hash");
        assertThat(rule.getVelocity().getWindowSeconds()).isEqualTo(3600);
        assertThat(rule.getVelocity().getThreshold()).isEqualTo(10);
        assertThat(rule.getVelocity().getAction()).isEqualTo("REVIEW");
    }

    @Test
    void testRuleEquality() {
        Rule rule1 = new Rule("rule-001", "Test Rule", "DECLINE");
        Rule rule2 = new Rule("rule-001", "Different Name", "APPROVE");

        assertThat(rule1).isEqualTo(rule2);
        assertThat(rule1.hashCode()).isEqualTo(rule2.hashCode());
    }

    @Test
    void testRuleInequality() {
        Rule rule1 = new Rule("rule-001", "Test Rule", "DECLINE");
        Rule rule2 = new Rule("rule-002", "Test Rule", "DECLINE");

        assertThat(rule1).isNotEqualTo(rule2);
    }

    @Test
    void testRuleToString() {
        Rule rule = new Rule("rule-001", "High Amount", "DECLINE");
        rule.setPriority(100);
        rule.setEnabled(true);

        String str = rule.toString();

        assertThat(str).contains("rule-001");
        assertThat(str).contains("High Amount");
        assertThat(str).contains("DECLINE");
    }
}
