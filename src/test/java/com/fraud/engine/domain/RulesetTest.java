package com.fraud.engine.domain;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class RulesetTest {

    @Test
    void testRulesetCreation() {
        Ruleset ruleset = new Ruleset("CARD_AUTH", 1);

        assertThat(ruleset.getKey()).isEqualTo("CARD_AUTH");
        assertThat(ruleset.getVersion()).isEqualTo(1);
        assertThat(ruleset.isActive()).isTrue();
    }

    @Test
    void testFullKey() {
        Ruleset ruleset = new Ruleset("CARD_AUTH", 3);

        assertThat(ruleset.getFullKey()).isEqualTo("CARD_AUTH/v3");
    }

    @Test
    void testRulesetWithRules() {
        Ruleset ruleset = new Ruleset("CARD_AUTH", 1);
        ruleset.setName("Card AUTH Rules");
        ruleset.setEvaluationType("AUTH");

        Rule rule1 = new Rule("rule-001", "High Amount", "DECLINE");
        rule1.setPriority(100);

        Rule rule2 = new Rule("rule-002", "High Risk Country", "REVIEW");
        rule2.setPriority(50);

        ruleset.addRule(rule1);
        ruleset.addRule(rule2);

        assertThat(ruleset.getRules()).hasSize(2);
    }

    @Test
    void testGetRulesByPriority() {
        Ruleset ruleset = new Ruleset("CARD_AUTH", 1);

        Rule rule1 = new Rule("rule-001", "Low Priority", "APPROVE");
        rule1.setPriority(10);
        rule1.setEnabled(true);

        Rule rule2 = new Rule("rule-002", "High Priority", "DECLINE");
        rule2.setPriority(100);
        rule2.setEnabled(true);

        Rule rule3 = new Rule("rule-003", "Disabled", "DECLINE");
        rule3.setPriority(200);
        rule3.setEnabled(false);

        Rule rule4 = new Rule("rule-004", "Medium Priority", "REVIEW");
        rule4.setPriority(50);
        rule4.setEnabled(true);

        ruleset.addRule(rule1);
        ruleset.addRule(rule2);
        ruleset.addRule(rule3);
        ruleset.addRule(rule4);

        List<Rule> sorted = ruleset.getRulesByPriority();

        assertThat(sorted).hasSize(3); // Excludes disabled rule
        assertThat(sorted.get(0).getId()).isEqualTo("rule-002"); // Priority 100
        assertThat(sorted.get(1).getId()).isEqualTo("rule-004"); // Priority 50
        assertThat(sorted.get(2).getId()).isEqualTo("rule-001"); // Priority 10
    }

    @Test
    void testRulesetEquality() {
        Ruleset ruleset1 = new Ruleset("CARD_AUTH", 1);
        Ruleset ruleset2 = new Ruleset("CARD_AUTH", 1);

        assertThat(ruleset1).isEqualTo(ruleset2);
        assertThat(ruleset1.hashCode()).isEqualTo(ruleset2.hashCode());
    }

    @Test
    void testRulesetInequality() {
        Ruleset ruleset1 = new Ruleset("CARD_AUTH", 1);
        Ruleset ruleset2 = new Ruleset("CARD_AUTH", 2);

        assertThat(ruleset1).isNotEqualTo(ruleset2);
    }

    @Test
    void testRulesetInequalityDifferentKey() {
        Ruleset ruleset1 = new Ruleset("CARD_AUTH", 1);
        Ruleset ruleset2 = new Ruleset("CARD_MONITORING", 1);

        assertThat(ruleset1).isNotEqualTo(ruleset2);
    }

    @Test
    void testRulesetToString() {
        Ruleset ruleset = new Ruleset("CARD_AUTH", 1);
        ruleset.setName("Card AUTH Rules");
        ruleset.setEvaluationType("AUTH");
        ruleset.setActive(true);

        Rule rule = new Rule("rule-001", "Test", "DECLINE");
        ruleset.addRule(rule);

        String str = ruleset.toString();

        assertThat(str).contains("CARD_AUTH");
        assertThat(str).contains("v1");
        assertThat(str).contains("Card AUTH Rules");
        assertThat(str).contains("AUTH");
        assertThat(str).contains("rulesCount=1");
    }
}
