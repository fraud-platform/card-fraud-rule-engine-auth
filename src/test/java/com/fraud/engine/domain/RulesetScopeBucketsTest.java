package com.fraud.engine.domain;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class RulesetScopeBucketsTest {

    @Test
    void getApplicableRulesReturnsScopedAndGlobalRules() {
        Ruleset ruleset = new Ruleset("CARD_AUTH", 1);

        Rule globalRule = rule("global", 10, null);
        Rule networkRule = rule("network", 20, RuleScope.network("VISA"));
        Rule binRule = rule("bin", 30, RuleScope.bin("4111"));
        Rule mccRule = rule("mcc", 40, RuleScope.mcc("5411"));
        Rule logoRule = rule("logo", 50, RuleScope.logo("PLATINUM"));
        Rule disabledRule = rule("disabled", 99, RuleScope.network("VISA"));
        disabledRule.setEnabled(false);

        ruleset.setRules(List.of(globalRule, networkRule, binRule, mccRule, logoRule, disabledRule));

        List<Rule> applicable = ruleset.getApplicableRules("visa", "411122", "5411", "platinum");

        assertThat(applicable).extracting(Rule::getId)
                .contains("global", "network", "bin", "mcc", "logo")
                .doesNotContain("disabled");
    }

    @Test
    void getApplicableRulesMatchesMultipleBinPrefixes() {
        Ruleset ruleset = new Ruleset("CARD_AUTH", 1);

        Rule shortPrefix = rule("bin-41", 10, RuleScope.bin("41"));
        Rule longPrefix = rule("bin-4111", 20, RuleScope.bin("4111"));
        ruleset.setRules(List.of(shortPrefix, longPrefix));

        List<Rule> applicable = ruleset.getApplicableRules(null, "411122", null, null);

        assertThat(applicable).extracting(Rule::getId)
                .containsExactlyInAnyOrder("bin-41", "bin-4111");
    }

    @Test
    void getScopeBucketCountsReflectsBucketBuild() {
        Ruleset ruleset = new Ruleset("CARD_AUTH", 1);
        ruleset.setRules(List.of(
                rule("network", 10, RuleScope.network("VISA")),
                rule("bin", 10, RuleScope.bin("4111")),
                rule("mcc", 10, RuleScope.mcc("5411")),
                rule("logo", 10, RuleScope.logo("PLATINUM")),
                rule("global", 10, null)
        ));

        Map<String, Integer> counts = ruleset.getScopeBucketCounts();

        assertThat(counts.get("NETWORK")).isEqualTo(1);
        assertThat(counts.get("BIN")).isEqualTo(1);
        assertThat(counts.get("MCC")).isEqualTo(1);
        assertThat(counts.get("LOGO")).isEqualTo(1);
        assertThat(counts.get("GLOBAL")).isEqualTo(1);
        assertThat(counts.get("TOTAL")).isEqualTo(5);
    }

    @Test
    void compatibilityUsesFieldRegistryVersionWhenPresent() {
        Ruleset ruleset = new Ruleset("CARD_AUTH", 1);
        ruleset.setFieldRegistryVersion(7);

        assertThat(ruleset.isCompatibleWith(7)).isTrue();
        assertThat(ruleset.isCompatibleWith(8)).isFalse();

        ruleset.setFieldRegistryVersion(null);
        assertThat(ruleset.isCompatibleWith(999)).isTrue();
    }

    @Test
    void setRulesInvalidatesScopeBucketsAndCache() {
        Ruleset ruleset = new Ruleset("CARD_AUTH", 1);
        ruleset.setRules(List.of(rule("network", 10, RuleScope.network("VISA"))));
        assertThat(ruleset.getApplicableRules("VISA", null, null, null))
                .extracting(Rule::getId).contains("network");

        ruleset.setRules(List.of(rule("mcc", 10, RuleScope.mcc("5411"))));
        assertThat(ruleset.getApplicableRules("VISA", null, "5411", null))
                .extracting(Rule::getId).contains("mcc").doesNotContain("network");
    }

    @Test
    void getApplicableRulesCachesByScopeTuple() {
        Ruleset ruleset = new Ruleset("CARD_AUTH", 1);
        ruleset.setRules(List.of(
                rule("global", 10, null),
                rule("visa", 20, RuleScope.network("VISA"))
        ));

        List<Rule> first = ruleset.getApplicableRules("VISA", null, null, null);
        List<Rule> second = ruleset.getApplicableRules("visa", null, null, null);

        assertThat(second).isSameAs(first);
    }

    private static Rule rule(String id, int priority, RuleScope scope) {
        Rule rule = new Rule(id, id, "APPROVE");
        rule.setPriority(priority);
        rule.setEnabled(true);
        if (scope != null) {
            rule.setScope(scope);
        }
        return rule;
    }
}
