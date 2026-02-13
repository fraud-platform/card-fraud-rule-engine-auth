package com.fraud.engine.domain;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class RuleScopeTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void globalScopeMatchesEverything() {
        assertThat(RuleScope.GLOBAL.matches("VISA", "411111", "5411", "PLATINUM")).isTrue();
        assertThat(RuleScope.GLOBAL.isGlobal()).isTrue();
        assertThat(RuleScope.GLOBAL.getSpecificity()).isEqualTo(0);
    }

    @Test
    void networkScopeIsCaseInsensitive() {
        RuleScope scope = RuleScope.network("visa");

        assertThat(scope.matches("VISA", null, null, null)).isTrue();
        assertThat(scope.matches("mastercard", null, null, null)).isFalse();
    }

    @Test
    void binScopeUsesPrefixMatch() {
        RuleScope scope = RuleScope.bin("4111");

        assertThat(scope.matches(null, "411122", null, null)).isTrue();
        assertThat(scope.matches(null, "422233", null, null)).isFalse();
    }

    @Test
    void combinedScopeRequiresAllDimensions() {
        RuleScope scope = RuleScope.combined(Map.of(
                "network", Set.of("VISA"),
                "bin", Set.of("4111"),
                "mcc", Set.of("5411")
        ));

        assertThat(scope.matches("VISA", "411122", "5411", null)).isTrue();
        assertThat(scope.matches("VISA", "411122", "5999", null)).isFalse();
        assertThat(scope.getSpecificity()).isEqualTo(RuleScope.Type.COMBINED.getSpecificity() + 3);
    }

    @Test
    void fromScopeNodeParsesSingleAndCombinedScopes() throws Exception {
        JsonNode networkNode = mapper.readTree("{\"network\":\"VISA\"}");
        RuleScope network = RuleScope.fromScopeNode(networkNode, mapper);
        assertThat(network.getType()).isEqualTo(RuleScope.Type.NETWORK);
        assertThat(network.getValue()).isEqualTo("VISA");

        JsonNode combinedNode = mapper.readTree("{\"network\":[\"VISA\"],\"mcc\":[\"5411\",\"5812\"]}");
        RuleScope combined = RuleScope.fromScopeNode(combinedNode, mapper);
        assertThat(combined.getType()).isEqualTo(RuleScope.Type.COMBINED);
        assertThat(combined.getDimensions()).containsKeys("network", "mcc");
    }

    @Test
    void fromScopeNodeReturnsGlobalForNullOrEmpty() throws Exception {
        assertThat(RuleScope.fromScopeNode(null, mapper)).isEqualTo(RuleScope.GLOBAL);
        assertThat(RuleScope.fromScopeNode(mapper.readTree("{}"), mapper)).isEqualTo(RuleScope.GLOBAL);
    }

    @Test
    void equalsHashCodeAndToStringAreStable() {
        RuleScope a = RuleScope.network("VISA");
        RuleScope b = RuleScope.network("VISA");
        RuleScope c = RuleScope.bin("4111");

        assertThat(a).isEqualTo(b);
        assertThat(a.hashCode()).isEqualTo(b.hashCode());
        assertThat(a).isNotEqualTo(c);
        assertThat(a.toString()).contains("NETWORK");
    }
}
