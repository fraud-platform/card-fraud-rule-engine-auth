package com.fraud.engine.domain;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class DecisionEnumsTest {

    @Test
    void engineModeFromValueParsesCaseInsensitive() {
        assertThat(Decision.EngineMode.fromValue("normal")).isEqualTo(Decision.EngineMode.NORMAL);
        assertThat(Decision.EngineMode.fromValue("DEGRADED")).isEqualTo(Decision.EngineMode.DEGRADED);
        assertThat(Decision.EngineMode.fromValue("bad")).isNull();
    }

    @Test
    void decisionTypeFromValueParsesCaseInsensitive() {
        assertThat(Decision.DecisionType.fromValue("approve")).isEqualTo(Decision.DecisionType.APPROVE);
        assertThat(Decision.DecisionType.fromValue("DECLINE")).isEqualTo(Decision.DecisionType.DECLINE);
        assertThat(Decision.DecisionType.fromValue("bad")).isNull();
    }

    @Test
    void evaluationTypeFromValueParsesCaseInsensitive() {
        assertThat(Decision.EvaluationType.fromValue("AUTH")).isEqualTo(Decision.EvaluationType.AUTH);
        assertThat(Decision.EvaluationType.fromValue("MONITORING")).isEqualTo(Decision.EvaluationType.MONITORING);
        assertThat(Decision.EvaluationType.fromValue("bad")).isNull();
    }

    @Test
    void enumGetValueReturnsName() {
        assertThat(Decision.EngineMode.NORMAL.getValue()).isEqualTo("NORMAL");
        assertThat(Decision.DecisionType.APPROVE.getValue()).isEqualTo("APPROVE");
        assertThat(Decision.EvaluationType.MONITORING.getValue()).isEqualTo("MONITORING");
    }
}
