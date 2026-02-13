package com.fraud.engine.domain;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class EngineMetadataTest {

    @Test
    void constructorsAndAccessors() {
        EngineMetadata metadata = new EngineMetadata("NORMAL", 12.5);
        metadata.setErrorCode("ERR");
        metadata.setErrorMessage("boom");
        metadata.setRuleEngineVersion("1.2.3");

        assertThat(metadata.getEngineMode()).isEqualTo("NORMAL");
        assertThat(metadata.getProcessingTimeMs()).isEqualTo(12.5);
        assertThat(metadata.getErrorCode()).isEqualTo("ERR");
        assertThat(metadata.getErrorMessage()).isEqualTo("boom");
        assertThat(metadata.getRuleEngineVersion()).isEqualTo("1.2.3");
    }

    @Test
    void equalsHashCodeAndToString() {
        EngineMetadata a = new EngineMetadata("DEGRADED", "CODE", "MSG", 1.0, "1.0.0");
        EngineMetadata b = new EngineMetadata("DEGRADED", "CODE", "MSG", 1.0, "1.0.0");
        EngineMetadata c = new EngineMetadata("NORMAL", "CODE", "MSG", 1.0, "1.0.0");

        assertThat(a).isEqualTo(b);
        assertThat(a).isNotEqualTo(c);
        assertThat(a.hashCode()).isEqualTo(b.hashCode());
        assertThat(a.toString()).contains("engineMode");
    }
}
