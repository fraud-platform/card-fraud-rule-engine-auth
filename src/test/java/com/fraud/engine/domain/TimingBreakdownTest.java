package com.fraud.engine.domain;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class TimingBreakdownTest {

    @Test
    void constructorsAndFromNanosPopulateTotalTime() {
        TimingBreakdown fromCtor = new TimingBreakdown(12.5);
        TimingBreakdown fromNanos = TimingBreakdown.fromNanos(12_345_678L);

        assertThat(fromCtor.getTotalProcessingTimeMs()).isEqualTo(12.5);
        assertThat(fromNanos.getTotalProcessingTimeMs()).isEqualTo(12.345678);
    }

    @Test
    void settersAndToStringExposeTimingDetails() {
        TimingBreakdown breakdown = new TimingBreakdown();
        breakdown.setTotalProcessingTimeMs(20.0);
        breakdown.setRulesetLookupTimeMs(2.0);
        breakdown.setRuleEvaluationTimeMs(10.0);
        breakdown.setVelocityCheckTimeMs(3.5);
        breakdown.setVelocityCheckCount(4);
        breakdown.setDecisionBuildTimeMs(1.0);

        assertThat(breakdown.getTotalProcessingTimeMs()).isEqualTo(20.0);
        assertThat(breakdown.getRulesetLookupTimeMs()).isEqualTo(2.0);
        assertThat(breakdown.getRuleEvaluationTimeMs()).isEqualTo(10.0);
        assertThat(breakdown.getVelocityCheckTimeMs()).isEqualTo(3.5);
        assertThat(breakdown.getVelocityCheckCount()).isEqualTo(4);
        assertThat(breakdown.getDecisionBuildTimeMs()).isEqualTo(1.0);
        assertThat(breakdown.toString()).contains("total=20.0ms");
        assertThat(breakdown.toString()).contains("velocityCount=4");
    }
}
