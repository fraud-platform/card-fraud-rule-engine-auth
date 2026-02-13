package com.fraud.engine.domain;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class DecisionVelocityResultTest {

    @Test
    void setCountUpdatesExceededFlag() {
        Decision.VelocityResult result = new Decision.VelocityResult("card_hash", "x", 1, 5, 60);
        assertThat(result.isExceeded()).isFalse();

        result.setCount(5);
        assertThat(result.isExceeded()).isTrue();
    }

    @Test
    void settersUpdateFields() {
        Decision.VelocityResult result = new Decision.VelocityResult();
        result.setDimension("ip_address");
        result.setDimensionValue("1.2.3.4");
        result.setThreshold(3);
        result.setWindowSeconds(60);
        result.setTtlRemaining(10L);

        assertThat(result.getDimension()).isEqualTo("ip_address");
        assertThat(result.getDimensionValue()).isEqualTo("1.2.3.4");
        assertThat(result.getThreshold()).isEqualTo(3);
        assertThat(result.getWindowSeconds()).isEqualTo(60);
        assertThat(result.getTtlRemaining()).isEqualTo(10L);
    }
}
