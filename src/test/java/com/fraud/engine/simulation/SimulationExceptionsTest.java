package com.fraud.engine.simulation;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SimulationExceptionsTest {

    @Test
    void invalidRulesetExceptionStoresCause() {
        RuntimeException cause = new RuntimeException("boom");
        SimulationService.InvalidRulesetException ex = new SimulationService.InvalidRulesetException("bad", cause);
        assertThat(ex.getMessage()).isEqualTo("bad");
        assertThat(ex.getCause()).isSameAs(cause);
    }

    @Test
    void simulationExceptionStoresMessageAndCause() {
        RuntimeException cause = new RuntimeException("boom");
        SimulationService.SimulationException ex = new SimulationService.SimulationException("fail", cause);
        assertThat(ex.getMessage()).isEqualTo("fail");
        assertThat(ex.getCause()).isSameAs(cause);
    }
}
