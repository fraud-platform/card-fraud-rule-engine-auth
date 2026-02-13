package com.fraud.engine;

import io.quarkus.runtime.Quarkus;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import static org.assertj.core.api.Assertions.assertThat;

class FraudRuleEngineApplicationTest {

    @Test
    void mainInvokesQuarkusRun() {
        try (MockedStatic<Quarkus> quarkus = Mockito.mockStatic(Quarkus.class)) {
            FraudRuleEngineApplication.main(new String[]{"arg"});
            quarkus.verify(() -> Quarkus.run(FraudRuleEngineApplication.class, new String[]{"arg"}));
        }
    }

    @Test
    void runWaitsForExitAndReturnsZero() throws Exception {
        try (MockedStatic<Quarkus> quarkus = Mockito.mockStatic(Quarkus.class)) {
            quarkus.when(Quarkus::waitForExit).thenAnswer(invocation -> null);

            FraudRuleEngineApplication app = new FraudRuleEngineApplication();
            int result = app.run();

            assertThat(result).isEqualTo(0);
            quarkus.verify(Quarkus::waitForExit);
        }
    }
}
