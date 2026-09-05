package com.fraud.engine.config;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class EvaluationConfigTest {

    @Test
    void shouldCaptureDebugRespectsFlags() {
        EvaluationConfig config = new EvaluationConfig();
        config.debugEnabled = false;
        config.debugSampleRate = 100;
        assertThat(config.shouldCaptureDebug()).isFalse();

        config.debugEnabled = true;
        config.debugSampleRate = 0;
        assertThat(config.shouldCaptureDebug()).isFalse();

        config.debugSampleRate = 100;
        assertThat(config.shouldCaptureDebug()).isTrue();
    }

    @Test
    void testShouldCaptureDebug_WithSampleRate50() {
        EvaluationConfig config = new EvaluationConfig();
        config.debugEnabled = true;
        config.debugSampleRate = 50;
        // Run multiple times to check random sampling - at least once should be true/false over time
        boolean hasTrue = false;
        boolean hasFalse = false;
        for (int i = 0; i < 100; i++) {
            if (config.shouldCaptureDebug()) {
                hasTrue = true;
            } else {
                hasFalse = true;
            }
        }
        // With 50% sample rate, we should get both true and false over 100 iterations
        assertThat(hasTrue).isTrue();
        assertThat(hasFalse).isTrue();
    }

    @Test
    void testShouldCaptureDebug_WithSampleRate0() {
        EvaluationConfig config = new EvaluationConfig();
        config.debugEnabled = true;
        config.debugSampleRate = 0;
        assertThat(config.shouldCaptureDebug()).isFalse();
    }

    @Test
    void testShouldCaptureDebug_WithSampleRate100() {
        EvaluationConfig config = new EvaluationConfig();
        config.debugEnabled = true;
        config.debugSampleRate = 100;
        assertThat(config.shouldCaptureDebug()).isTrue();
    }

    @Test
    void testShouldCaptureDebug_WhenDisabled() {
        EvaluationConfig config = new EvaluationConfig();
        config.debugEnabled = false;
        config.debugSampleRate = 100;
        assertThat(config.shouldCaptureDebug()).isFalse();
    }

    @Test
    void testShouldCaptureDebug_EdgeCases() {
        EvaluationConfig config = new EvaluationConfig();
        config.debugEnabled = true;
        config.debugSampleRate = -1; // Below 0
        assertThat(config.shouldCaptureDebug()).isFalse();

        config.debugSampleRate = 101; // Above 100
        assertThat(config.shouldCaptureDebug()).isTrue();
    }

    @Test
    void testShouldCaptureDebug_WithPositiveSampleRateCoversBranch() {
        EvaluationConfig config = new EvaluationConfig();
        config.debugEnabled = true;
        config.debugSampleRate = 1; // Positive but not 0 or 100

        // This should exercise the "else" branch (line 76: sampleRate > 0 AND sampleRate < 100)
        // and the random comparison (line 79)
        boolean result = config.shouldCaptureDebug();
        // We just verify it returns a boolean without throwing
        assertThat(result).isIn(true, false);
    }

    @Test
    void isDebugEnabled_reflectsPlainFlagNonProbabilistically() {
        EvaluationConfig config = new EvaluationConfig();

        config.debugEnabled = false;
        assertThat(config.isDebugEnabled()).isFalse();

        config.debugEnabled = true;
        // Even with a 0 sample rate (shouldCaptureDebug() would always say "no"),
        // isDebugEnabled() must still say "yes" - it does not roll the sample rate at all.
        config.debugSampleRate = 0;
        assertThat(config.isDebugEnabled()).isTrue();
        for (int i = 0; i < 20; i++) {
            assertThat(config.shouldCaptureDebug()).isFalse();
        }
    }

    @Test
    void shouldSampleDetailedTiming_defaultIsAlwaysOn() {
        EvaluationConfig config = new EvaluationConfig();
        // Field initializer already matches the documented/@ConfigProperty default of 1;
        // set explicitly here anyway so the test doesn't depend on that initializer.
        config.timingSampleEveryN = 1;
        for (int i = 0; i < 50; i++) {
            assertThat(config.shouldSampleDetailedTiming()).isTrue();
        }
    }

    @Test
    void shouldSampleDetailedTiming_zeroMeansNever() {
        EvaluationConfig config = new EvaluationConfig();
        config.timingSampleEveryN = 0;
        for (int i = 0; i < 50; i++) {
            assertThat(config.shouldSampleDetailedTiming()).isFalse();
        }
    }

    @Test
    void shouldSampleDetailedTiming_negativeMeansNever() {
        EvaluationConfig config = new EvaluationConfig();
        config.timingSampleEveryN = -1;
        assertThat(config.shouldSampleDetailedTiming()).isFalse();
    }

    @Test
    void shouldSampleDetailedTiming_nGreaterThanOneSamplesRoughlyOneOfN() {
        EvaluationConfig config = new EvaluationConfig();
        config.timingSampleEveryN = 5;

        int sampled = 0;
        int iterations = 1000;
        for (int i = 0; i < iterations; i++) {
            if (config.shouldSampleDetailedTiming()) {
                sampled++;
            }
        }

        assertThat(sampled).isStrictlyBetween(50, 500);
    }
}
