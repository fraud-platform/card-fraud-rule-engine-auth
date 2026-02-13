package com.fraud.engine.startup;

import com.fraud.engine.domain.Ruleset;
import com.fraud.engine.ruleset.RulesetRegistry;
import com.fraud.engine.util.EngineMetrics;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.junit.jupiter.api.extension.ExtendWith;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class StartupRulesetLoaderTest {

    @Mock
    RulesetRegistry rulesetRegistry;

    private StartupRulesetLoader loader;

    @BeforeEach
    void setUp() {
        loader = new StartupRulesetLoader();
        loader.rulesetRegistry = rulesetRegistry;
        loader.engineMetrics = new EngineMetrics();
        loader.environment = "local";
        loader.country = "US";
        loader.startupRulesets = List.of("CARD_AUTH", "CARD_MONITORING");
        loader.startupLoadEnabled = true;
        loader.failFast = true;
    }

    @Test
    void onStartSkipsWhenDisabled() {
        loader.startupLoadEnabled = false;

        loader.onStart(null);

        verifyNoInteractions(rulesetRegistry);
    }

    @Test
    void onStartLoadsRulesetsWhenAvailable() {
        when(rulesetRegistry.getOrLoadLatest("US", "CARD_AUTH"))
                .thenReturn(new Ruleset("CARD_AUTH", 1));
        when(rulesetRegistry.getOrLoadLatest("US", "CARD_MONITORING"))
                .thenReturn(new Ruleset("CARD_MONITORING", 2));
        when(rulesetRegistry.size()).thenReturn(2);

        assertDoesNotThrow(() -> loader.onStart(null));
    }

    @Test
    void onStartThrowsWhenRulesetMissingAndFailFastEnabled() {
        when(rulesetRegistry.getOrLoadLatest("US", "CARD_AUTH")).thenReturn(null);

        assertThrows(IllegalStateException.class, () -> loader.onStart(null));
    }

    @Test
    void onStartContinuesWhenRulesetMissingAndFailFastDisabled() {
        loader.failFast = false;
        when(rulesetRegistry.getOrLoadLatest("US", "CARD_AUTH")).thenReturn(null);
        when(rulesetRegistry.getOrLoadLatest("US", "CARD_MONITORING"))
                .thenReturn(new Ruleset("CARD_MONITORING", 2));
        when(rulesetRegistry.size()).thenReturn(1);

        assertDoesNotThrow(() -> loader.onStart(null));
    }

    @Test
    void onStartThrowsWhenRegistryFailsAndFailFastEnabled() {
        when(rulesetRegistry.getOrLoadLatest("US", "CARD_AUTH"))
                .thenThrow(new RuntimeException("boom"));

        assertThrows(IllegalStateException.class, () -> loader.onStart(null));
    }

    @Test
    void onStartContinuesWhenRegistryFailsAndFailFastDisabled() {
        loader.failFast = false;
        when(rulesetRegistry.getOrLoadLatest("US", "CARD_AUTH"))
                .thenThrow(new RuntimeException("boom"));
        when(rulesetRegistry.getOrLoadLatest("US", "CARD_MONITORING"))
                .thenReturn(new Ruleset("CARD_MONITORING", 3));
        when(rulesetRegistry.size()).thenReturn(1);

        assertDoesNotThrow(() -> loader.onStart(null));
    }
}
