package com.fraud.engine.service;

import com.fraud.engine.domain.Ruleset;
import com.fraud.engine.dto.FieldRegistryManifest;
import com.fraud.engine.dto.RulesetManifest;
import com.fraud.engine.loader.FieldRegistryLoader;
import com.fraud.engine.ruleset.RulesetLoader;
import com.fraud.engine.ruleset.RulesetRegistry;
import com.fraud.engine.util.EngineMetrics;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class HotReloadCoordinatorTest {

    @Mock
    FieldRegistryLoader fieldRegistryLoader;

    @Mock
    FieldRegistryService fieldRegistryService;

    @Mock
    RulesetLoader rulesetLoader;

    @Mock
    RulesetRegistry rulesetRegistry;

    private HotReloadCoordinator coordinator;

    @BeforeEach
    void setUp() {
        coordinator = new HotReloadCoordinator();
        coordinator.fieldRegistryLoader = fieldRegistryLoader;
        coordinator.fieldRegistryService = fieldRegistryService;
        coordinator.rulesetLoader = rulesetLoader;
        coordinator.rulesetRegistry = rulesetRegistry;
        coordinator.engineMetrics = new EngineMetrics();
        coordinator.requiredRulesetKeys = "CARD_AUTH,CARD_MONITORING";
        coordinator.hotReloadEnabled = true;
        coordinator.pollIntervalSeconds = 30;
    }

    @Test
    void validateStartupFailsWhenFieldRegistryManifestMissing() {
        when(fieldRegistryLoader.loadManifest()).thenReturn(null);
        when(rulesetLoader.isManifestAvailable("CARD_AUTH")).thenReturn(true);
        when(rulesetLoader.isManifestAvailable("CARD_MONITORING")).thenReturn(true);

        assertThrows(IllegalStateException.class, () -> invokePrivateVoid("validateStartup"));
    }

    @Test
    void validateStartupFailsWhenRulesetManifestMissing() {
        FieldRegistryManifest manifest = new FieldRegistryManifest();
        manifest.setRegistryVersion(1);

        when(fieldRegistryLoader.loadManifest()).thenReturn(manifest);
        when(rulesetLoader.isManifestAvailable("CARD_AUTH")).thenReturn(false);
        when(rulesetLoader.isManifestAvailable("CARD_MONITORING")).thenReturn(true);

        assertThrows(IllegalStateException.class, () -> invokePrivateVoid("validateStartup"));
    }

    @Test
    void validateStartupSucceedsWhenArtifactsAvailable() {
        FieldRegistryManifest manifest = new FieldRegistryManifest();
        manifest.setRegistryVersion(1);

        when(fieldRegistryLoader.loadManifest()).thenReturn(manifest);
        when(rulesetLoader.isManifestAvailable("CARD_AUTH")).thenReturn(true);
        when(rulesetLoader.isManifestAvailable("CARD_MONITORING")).thenReturn(true);

        invokePrivateVoid("validateStartup");
    }

    @Test
    void compatibilityFromManifestReturnsFalseWhenManifestMissing() {
        when(rulesetRegistry.getCountries()).thenReturn(Set.of("global"));
        when(rulesetRegistry.getRulesetKeys("global")).thenReturn(Set.of("CARD_AUTH"));
        when(rulesetLoader.loadManifest("CARD_AUTH")).thenReturn(null);

        boolean compatible = (boolean) invokePrivate("checkRulesetCompatibility", new Class[]{int.class}, 5);
        assertThat(compatible).isFalse();
    }

    @Test
    void compatibilityFromManifestReturnsFalseOnVersionMismatch() {
        RulesetManifest manifest = org.mockito.Mockito.mock(RulesetManifest.class);
        when(manifest.getFieldRegistryVersion()).thenReturn(4);

        when(rulesetRegistry.getCountries()).thenReturn(Set.of("global"));
        when(rulesetRegistry.getRulesetKeys("global")).thenReturn(Set.of("CARD_AUTH"));
        when(rulesetLoader.loadManifest("CARD_AUTH")).thenReturn(manifest);

        boolean compatible = (boolean) invokePrivate("checkRulesetCompatibility", new Class[]{int.class}, 5);
        assertThat(compatible).isFalse();
    }

    @Test
    void compatibilityFromManifestReturnsTrueWhenVersionInfoMissing() {
        RulesetManifest manifest = org.mockito.Mockito.mock(RulesetManifest.class);
        when(manifest.getFieldRegistryVersion()).thenReturn(null);

        when(rulesetRegistry.getCountries()).thenReturn(Set.of("global"));
        when(rulesetRegistry.getRulesetKeys("global")).thenReturn(Set.of("CARD_AUTH"));
        when(rulesetLoader.loadManifest("CARD_AUTH")).thenReturn(manifest);

        boolean compatible = (boolean) invokePrivate("checkRulesetCompatibility", new Class[]{int.class}, 5);
        assertThat(compatible).isTrue();
    }

    @Test
    void performCoordinatedReloadUpdatesTrackedVersionAndSwapsRuleset() {
        doNothing().when(fieldRegistryService).reload();
        when(fieldRegistryService.getRegistryVersion()).thenReturn(2);

        Ruleset current = new Ruleset("CARD_AUTH", 1);
        Ruleset latest = new Ruleset("CARD_AUTH", 2);
        Ruleset rulesetV2 = new Ruleset("CARD_AUTH", 2);
        rulesetV2.setFieldRegistryVersion(2);

        when(rulesetRegistry.getCountries()).thenReturn(Set.of("global"));
        when(rulesetRegistry.getRulesetKeys("global")).thenReturn(Set.of("CARD_AUTH"));
        when(rulesetRegistry.getRuleset("global", "CARD_AUTH")).thenReturn(current);
        when(rulesetLoader.loadLatestCompiledRuleset("CARD_AUTH")).thenReturn(Optional.of(latest));
        when(rulesetLoader.loadCompiledRuleset("CARD_AUTH", 2)).thenReturn(Optional.of(rulesetV2));
        when(rulesetRegistry.hotSwap("global", "CARD_AUTH", 2))
                .thenReturn(new RulesetRegistry.HotSwapResult(true, "SUCCESS", "ok", 1));

        invokePrivate("performCoordinatedReload", new Class[]{int.class}, 2);

        assertThat(coordinator.getFieldRegistryVersion()).isEqualTo(2);
        verify(rulesetRegistry).hotSwap("global", "CARD_AUTH", 2);
    }

    @Test
    void triggerCheckReturnsFalseWhenCoordinatorNotRunning() throws Exception {
        setField("lastFieldRegistryVersion", 1);
        setField("running", false);

        boolean changed = coordinator.triggerCheck();

        assertThat(changed).isFalse();
        assertThat(coordinator.getFieldRegistryVersion()).isEqualTo(1);
    }

    @Test
    void triggerCheckReturnsTrueWhenFieldRegistryVersionChanges() throws Exception {
        FieldRegistryManifest manifest = new FieldRegistryManifest();
        manifest.setRegistryVersion(2);

        RulesetManifest rulesetManifest = org.mockito.Mockito.mock(RulesetManifest.class);
        when(rulesetManifest.getFieldRegistryVersion()).thenReturn(2);

        Ruleset current = new Ruleset("CARD_AUTH", 1);
        Ruleset latestSameVersion = new Ruleset("CARD_AUTH", 1);

        when(fieldRegistryLoader.loadManifest()).thenReturn(manifest);
        when(rulesetRegistry.getCountries()).thenReturn(Set.of("global"));
        when(rulesetRegistry.getRulesetKeys("global")).thenReturn(Set.of("CARD_AUTH"));
        when(rulesetLoader.loadManifest("CARD_AUTH")).thenReturn(rulesetManifest);
        doNothing().when(fieldRegistryService).reload();
        when(fieldRegistryService.getRegistryVersion()).thenReturn(2);
        when(rulesetRegistry.getRuleset("global", "CARD_AUTH")).thenReturn(current);
        when(rulesetLoader.loadLatestCompiledRuleset("CARD_AUTH")).thenReturn(Optional.of(latestSameVersion));

        setField("lastFieldRegistryVersion", 1);
        setField("running", true);

        boolean changed = coordinator.triggerCheck();

        assertThat(changed).isTrue();
        assertThat(coordinator.getFieldRegistryVersion()).isEqualTo(2);
    }

    private Object invokePrivate(String methodName, Class<?>[] parameterTypes, Object... args) {
        try {
            Method method = HotReloadCoordinator.class.getDeclaredMethod(methodName, parameterTypes);
            method.setAccessible(true);
            return method.invoke(coordinator, args);
        } catch (Exception e) {
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException runtimeException) {
                throw runtimeException;
            }
            throw new RuntimeException(e);
        }
    }

    private void invokePrivateVoid(String methodName) {
        invokePrivate(methodName, new Class[]{});
    }

    private void setField(String name, Object value) throws Exception {
        Field field = HotReloadCoordinator.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(coordinator, value);
    }
}
