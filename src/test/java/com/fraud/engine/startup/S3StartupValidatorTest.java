package com.fraud.engine.startup;

import com.fraud.engine.dto.FieldRegistryManifest;
import com.fraud.engine.loader.FieldRegistryLoader;
import com.fraud.engine.ruleset.RulesetLoader;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class S3StartupValidatorTest {

    @Mock
    FieldRegistryLoader fieldRegistryLoader;

    @Mock
    RulesetLoader rulesetLoader;

    private S3StartupValidator validator;

    @BeforeEach
    void setUp() throws Exception {
        validator = new S3StartupValidator();
        setField("fieldRegistryLoader", fieldRegistryLoader);
        setField("rulesetLoader", rulesetLoader);
        setField("requiredRulesetKeys", "CARD_AUTH,CARD_MONITORING");
        setField("validationEnabled", true);
    }

    @Test
    void validationDisabledDoesNotThrow() throws Exception {
        setField("validationEnabled", false);
        validator.validate();
        assertThat(validator.isStartupHealthy()).isFalse();
    }

    @Test
    void missingFieldRegistryThrows() {
        when(fieldRegistryLoader.loadManifest()).thenReturn(null);
        when(rulesetLoader.isManifestAvailable("CARD_AUTH")).thenReturn(true);
        when(rulesetLoader.isManifestAvailable("CARD_MONITORING")).thenReturn(true);

        assertThatThrownBy(() -> validator.validate())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Field registry unavailable");

        assertThat(validator.isFieldRegistryAvailable()).isFalse();
    }

    @Test
    void missingRulesetThrows() {
        FieldRegistryManifest manifest = new FieldRegistryManifest(1, 2, "s3://fields", "abc", 10, "2026-01-01", "tester");
        when(fieldRegistryLoader.loadManifest()).thenReturn(manifest);
        when(rulesetLoader.isManifestAvailable("CARD_AUTH")).thenReturn(true);
        when(rulesetLoader.isManifestAvailable("CARD_MONITORING")).thenReturn(false);

        assertThatThrownBy(() -> validator.validate())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Rulesets unavailable");

        assertThat(validator.isRulesetAvailable()).isFalse();
    }

    @Test
    void bothAvailableMarksHealthy() {
        FieldRegistryManifest manifest = new FieldRegistryManifest(1, 5, "s3://fields", "abc", 26, "2026-01-01", "tester");
        when(fieldRegistryLoader.loadManifest()).thenReturn(manifest);
        when(rulesetLoader.isManifestAvailable("CARD_AUTH")).thenReturn(true);
        when(rulesetLoader.isManifestAvailable("CARD_MONITORING")).thenReturn(true);

        validator.validate();

        assertThat(validator.isFieldRegistryAvailable()).isTrue();
        assertThat(validator.isRulesetAvailable()).isTrue();
        assertThat(validator.isStartupHealthy()).isTrue();
    }

    @Test
    void isStartupHealthyReturnsFalseWhenFieldRegistryMissing() throws Exception {
        // Directly test isStartupHealthy combinations
        S3StartupValidator v1 = new S3StartupValidator();
        setField(v1, "fieldRegistryLoader", fieldRegistryLoader);
        setField(v1, "rulesetLoader", rulesetLoader);
        setField(v1, "requiredRulesetKeys", "CARD_AUTH,CARD_MONITORING");
        setField(v1, "validationEnabled", false); // Disable to avoid validate() being called
        v1.validate(); // Initialize with validation disabled

        // Manually set the internal state for testing
        setField(v1, "fieldRegistryAvailable", false);
        setField(v1, "rulesetAvailable", true);

        assertThat(v1.isStartupHealthy()).isFalse();
    }

    @Test
    void isStartupHealthyReturnsFalseWhenRulesetMissing() throws Exception {
        S3StartupValidator v2 = new S3StartupValidator();
        setField(v2, "fieldRegistryLoader", fieldRegistryLoader);
        setField(v2, "rulesetLoader", rulesetLoader);
        setField(v2, "requiredRulesetKeys", "CARD_AUTH,CARD_MONITORING");
        setField(v2, "validationEnabled", false);
        v2.validate();

        setField(v2, "fieldRegistryAvailable", true);
        setField(v2, "rulesetAvailable", false);

        assertThat(v2.isStartupHealthy()).isFalse();
    }

    @Test
    void isStartupHealthyReturnsFalseWhenBothMissing() throws Exception {
        S3StartupValidator v3 = new S3StartupValidator();
        setField(v3, "fieldRegistryLoader", fieldRegistryLoader);
        setField(v3, "rulesetLoader", rulesetLoader);
        setField(v3, "requiredRulesetKeys", "CARD_AUTH,CARD_MONITORING");
        setField(v3, "validationEnabled", false);
        v3.validate();

        setField(v3, "fieldRegistryAvailable", false);
        setField(v3, "rulesetAvailable", false);

        assertThat(v3.isStartupHealthy()).isFalse();
    }

    private void setField(String name, Object value) throws Exception {
        var field = S3StartupValidator.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(validator, value);
    }

    private void setField(S3StartupValidator target, String name, Object value) throws Exception {
        var field = S3StartupValidator.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }
}
