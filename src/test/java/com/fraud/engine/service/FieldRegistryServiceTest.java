package com.fraud.engine.service;

import com.fraud.engine.domain.FieldRegistry;
import com.fraud.engine.dto.FieldRegistryArtifact;
import com.fraud.engine.dto.FieldRegistryEntry;
import com.fraud.engine.loader.FieldRegistryLoader;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for FieldRegistryService.
 * <p>
 * Verifies field registry loading, caching, and lookup functionality.
 */
class FieldRegistryServiceTest {

    private FieldRegistryLoader mockLoader;
    private FieldRegistryService service;

    @BeforeEach
    void setUp() {
        mockLoader = mock(FieldRegistryLoader.class);
        service = new FieldRegistryService(mockLoader);

        // Simulate @PostConstruct behavior
        when(mockLoader.loadLatest()).thenReturn(
                new FieldRegistryLoader().loadBuiltin()
        );
        service.init();
    }

    @Test
    void testInit_LoadsBuiltinWhenS3Unavailable() {
        assertThat(service.getFieldCount()).isEqualTo(26);
        assertThat(service.getSource()).isEqualTo("builtin");
    }

    @Test
    void testGetFieldId_StandardField() {
        // Test standard field lookup
        assertThat(service.getFieldId("amount")).isEqualTo(FieldRegistry.AMOUNT);
        assertThat(service.getFieldId("card_hash")).isEqualTo(FieldRegistry.CARD_HASH);
        assertThat(service.getFieldId("transaction_id")).isEqualTo(FieldRegistry.TRANSACTION_ID);
    }

    @Test
    void testGetFieldId_Aliases() {
        // Test alias lookup (via static FieldRegistry fallback)
        assertThat(service.getFieldId("txn_id")).isEqualTo(FieldRegistry.TRANSACTION_ID);
        assertThat(service.getFieldId("card")).isEqualTo(FieldRegistry.CARD_HASH);
        assertThat(service.getFieldId("mcc")).isEqualTo(FieldRegistry.MERCHANT_CATEGORY_CODE);
    }

    @Test
    void testGetFieldId_UnknownField() {
        assertThat(service.getFieldId("unknown_field")).isEqualTo(FieldRegistry.UNKNOWN);
        assertThat(service.getFieldId("")).isEqualTo(FieldRegistry.UNKNOWN);
        assertThat(service.getFieldId(null)).isEqualTo(FieldRegistry.UNKNOWN);
    }

    @Test
    void testGetField_ExistingField() {
        Optional<FieldRegistryEntry> field = service.getField(FieldRegistry.AMOUNT);

        assertThat(field).isPresent();
        assertThat(field.get().getFieldKey()).isEqualTo("amount");
        assertThat(field.get().getDataType()).isEqualTo("NUMBER");
    }

    @Test
    void testGetField_NonExistentField() {
        Optional<FieldRegistryEntry> field = service.getField(999);
        assertThat(field).isEmpty();
    }

    @Test
    void testGetFieldByName() {
        Optional<FieldRegistryEntry> field = service.getFieldByName("amount");

        assertThat(field).isPresent();
        assertThat(field.get().getFieldId()).isEqualTo(FieldRegistry.AMOUNT);
    }

    @Test
    void testGetFieldByNameUnknownReturnsEmpty() {
        Optional<FieldRegistryEntry> field = service.getFieldByName("does_not_exist");
        assertThat(field).isEmpty();
    }

    @Test
    void testGetFieldByName_CaseInsensitive() {
        // Field names should be case-insensitive
        assertThat(service.getFieldId("AMOUNT")).isEqualTo(FieldRegistry.AMOUNT);
        assertThat(service.getFieldId("Amount")).isEqualTo(FieldRegistry.AMOUNT);
        assertThat(service.getFieldId("aMoUnT")).isEqualTo(FieldRegistry.AMOUNT);
    }

    @Test
    void testReload_UpdatesRegistry() {
        int initialVersion = service.getRegistryVersion();

        // Create a new artifact with different version
        List<FieldRegistryEntry> fields = List.of(
                new FieldRegistryEntry(0, "test_field", "Test", "Test field",
                        "STRING", List.of("EQ"), false, false)
        );
        FieldRegistryArtifact newArtifact = new FieldRegistryArtifact(
                1, 999, fields, null, Instant.now(), "test"
        );

        when(mockLoader.loadLatest()).thenReturn(newArtifact);
        service.reload();

        assertThat(service.getRegistryVersion()).isEqualTo(999);
        assertThat(service.getFieldCount()).isEqualTo(1);
    }

    @Test
    void testGetRegistryVersion() {
        // Builtin registry has version 1
        assertThat(service.getRegistryVersion()).isEqualTo(1);
    }

    @Test
    void testIsLoadedFromS3() {
        // Test with builtin
        assertThat(service.isLoadedFromS3()).isFalse();

        // Test with S3 artifact
        FieldRegistryArtifact s3Artifact = new FieldRegistryArtifact(
                1, 2, List.of(), null, Instant.now(), "s3"
        );
        when(mockLoader.loadLatest()).thenReturn(s3Artifact);
        service.reload();

        assertThat(service.isLoadedFromS3()).isTrue();
    }

    @Test
    void testGetSource() {
        assertThat(service.getSource()).isEqualTo("builtin");
    }

    @Test
    void testInitFallbackWhenReloadFails() {
        FieldRegistryLoader failingLoader = mock(FieldRegistryLoader.class);
        when(failingLoader.loadLatest()).thenThrow(new RuntimeException("boom"));
        when(failingLoader.loadBuiltin()).thenReturn(new FieldRegistryLoader().loadBuiltin());

        FieldRegistryService failingService = new FieldRegistryService(failingLoader);
        failingService.init();

        assertThat(failingService.getFieldCount()).isEqualTo(26);
        assertThat(failingService.getSource()).isEqualTo("builtin");
    }

    @Test
    void testGetSourceUnknownWhenRegistryNull() throws Exception {
        var field = FieldRegistryService.class.getDeclaredField("registry");
        field.setAccessible(true);
        field.set(service, null);

        assertThat(service.getSource()).isEqualTo("unknown");
    }

    @Test
    void testIsStorageAccessible() {
        when(mockLoader.isStorageAccessible()).thenReturn(true);
        assertThat(service.isStorageAccessible()).isTrue();

        when(mockLoader.isStorageAccessible()).thenReturn(false);
        assertThat(service.isStorageAccessible()).isFalse();
    }

    @Test
    void testBuiltinFieldsMatchStaticRegistry() {
        // Verify all static FieldRegistry IDs can be resolved
        for (int i = 0; i < FieldRegistry.FIELD_COUNT; i++) {
            String fieldName = FieldRegistry.getName(i);
            int resolvedId = service.getFieldId(fieldName);
            assertThat(resolvedId).isEqualTo(i);
        }
    }
}
