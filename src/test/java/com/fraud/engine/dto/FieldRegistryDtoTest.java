package com.fraud.engine.dto;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class FieldRegistryDtoTest {

    @Test
    void manifestGettersAndSetters() {
        FieldRegistryManifest manifest = new FieldRegistryManifest();
        manifest.setSchemaVersion(1);
        manifest.setRegistryVersion(2);
        manifest.setArtifactUri("s3://fields");
        manifest.setChecksum("abc");
        manifest.setFieldCount(26);
        manifest.setCreatedAt("2026-01-01");
        manifest.setCreatedBy("tester");

        assertThat(manifest.getSchemaVersion()).isEqualTo(1);
        assertThat(manifest.getRegistryVersion()).isEqualTo(2);
        assertThat(manifest.getArtifactUri()).isEqualTo("s3://fields");
        assertThat(manifest.getChecksum()).isEqualTo("abc");
        assertThat(manifest.getFieldCount()).isEqualTo(26);
        assertThat(manifest.getCreatedAt()).isEqualTo("2026-01-01");
        assertThat(manifest.getCreatedBy()).isEqualTo("tester");
    }

    @Test
    void artifactGettersAndSetters() {
        FieldRegistryEntry entry = new FieldRegistryEntry(1, "amount", "Amount", "desc", "NUMBER", List.of("gt"), false, false);
        FieldRegistryArtifact artifact = new FieldRegistryArtifact();
        artifact.setSchemaVersion(1);
        artifact.setRegistryVersion(3);
        artifact.setFields(List.of(entry));
        artifact.setChecksum("checksum");
        artifact.setCreatedAt(Instant.EPOCH);
        artifact.setCreatedBy("tester");

        assertThat(artifact.getSchemaVersion()).isEqualTo(1);
        assertThat(artifact.getRegistryVersion()).isEqualTo(3);
        assertThat(artifact.getFields()).hasSize(1);
        assertThat(artifact.getChecksum()).isEqualTo("checksum");
        assertThat(artifact.getCreatedAt()).isEqualTo(Instant.EPOCH);
        assertThat(artifact.getCreatedBy()).isEqualTo("tester");
    }

    @Test
    void entryGettersAndSetters() {
        FieldRegistryEntry entry = new FieldRegistryEntry();
        entry.setFieldId(10);
        entry.setFieldKey("card_hash");
        entry.setDisplayName("Card Hash");
        entry.setDescription("desc");
        entry.setDataType("STRING");
        entry.setAllowedOperators(List.of("eq"));
        entry.setMultiValueAllowed(true);
        entry.setSensitive(true);

        assertThat(entry.getFieldId()).isEqualTo(10);
        assertThat(entry.getFieldKey()).isEqualTo("card_hash");
        assertThat(entry.getDisplayName()).isEqualTo("Card Hash");
        assertThat(entry.getDescription()).isEqualTo("desc");
        assertThat(entry.getDataType()).isEqualTo("STRING");
        assertThat(entry.getAllowedOperators()).containsExactly("eq");
        assertThat(entry.isMultiValueAllowed()).isTrue();
        assertThat(entry.isSensitive()).isTrue();
    }
}
