package com.fraud.engine.dto;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class RulesetManifestTest {

    @Test
    void gettersReturnValues() throws Exception {
        RulesetManifest manifest = new RulesetManifest();
        setField(manifest, "schemaVersion", "2.0");
        setField(manifest, "environment", "local");
        setField(manifest, "rulesetKey", "CARD_AUTH");
        setField(manifest, "rulesetVersion", 3);
        setField(manifest, "fieldRegistryVersion", 2);
        setField(manifest, "artifactUri", "s3://ruleset");
        setField(manifest, "checksum", "abc");
        setField(manifest, "publishedAt", Instant.EPOCH);

        assertThat(manifest.getSchemaVersion()).isEqualTo("2.0");
        assertThat(manifest.getEnvironment()).isEqualTo("local");
        assertThat(manifest.getRulesetKey()).isEqualTo("CARD_AUTH");
        assertThat(manifest.getRulesetVersion()).isEqualTo(3);
        assertThat(manifest.getFieldRegistryVersion()).isEqualTo(2);
        assertThat(manifest.getArtifactUri()).isEqualTo("s3://ruleset");
        assertThat(manifest.getChecksum()).isEqualTo("abc");
        assertThat(manifest.getPublishedAt()).isEqualTo(Instant.EPOCH);
    }

    private void setField(Object target, String name, Object value) throws Exception {
        var field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }
}
