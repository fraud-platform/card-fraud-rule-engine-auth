package com.fraud.engine.loader;

import com.fraud.engine.dto.FieldRegistryArtifact;
import com.fraud.engine.dto.FieldRegistryManifest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadBucketRequest;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FieldRegistryLoaderTest {

    @Mock
    S3Client s3Client;

    private FieldRegistryLoader loader;

    @BeforeEach
    void setUp() throws Exception {
        loader = new FieldRegistryLoader();
        setField("s3Client", s3Client);
        setField("bucketName", "fraud-gov-artifacts");
        setField("pathPrefix", "fields/");
    }

    @Test
    void loadManifestReturnsManifest() {
        String json = "{" +
                "\"schemaVersion\":1," +
                "\"registryVersion\":2," +
                "\"artifactUri\":\"s3://fields\"," +
                "\"checksum\":\"abc\"," +
                "\"fieldCount\":3," +
                "\"createdAt\":\"2026-01-01\"," +
                "\"createdBy\":\"tester\"" +
                "}";
        when(s3Client.getObject(any(GetObjectRequest.class)))
                .thenReturn(responseStream(json));

        FieldRegistryManifest manifest = loader.loadManifest();

        assertThat(manifest).isNotNull();
        assertThat(manifest.getRegistryVersion()).isEqualTo(2);
        assertThat(manifest.getFieldCount()).isEqualTo(3);
    }

    @Test
    void loadManifestMissingReturnsNull() {
        when(s3Client.getObject(any(GetObjectRequest.class)))
                .thenThrow(NoSuchKeyException.builder().message("missing").build());

        assertThat(loader.loadManifest()).isNull();
    }

    @Test
    void loadRegistryReturnsArtifact() {
        String json = "{" +
                "\"schemaVersion\":1," +
                "\"registryVersion\":4," +
                "\"fields\":[]" +
                "}";
        when(s3Client.getObject(any(GetObjectRequest.class)))
                .thenReturn(responseStream(json));

        FieldRegistryArtifact artifact = loader.loadRegistry(4);

        assertThat(artifact).isNotNull();
        assertThat(artifact.getRegistryVersion()).isEqualTo(4);
        assertThat(artifact.getFields()).isEmpty();
    }

    @Test
    void loadRegistryMissingReturnsNull() {
        when(s3Client.getObject(any(GetObjectRequest.class)))
                .thenThrow(NoSuchKeyException.builder().message("missing").build());

        assertThat(loader.loadRegistry(9)).isNull();
    }

    @Test
    void loadLatestFallsBackToBuiltin() {
        when(s3Client.getObject(any(GetObjectRequest.class)))
                .thenThrow(NoSuchKeyException.builder().message("missing").build());

        FieldRegistryArtifact artifact = loader.loadLatest();

        assertThat(artifact).isNotNull();
        assertThat(artifact.getCreatedBy()).isEqualTo("builtin");
        assertThat(artifact.getFields()).isNotEmpty();
    }

    @Test
    void loadLatestUsesBuiltinWhenManifestVersionInvalid() {
        String manifestJson = "{" +
                "\"schemaVersion\":1," +
                "\"registryVersion\":0," +
                "\"artifactUri\":\"s3://fields\"" +
                "}";
        when(s3Client.getObject(any(GetObjectRequest.class)))
                .thenReturn(responseStream(manifestJson));

        FieldRegistryArtifact artifact = loader.loadLatest();

        assertThat(artifact.getCreatedBy()).isEqualTo("builtin");
        assertThat(artifact.getFields()).isNotEmpty();
    }

    @Test
    void loadLatestFallsBackWhenRegistryMissing() {
        String manifestJson = "{" +
                "\"schemaVersion\":1," +
                "\"registryVersion\":2," +
                "\"artifactUri\":\"s3://fields\"" +
                "}";
        when(s3Client.getObject(any(GetObjectRequest.class)))
                .thenReturn(responseStream(manifestJson))
                .thenThrow(NoSuchKeyException.builder().message("missing").build());

        FieldRegistryArtifact artifact = loader.loadLatest();

        assertThat(artifact.getCreatedBy()).isEqualTo("builtin");
        assertThat(artifact.getFields()).isNotEmpty();
    }

    @Test
    void isStorageAccessibleTrueWhenHeadBucketSucceeds() {
        assertThat(loader.isStorageAccessible()).isTrue();
    }

    @Test
    void isStorageAccessibleFalseWhenHeadBucketFails() {
        doThrow(RuntimeException.class).when(s3Client).headBucket(any(HeadBucketRequest.class));

        assertThat(loader.isStorageAccessible()).isFalse();
    }

    private static ResponseInputStream<GetObjectResponse> responseStream(String json) {
        return new ResponseInputStream<>(
                GetObjectResponse.builder().build(),
                new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8))
        );
    }

    private void setField(String name, Object value) throws Exception {
        var field = FieldRegistryLoader.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(loader, value);
    }
}
