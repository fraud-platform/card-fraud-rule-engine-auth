package com.fraud.engine.loader;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fraud.engine.dto.FieldRegistryArtifact;
import com.fraud.engine.dto.FieldRegistryEntry;
import com.fraud.engine.dto.FieldRegistryManifest;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.S3Exception;

import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;

/**
 * Loader for field registry artifacts from S3/MinIO storage.
 * <p>
 * This service loads field registry definitions from S3, with builtin
 * fallback when S3 is unavailable. The registry contains field definitions
 * used in rule compilation.
 * <p>
 * Follows the same pattern as RulesetLoader for consistency.
 */
@ApplicationScoped
public class FieldRegistryLoader {

    private static final Logger LOG = Logger.getLogger(FieldRegistryLoader.class);

    @ConfigProperty(name = "s3.endpoint-url")
    String endpointUrl;

    @ConfigProperty(name = "s3.aws.region")
    String region;

    @ConfigProperty(name = "s3.aws.credentials.static-provider.access-key-id")
    String accessKeyId;

    @ConfigProperty(name = "s3.aws.credentials.static-provider.secret-access-key")
    String secretAccessKey;

    @ConfigProperty(name = "app.ruleset.bucket", defaultValue = "fraud-gov-artifacts")
    String bucketName;

    @ConfigProperty(name = "app.field-registry.path-prefix", defaultValue = "fields/")
    String pathPrefix;

    private S3Client s3Client;
    private final ObjectMapper jsonMapper = new ObjectMapper();

    @PostConstruct
    void init() {
        try {
            LOG.infof("Initializing S3 client for FieldRegistry: %s", endpointUrl);

            s3Client = S3Client.builder()
                    .endpointOverride(URI.create(endpointUrl))
                    .region(Region.of(region))
                    .credentialsProvider(StaticCredentialsProvider.create(
                            AwsBasicCredentials.create(accessKeyId, secretAccessKey)))
                    .forcePathStyle(true) // Required for MinIO
                    .build();

            LOG.info("S3 client for FieldRegistry initialized successfully");

        } catch (Exception e) {
            LOG.error("Failed to initialize S3 client for FieldRegistry", e);
        }
    }

    /**
     * Loads the field registry manifest from S3.
     * <p>
     * The manifest contains the current registry version and artifact URI.
     *
     * @return the manifest, or null if not found or S3 is unavailable
     */
    public FieldRegistryManifest loadManifest() {
        try {
            String objectKey = pathPrefix + "registry/manifest.json";

            LOG.debugf("Loading field registry manifest from S3: bucket=%s, key=%s", bucketName, objectKey);

            GetObjectRequest getObjectRequest = GetObjectRequest.builder()
                    .bucket(bucketName)
                    .key(objectKey)
                    .build();

            try (InputStream inputStream = s3Client.getObject(getObjectRequest)) {
                FieldRegistryManifest manifest = jsonMapper.readValue(inputStream, FieldRegistryManifest.class);
                LOG.debugf("Loaded field registry manifest: version=%d, fields=%d",
                        manifest.registryVersion, manifest.fieldCount);
                return manifest;
            }

        } catch (NoSuchKeyException e) {
            LOG.debugf("Field registry manifest not found: %s", e.getMessage());
            return null;

        } catch (Exception e) {
            LOG.warnf("Error loading field registry manifest: %s", e.getMessage());
            return null;
        }
    }

    /**
     * Loads a specific version of the field registry from S3.
     *
     * @param version the registry version to load
     * @return the field registry artifact, or null if not found
     */
    public FieldRegistryArtifact loadRegistry(int version) {
        try {
            String objectKey = pathPrefix + "registry/v" + version + "/fields.json";

            LOG.infof("Loading field registry from S3: bucket=%s, key=%s", bucketName, objectKey);

            GetObjectRequest getObjectRequest = GetObjectRequest.builder()
                    .bucket(bucketName)
                    .key(objectKey)
                    .build();

            try (InputStream inputStream = s3Client.getObject(getObjectRequest)) {
                byte[] rawContent = inputStream.readAllBytes();
                String computedChecksum = computeChecksum(rawContent);

                FieldRegistryArtifact artifact = jsonMapper.readValue(rawContent, FieldRegistryArtifact.class);

                if (artifact.checksum != null && !artifact.checksum.isEmpty()) {
                    if (!computedChecksum.equalsIgnoreCase(artifact.checksum)) {
                        LOG.errorf("CHECKSUM MISMATCH for field registry v%d. Expected: %s, Computed: %s. " +
                                   "Artifact may be tampered. Rejecting load.",
                                version, artifact.checksum, computedChecksum);
                        return null;
                    }
                    LOG.debugf("Checksum validated successfully for field registry v%d", version);
                }

                LOG.infof("Field registry v%d loaded successfully with %d fields",
                        version, artifact.fields != null ? artifact.fields.size() : 0);

                return artifact;
            }

        } catch (NoSuchKeyException e) {
            LOG.warnf("Field registry version %d not found", version);
            return null;

        } catch (Exception e) {
            LOG.errorf(e, "Error loading field registry version %d", version);
            return null;
        }
    }

    /**
     * Loads the latest field registry from S3.
     * <p>
     * First loads the manifest to find the latest version, then loads that version.
     * Falls back to builtin registry if manifest not found or S3 is unavailable.
     *
     * @return the latest field registry artifact, or builtin fallback
     */
    public FieldRegistryArtifact loadLatest() {
        try {
            FieldRegistryManifest manifest = loadManifest();
            if (manifest == null || manifest.registryVersion <= 0) {
                LOG.debug("No manifest found, using builtin registry");
                return loadBuiltin();
            }

            FieldRegistryArtifact artifact = loadRegistry(manifest.registryVersion);
            if (artifact == null) {
                LOG.warnf("Failed to load registry version %d from manifest, using builtin",
                        manifest.registryVersion);
                return loadBuiltin();
            }

            return artifact;

        } catch (Exception e) {
            LOG.warnf("Error loading latest field registry, using builtin: %s", e.getMessage());
            return loadBuiltin();
        }
    }

    /**
     * Loads the builtin field registry (hardcoded fallback).
     * <p>
     * This provides the 26 standard fields as a fallback when S3 is unavailable.
     * This method never fails - it always returns a valid registry.
     *
     * @return the builtin field registry artifact
     */
    public FieldRegistryArtifact loadBuiltin() {
        LOG.debug("Loading builtin field registry (26 standard fields)");

        List<FieldRegistryEntry> builtinFields = BuiltinFieldRegistry.getFields();

        return new FieldRegistryArtifact(
                1, // schemaVersion
                1, // registryVersion (builtin is version 1)
                builtinFields,
                null, // checksum - not computed for builtin
                Instant.EPOCH, // createdAt
                "builtin" // createdBy
        );
    }

    /**
     * Checks if the S3 storage is accessible.
     *
     * @return true if S3 is accessible, false otherwise
     */
    public boolean isStorageAccessible() {
        try {
            software.amazon.awssdk.services.s3.model.HeadBucketRequest headBucketRequest =
                    software.amazon.awssdk.services.s3.model.HeadBucketRequest.builder()
                            .bucket(bucketName)
                            .build();

            s3Client.headBucket(headBucketRequest);
            return true;

        } catch (Exception e) {
            LOG.debugf("S3 storage is not accessible: %s", e.getMessage());
            return false;
        }
    }

    private String computeChecksum(byte[] content) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(content);
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            LOG.error("SHA-256 algorithm not available", e);
            return "";
        }
    }
}
