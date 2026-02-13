package com.fraud.engine.watcher;

import com.fraud.engine.dto.FieldRegistryManifest;
import com.fraud.engine.loader.FieldRegistryLoader;
import com.fraud.engine.service.FieldRegistryService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FieldRegistryWatcherTest {

    @Mock
    FieldRegistryLoader loader;

    @Mock
    FieldRegistryService service;

    private FieldRegistryWatcher watcher;

    @BeforeEach
    void setUp() throws Exception {
        watcher = new FieldRegistryWatcher(loader, service);
        setField("hotReloadEnabled", true);
        setField("pollIntervalSeconds", 30);
    }

    @Test
    void startDisabledDoesNothing() throws Exception {
        setField("hotReloadEnabled", false);
        watcher.start();
        assertThat(watcher.isRunning()).isFalse();
    }

    @Test
    void startAndStopLifecycle() throws Exception {
        FieldRegistryManifest manifest = new FieldRegistryManifest(1, 2, "s3://fields", "abc", 26, "2026-01-01", "tester");
        when(loader.loadManifest()).thenReturn(manifest);

        watcher.start();
        assertThat(watcher.isRunning()).isTrue();

        watcher.stop();
        assertThat(watcher.isRunning()).isFalse();
    }

    @Test
    void triggerCheckUpdatesVersionOnReload() throws Exception {
        setField("running", true);
        setField("lastVersion", 1);

        FieldRegistryManifest manifest = new FieldRegistryManifest(1, 2, "s3://fields", "abc", 26, "2026-01-01", "tester");
        when(loader.loadManifest()).thenReturn(manifest);
        when(service.getRegistryVersion()).thenReturn(2);

        watcher.triggerCheck();

        assertThat(watcher.getLastVersion()).isEqualTo(2);
        verify(service, times(1)).reload();
    }

    @Test
    void triggerCheckNoManifestKeepsVersion() throws Exception {
        setField("running", true);
        setField("lastVersion", 3);
        when(loader.loadManifest()).thenReturn(null);

        watcher.triggerCheck();

        assertThat(watcher.getLastVersion()).isEqualTo(3);
        verify(service, times(0)).reload();
    }

    @Test
    void triggerCheckRollbackUpdatesVersion() throws Exception {
        setField("running", true);
        setField("lastVersion", 5);
        FieldRegistryManifest manifest = new FieldRegistryManifest(1, 4, "s3://fields", "abc", 26, "2026-01-01", "tester");
        when(loader.loadManifest()).thenReturn(manifest);

        watcher.triggerCheck();

        assertThat(watcher.getLastVersion()).isEqualTo(4);
    }

    @Test
    void triggerCheckReloadFailureKeepsVersion() throws Exception {
        setField("running", true);
        setField("lastVersion", 1);
        FieldRegistryManifest manifest = new FieldRegistryManifest(1, 2, "s3://fields", "abc", 26, "2026-01-01", "tester");
        when(loader.loadManifest()).thenReturn(manifest);
        doThrow(new RuntimeException("boom")).when(service).reload();

        watcher.triggerCheck();

        assertThat(watcher.getLastVersion()).isEqualTo(1);
    }

    private void setField(String name, Object value) throws Exception {
        var field = FieldRegistryWatcher.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(watcher, value);
    }
}
