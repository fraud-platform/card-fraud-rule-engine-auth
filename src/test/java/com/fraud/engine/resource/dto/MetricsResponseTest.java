package com.fraud.engine.resource.dto;

import com.fraud.engine.util.LatencyHistogram;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * Verifies {@link MetricsResponse} carries the AUTH latency histogram
 * snapshot so it is exposed by {@code GET /v1/manage/metrics}.
 */
class MetricsResponseTest {

    @Test
    void authLatencyGetterAndSetterRoundTrip() {
        MetricsResponse response = new MetricsResponse();
        LatencyHistogram.Snapshot snapshot = new LatencyHistogram().snapshot();

        response.setAuthLatency(snapshot);

        assertSame(snapshot, response.getAuthLatency());
        assertEquals(0L, response.getAuthLatency().count);
    }
}
