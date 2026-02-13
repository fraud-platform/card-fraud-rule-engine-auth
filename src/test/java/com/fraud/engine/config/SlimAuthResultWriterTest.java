package com.fraud.engine.config;

import com.fraud.engine.resource.dto.SlimAuthResult;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SlimAuthResultWriterTest {

    private final SlimAuthResultWriter writer = new SlimAuthResultWriter();

    @Test
    void isWriteableReturnsTrueForSlimAuthResultJson() {
        boolean writeable = writer.isWriteable(
                SlimAuthResult.class,
                SlimAuthResult.class,
                new java.lang.annotation.Annotation[0],
                MediaType.APPLICATION_JSON_TYPE
        );

        assertTrue(writeable);
    }

    @Test
    void isWriteableReturnsFalseForOtherTypes() {
        boolean writeable = writer.isWriteable(
                String.class,
                String.class,
                new java.lang.annotation.Annotation[0],
                MediaType.APPLICATION_JSON_TYPE
        );

        assertFalse(writeable);
    }

    @Test
    void writeToSerializesExpectedShape() throws Exception {
        SlimAuthResult result = new SlimAuthResult();
        result.transaction_id = "tx-123";
        result.decision = "APPROVE";
        result.engine_mode = "NORMAL";
        result.engine_error_code = null;

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writer.writeTo(
                result,
                SlimAuthResult.class,
                SlimAuthResult.class,
                new java.lang.annotation.Annotation[0],
                MediaType.APPLICATION_JSON_TYPE,
                new MultivaluedHashMap<>(),
                out
        );

        assertEquals(
                "{\"transaction_id\":\"tx-123\",\"decision\":\"APPROVE\",\"engine_mode\":\"NORMAL\",\"engine_error_code\":null}",
                out.toString(StandardCharsets.UTF_8)
        );
    }

    @Test
    void writeToEscapesJsonSpecialCharacters() throws Exception {
        SlimAuthResult result = new SlimAuthResult();
        result.transaction_id = "tx\"\\\n";
        result.decision = "DECLINE";
        result.engine_mode = "FAIL_OPEN";
        result.engine_error_code = "E\"R\\R";

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writer.writeTo(
                result,
                SlimAuthResult.class,
                SlimAuthResult.class,
                new java.lang.annotation.Annotation[0],
                MediaType.APPLICATION_JSON_TYPE,
                new MultivaluedHashMap<>(),
                out
        );

        assertEquals(
                "{\"transaction_id\":\"tx\\\"\\\\\\n\",\"decision\":\"DECLINE\",\"engine_mode\":\"FAIL_OPEN\",\"engine_error_code\":\"E\\\"R\\\\R\"}",
                out.toString(StandardCharsets.UTF_8)
        );
    }
}
