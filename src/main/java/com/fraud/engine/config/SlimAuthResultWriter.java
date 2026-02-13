package com.fraud.engine.config;

import com.fasterxml.jackson.core.io.JsonStringEncoder;
import com.fraud.engine.resource.dto.SlimAuthResult;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.ext.MessageBodyWriter;
import jakarta.ws.rs.ext.Provider;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;

/**
 * Dedicated writer for AUTH responses to avoid reflection-heavy bean serialization.
 */
@Provider
@Priority(Priorities.USER - 200)
@Produces(MediaType.APPLICATION_JSON)
@ApplicationScoped
public class SlimAuthResultWriter implements MessageBodyWriter<SlimAuthResult> {

    private static final JsonStringEncoder JSON_STRING_ENCODER = JsonStringEncoder.getInstance();

    private static final byte[] OPEN = "{".getBytes(StandardCharsets.UTF_8);
    private static final byte[] CLOSE = "}".getBytes(StandardCharsets.UTF_8);
    private static final byte[] COMMA = ",".getBytes(StandardCharsets.UTF_8);
    private static final byte[] NULL = "null".getBytes(StandardCharsets.UTF_8);

    private static final byte[] FIELD_TRANSACTION_ID =
            "\"transaction_id\":".getBytes(StandardCharsets.UTF_8);
    private static final byte[] FIELD_DECISION =
            "\"decision\":".getBytes(StandardCharsets.UTF_8);
    private static final byte[] FIELD_ENGINE_MODE =
            "\"engine_mode\":".getBytes(StandardCharsets.UTF_8);
    private static final byte[] FIELD_ENGINE_ERROR_CODE =
            "\"engine_error_code\":".getBytes(StandardCharsets.UTF_8);

    @Override
    public boolean isWriteable(
            Class<?> type,
            Type genericType,
            Annotation[] annotations,
            MediaType mediaType
    ) {
        return SlimAuthResult.class.isAssignableFrom(type)
                && (mediaType == null || MediaType.APPLICATION_JSON_TYPE.isCompatible(mediaType));
    }

    @Override
    public void writeTo(
            SlimAuthResult value,
            Class<?> type,
            Type genericType,
            Annotation[] annotations,
            MediaType mediaType,
            MultivaluedMap<String, Object> httpHeaders,
            OutputStream entityStream
    ) throws IOException, WebApplicationException {
        SlimAuthResult result = value == null ? new SlimAuthResult() : value;

        entityStream.write(OPEN);
        writeField(entityStream, FIELD_TRANSACTION_ID, result.transaction_id);
        entityStream.write(COMMA);
        writeField(entityStream, FIELD_DECISION, result.decision);
        entityStream.write(COMMA);
        writeField(entityStream, FIELD_ENGINE_MODE, result.engine_mode);
        entityStream.write(COMMA);
        writeField(entityStream, FIELD_ENGINE_ERROR_CODE, result.engine_error_code);
        entityStream.write(CLOSE);
    }

    private static void writeField(OutputStream out, byte[] fieldName, String value) throws IOException {
        out.write(fieldName);
        if (value == null) {
            out.write(NULL);
            return;
        }

        out.write('"');
        out.write(JSON_STRING_ENCODER.quoteAsUTF8(value));
        out.write('"');
    }
}
