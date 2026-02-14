package com.fraud.engine.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fraud.engine.outbox.AsyncOutboxDispatcher;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.never;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LoadSheddingFilterTest {

    @Mock
    ContainerRequestContext requestContext;

    @Mock
    ContainerResponseContext responseContext;

    @Mock
    UriInfo uriInfo;

    @Mock
    AsyncOutboxDispatcher asyncOutboxDispatcher;

    private LoadSheddingFilter filter;

    @BeforeEach
    void setUp() throws Exception {
        filter = new LoadSheddingFilter();
        setField("enabled", true);
        setField("maxConcurrent", 0);
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        setField("objectMapper", mapper);
        setField("asyncOutboxDispatcher", asyncOutboxDispatcher);
        filter.init();
    }

    @Test
    void authLoadShedDefaultsApprove() throws Exception {
        String body = "{" +
                "\"transaction_id\":\"txn-3\"," +
                "\"transaction_type\":\"REFUND\"" +
                "}";

        when(requestContext.getUriInfo()).thenReturn(uriInfo);
        when(uriInfo.getPath()).thenReturn("/v1/evaluate/auth");
        when(requestContext.getEntityStream()).thenReturn(new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));

        filter.filter(requestContext);

        ArgumentCaptor<Response> captor = ArgumentCaptor.forClass(Response.class);
        verify(requestContext).abortWith(captor.capture());
        Response response = captor.getValue();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat((String) response.getEntity()).contains("\"decision\":\"APPROVE\"");
        assertThat((String) response.getEntity()).contains("\"ruleset_key\":\"CARD_AUTH\"");
        verify(asyncOutboxDispatcher).enqueueAuth(any(), any());
    }

    @Test
    void nonEvaluationPathDoesNothing() throws Exception {
        when(requestContext.getUriInfo()).thenReturn(uriInfo);
        when(uriInfo.getPath()).thenReturn("/v1/health");

        filter.filter(requestContext);

        verify(requestContext, never()).abortWith(any());
    }

    @Test
    void disabledFilterDoesNothing() throws Exception {
        LoadSheddingFilter disabledFilter = new LoadSheddingFilter();
        setField(disabledFilter, "enabled", false);
        setField(disabledFilter, "maxConcurrent", 100);
        disabledFilter.init();

        when(requestContext.getUriInfo()).thenReturn(uriInfo);
        when(uriInfo.getPath()).thenReturn("/v1/evaluate/auth");

        disabledFilter.filter(requestContext);

        verify(requestContext, never()).abortWith(any());
    }

    @Test
    void responseFilterReleasesPermit() throws Exception {
        // Create a new filter instance for this test to avoid state interference
        LoadSheddingFilter filterWithPermits = new LoadSheddingFilter();
        setField(filterWithPermits, "enabled", true);
        setField(filterWithPermits, "maxConcurrent", 10);
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        setField(filterWithPermits, "objectMapper", mapper);
        setField(filterWithPermits, "asyncOutboxDispatcher", asyncOutboxDispatcher);
        filterWithPermits.init();

        when(requestContext.getProperty("loadShedding.permitAcquired")).thenReturn(Boolean.TRUE);

        // Verify permits are available (should be close to maxConcurrent, accounting for any previous tests)
        int beforePermits = filterWithPermits.getAvailablePermits();
        assertThat(beforePermits).isGreaterThan(0);

        filterWithPermits.filter(requestContext, responseContext);

        // After releasing, available permits should increase (permit was returned)
        int afterPermits = filterWithPermits.getAvailablePermits();
        assertThat(afterPermits).isGreaterThan(beforePermits);
    }

    @Test
    void responseFilterSkipsWhenNoPermitAcquired() throws Exception {
        LoadSheddingFilter filterWithPermits = new LoadSheddingFilter();
        setField(filterWithPermits, "enabled", true);
        setField(filterWithPermits, "maxConcurrent", 10);
        filterWithPermits.init();

        when(requestContext.getProperty("loadShedding.permitAcquired")).thenReturn(null);

        int beforePermits = filterWithPermits.getAvailablePermits();
        filterWithPermits.filter(requestContext, responseContext);
        int afterPermits = filterWithPermits.getAvailablePermits();

        assertThat(afterPermits).isEqualTo(beforePermits);
    }

    @Test
    void getAvailablePermitsReturnsMaxWhenNotInitialized() throws Exception {
        LoadSheddingFilter newFilter = new LoadSheddingFilter();
        setField(newFilter, "maxConcurrent", 50);
        assertThat(newFilter.getAvailablePermits()).isEqualTo(50);
    }

    @Test
    void getShedCountReturnsZeroInitially() {
        assertThat(filter.getShedCount()).isEqualTo(0);
    }

    @Test
    void getProcessedCountReturnsZeroInitially() {
        assertThat(filter.getProcessedCount()).isEqualTo(0);
    }

    @Test
    void getUtilizationReturnsZeroWhenNotInitialized() {
        LoadSheddingFilter newFilter = new LoadSheddingFilter();
        assertThat(newFilter.getUtilization()).isEqualTo(0.0);
    }

    @Test
    void loadShedWithNullTransactionIdReturnsOk() throws Exception {
        String body = "{}";

        when(requestContext.getUriInfo()).thenReturn(uriInfo);
        when(uriInfo.getPath()).thenReturn("/v1/evaluate/auth");
        when(requestContext.getEntityStream()).thenReturn(new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));

        filter.filter(requestContext);

        ArgumentCaptor<Response> captor = ArgumentCaptor.forClass(Response.class);
        verify(requestContext).abortWith(captor.capture());
        assertThat(captor.getValue().getStatus()).isEqualTo(200);
    }

    @Test
    void transferTransactionTypeUsesCorrectRuleset() throws Exception {
        String body = "{" +
                "\"transaction_id\":\"txn-transfer\"," +
                "\"transaction_type\":\"TRANSFER\"" +
                "}";

        when(requestContext.getUriInfo()).thenReturn(uriInfo);
        when(uriInfo.getPath()).thenReturn("/v1/evaluate/auth");
        when(requestContext.getEntityStream()).thenReturn(new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));

        filter.filter(requestContext);

        ArgumentCaptor<Response> captor = ArgumentCaptor.forClass(Response.class);
        verify(requestContext).abortWith(captor.capture());
        String response = (String) captor.getValue().getEntity();
        assertThat(response).contains("\"ruleset_key\":\"CARD_AUTH\"");
    }

    @Test
    void unknownTransactionTypeUsesCardAuthRuleset() throws Exception {
        String body = "{" +
                "\"transaction_id\":\"txn-unknown\"," +
                "\"transaction_type\":\"UNKNOWN_TYPE\"" +
                "}";

        when(requestContext.getUriInfo()).thenReturn(uriInfo);
        when(uriInfo.getPath()).thenReturn("/v1/evaluate/auth");
        when(requestContext.getEntityStream()).thenReturn(new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));

        filter.filter(requestContext);

        ArgumentCaptor<Response> captor = ArgumentCaptor.forClass(Response.class);
        verify(requestContext).abortWith(captor.capture());
        String response = (String) captor.getValue().getEntity();
        assertThat(response).contains("\"ruleset_key\":\"CARD_AUTH\"");
    }

    private void setField(String name, Object value) throws Exception {
        var field = LoadSheddingFilter.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(filter, value);
    }

    private void setField(LoadSheddingFilter target, String name, Object value) throws Exception {
        var field = LoadSheddingFilter.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }
}
