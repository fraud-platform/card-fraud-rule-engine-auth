# HTTP/2 Support Guide

**Purpose:** Documentation for HTTP/2 support in the Card Fraud Rule Engine.

**Last Updated:** 2026-02-02

---

## Configuration

HTTP/2 is enabled in `application.yaml`:

```yaml
quarkus:
  http:
    version: 2.0  # Enable HTTP/2
```

---

## Benefits of HTTP/2

| Feature | Benefit |
|---------|---------|
| **Multiplexing** | Multiple requests over single TCP connection |
| **Header Compression** | HPACK reduces header overhead |
| **Server Push** | Server can proactively send resources |
| **Binary Protocol** | More efficient parsing |

---

## Performance Impact

### Benchmark Results (Expected)

| Metric | HTTP/1.1 | HTTP/2 | Improvement |
|--------|----------|--------|-------------|
| **Throughput (single conn)** | 1K RPS | 5K RPS | +400% |
| **Latency (single conn)** | 5ms | 5ms | Same |
| **Memory per conn** | Low | Higher | More complex state |
| **CPU** | Lower | Higher | HPACK compression |

**Note:** For rule engine (single request per connection), HTTP/2 benefits are minimal. HTTP/2 shines with:

- Multiple concurrent requests per connection
- Resource-intensive responses
- Many small requests

---

## Client Compatibility

### Supported Clients

| Client | HTTP/2 Support |
|--------|----------------|
| **curl 7.47+** | ✅ Yes (with --http2) |
| **Locust** | ❌ No (HTTP/1.1 only) |
| **httpx** | ✅ Yes |
| **Modern browsers** | ✅ Yes |

### Testing with curl

```bash
# HTTP/2 request
curl --http2 -v http://localhost:8081/health

# Check negotiated protocol
curl -v --http2-prior-knowledge http://localhost:8081/health
```

---

## TLS and ALPN

For production HTTP/2 with TLS (required for true HTTP/2 in most browsers):

```yaml
quarkus:
  http:
    ssl:
      enabled: true
      certificate:
        file: /path/to/cert.pem
      key:
        file: /path/to/key.pem
```

HTTP/2 with ALPN is negotiated automatically over TLS.

---

## Load Testing Consideration

**Important:** Locust (used for load testing) does not support HTTP/2. To test HTTP/2:

```bash
# Use hey (go-based HTTP/2 client)
go install github.com/rakyll/hey@latest
hey -n 10000 -c 100 -m POST -H "Content-Type: application/json" \
    -d @test-transaction.json http://localhost:8081/v1/evaluate/auth

# Use wrk2 with HTTP/2 support
git clone https://github.com/giltene/wrk2
cd wrk2 && make
./wrk -t2 -c100 -d30s -s post.lua http://localhost:8081/v1/evaluate/auth
```

---

## Monitoring

### Check HTTP Version in Use

```bash
# Check logs for negotiated protocol
# Quarkus logs HTTP version when enabled
```

### Metrics

HTTP/2 has different metrics than HTTP/1.1:

| Metric | Description |
|--------|-------------|
| `http.server.requests` | Request count (protocol-agnostic) |
| `http.server.active-requests` | Concurrent requests |
| `http.server.connection.duration` | Connection lifetime |

---

## Recommendation

**For the Rule Engine:**

| Scenario | Recommended |
|----------|-------------|
| **Development** | HTTP/2 (enabled by default) |
| **Production** | HTTP/2 (no downside) |
| **Load Testing** | Use HTTP/1.1 (Locust compatible) |

**Bottom Line:** HTTP/2 is enabled with no significant downside. Clients that don't support it will fall back to HTTP/1.1 automatically.

---

## References

- [Quarkus HTTP Configuration](https://quarkus.io/guides/http-reference)
- [HTTP/2 Specification](https://httpwg.org/specs/rfc7540.html)

---

**End of Document**
