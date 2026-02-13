# How to Run AUTH-Only Load Test

## Problem

The e2e load testing harness (`card-fraud-e2e-load-testing`) defaults to **70% AUTH / 30% MONITORING** mix.

For AUTH performance optimization, we need **100% AUTH** traffic to:
1. Eliminate resource contention with MONITORING endpoint
2. Measure pure AUTH capacity
3. Identify AUTH-specific bottlenecks (like Redis pool saturation)

## Traffic Mix Configuration

### Location
`card-fraud-e2e-load-testing/src/config/defaults.py`

```python
@dataclass
class TrafficMix:
    """Traffic mix for Rule Engine."""

    preauth: float = 0.70  # 70% AUTH (/v1/evaluate/auth)
    postauth: float = 0.30  # 30% MONITORING (/v1/evaluate/monitoring)
```

### Current Limitation
⚠️ **NOT configurable via environment variables!**

The `from_env()` method doesn't load `traffic_mix` from env vars, only loads:
- `RULE_ENGINE_RPS`
- `RULE_ENGINE_P50_MS`
- `RULE_ENGINE_P95_MS`
- `RULE_ENGINE_P99_MS`
- `RULE_ENGINE_USERS`

## Solutions

### Option 1: Temporary Code Change (Quick)

Edit `card-fraud-e2e-load-testing/src/config/defaults.py`:

```python
@dataclass
class TrafficMix:
    """Traffic mix for Rule Engine."""

    preauth: float = 1.0  # 100% AUTH
    postauth: float = 0.0  # 0% MONITORING
```

Then run:
```bash
cd /c/Users/kanna/github/card-fraud-e2e-load-testing
```

### Option 2: Add Environment Variable Support (Proper)

Add to `RuleEngineConfig.from_env()` in `defaults.py`:

```python
@classmethod
def from_env(cls) -> RuleEngineConfig:
    """Load from environment variables."""
    traffic_mix = TrafficMix(
        preauth=float(os.getenv("RULE_ENGINE_PREAUTH_PCT", "0.70")),
        postauth=float(os.getenv("RULE_ENGINE_POSTAUTH_PCT", "0.30")),
    )

    return cls(
        target_rps=int(os.getenv("RULE_ENGINE_RPS", str(cls().target_rps))),
        # ... rest of config
        traffic_mix=traffic_mix,
    )
```

Then run:
```bash
RULE_ENGINE_PREAUTH_PCT=1.0 RULE_ENGINE_POSTAUTH_PCT=0.0 uv run lt-run ...
```

### Option 3: Dedicated AUTH-Only Locustfile

Create `locustfile-auth-only.py`:

```python
from locust import HttpUser, between
from src.tasksets.rule_engine.auth import AuthTaskSet

class AuthOnlyUser(HttpUser):
    wait_time = between(0.001, 0.010)
    host = "http://localhost:8081"
    tasks = {AuthTaskSet: 1}  # 100% AUTH
```

Then run:
```bash
locust -f locustfile-auth-only.py --users=100 --spawn-rate=20 --run-time=2m --headless
```

## Recommended Approach

**For this session:** Use Option 1 (quick temp change)
**For future:** Implement Option 2 (env var support) in e2e repo

## Expected Difference

**Mixed Traffic (70/30):**
- AUTH shares resources with MONITORING
- Better for production-like testing

**AUTH-Only (100/0):**
- Exposes AUTH-specific bottlenecks (Redis pool saturation)
- Shows maximum AUTH capacity
- Previous AUTH-only test: 97ms AVG (20% slower due to pool saturation)
- After pool increase (100→200): Expected to be FASTER than mixed

## References

- Previous AUTH-only analysis: `docs/04-testing/AUTH-ONLY-ANALYSIS-2026-02-08.md`
- Traffic mix code: `card-fraud-e2e-load-testing/src/config/defaults.py:14-15`
- Task loading: `card-fraud-e2e-load-testing/src/locustfile.py:206-209`
