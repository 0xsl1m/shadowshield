# Configuration

A single `ShieldConfig` drives the whole framework. Build it three ways:

```python
import shadowshield as ss

# 1. From a named mode (the 90% path)
shield = ss.Shield.for_mode("strict")

# 2. From a mode + overrides
shield = ss.Shield.for_mode("balanced", block_threshold=0.4, raise_on_block=True)

# 3. From YAML
shield = ss.Shield.from_yaml("shield.yaml")
```

Generate an annotated starter file with `shadowshield init > shield.yaml`.

## Modes

| Mode | block_threshold | medium→ | LLM check | rate limit |
|---|---|---|---|---|
| `strict` | 0.45 | block | on | on (30/60s) |
| `balanced` | 0.65 | sanitize | off | off |
| `permissive` | 0.85 | flag | off | off |

A mode seeds every default; any field you set in YAML or `for_mode(..., **kw)`
layers on top.

## Key fields

| Field | Meaning |
|---|---|
| `mode` | preset posture (strict/balanced/permissive) |
| `raise_on_block` | make `Shield.scan()` raise on a block (default false) |
| `block_threshold` | aggregate score that forces a block regardless of policy |
| `policy.{none..critical}` | severity → decision mapping |
| `detectors.<name>.enabled` | per-detector toggle |
| `detectors.<name>.weight` | trust multiplier (0–5) on that detector's score |
| `detectors.<name>.options` | detector-specific options (e.g. anomaly thresholds) |
| `disabled_detectors` | global kill-switch list (wins over `detectors`) |
| `llm_check.enabled` / `min_score_to_invoke` | gate the optional LLM judge |
| `rate_limit.*` | per-identity sliding-window throttle |
| `logging.audit_path` | JSONL audit file (null = stderr structlog only) |
| `logging.redact_payloads` | never write raw offending text to the audit log |

## Tuning guidance

- **Rolling out?** Start in `permissive`, point `logging.audit_path` at a file,
  and measure for a week. Promote to `balanced`/`strict` once you've seen the
  false-positive rate on your real traffic.
- **Too many false positives from one detector?** Lower its `weight` before you
  disable it — a 0.5 weight halves its contribution while keeping coverage.
- **High-assurance path?** Enable `llm_check` with a real judge; the gate keeps
  cost proportional to suspicious traffic only.
- **Multi-process rate limiting?** The default limiter is in-memory/process-local;
  subclass `RateLimitResponder` and back `_hits()` with Redis.

See [`src/shadowshield/config/default.yaml`](../src/shadowshield/config/default.yaml)
for the fully-commented reference.
