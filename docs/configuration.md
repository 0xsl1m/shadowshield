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

| Mode | block_threshold | medium→ | detector failure | LLM check | rate limit |
|---|---|---|---|---|---|
| `strict` | 0.45 | block | block | on | on (30/60s) |
| `balanced` | 0.65 | sanitize | report | off | off |
| `permissive` | 0.85 | flag | report | off | off |
| `shadow` | 1.0 (disabled) | flag | report only | off | off |

A mode seeds every default; any field you set in YAML or `for_mode(..., **kw)`
layers on top.

## Key fields

| Field | Meaning |
|---|---|
| `mode` | preset posture (strict/balanced/permissive/shadow) |
| `raise_on_block` | make `Shield.scan()` raise on a block (default false) |
| `fail_closed_on_detector_error` | block if any detector raises; failures are always reported as content-free metadata (strict defaults true) |
| `parallel_detectors` | fan cheap detectors out across a bounded thread pool (default false). Verdicts, ordering, and error accounting are identical to sequential — only wall-clock latency changes |
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

- **Rolling out?** Start in `shadow`, point `logging.audit_path` at a file,
  and measure representative traffic. `permissive` still blocks critical
  findings. Promote only after reviewing false positives and coverage for the
  exact application and policy.
- **Too many false positives from one detector?** Lower its `weight` before you
  disable it — a 0.5 weight halves its contribution while keeping coverage.
- **High-assurance path?** Enable `llm_check` with a real judge; the gate keeps
  cost proportional to suspicious traffic only.
- **Multi-process rate limiting?** The default limiter is in-memory/process-local;
  subclass `RateLimitResponder` and back `_hits()` with Redis.

See [`src/shadowshield/config/default.yaml`](../src/shadowshield/config/default.yaml)
for the fully-commented reference.

## Proxy policy and limits

The proxy scans POST `/v1/chat/completions`, `/v1/completions`, `/v1/messages`,
and `/v1/responses`. Other paths are authenticated passthrough. Text scanning
does not cover image/audio bytes, provider-side stored context, or remote tool
execution performed inside the provider. A configured route or a health counter
is not proof of complete agent/tool coverage.

`shadow` preserves request and response payloads, including SSE event framing.
It bounds inspection work without turning findings into blocks or sanitized
content. HTTP authentication, request-body size, and concurrency limits still
apply in every mode.

Enforcing modes reject requests whose relevant content exceeds the extractor's
bounded coverage rather than silently omitting later messages. The default
scanner also blocks individual inputs beyond `max_input_chars` (100,000).
These limits can affect long agent histories. A scanner failure must produce an
explicit failure rather than forward content as though its scan had passed.

Deterministic detectors can flag legitimate security documentation or test
fixtures that quote attack strings. Do not bypass this by trusting any quoted
text or local filename. A coding-agent rollout needs application-specific
provenance and policy, labeled benign cases, and a tested return-to-shadow path.

### Isolated proxy credentials

By default, explicit `api_keys` and `SHADOWSHIELD_API_KEY` are combined for
compatibility. An in-process deployment using a dedicated protected credential
can call `create_proxy_app(..., api_keys=[key], include_environment_keys=False)`.
Only the explicit key is then accepted; missing/empty explicit keys cause
startup to fail instead of disabling authentication. Read `key` through the
deployment's protected secret mechanism, never through a command-line argument.
The proxy strips `X-API-Key` before forwarding to the provider.
