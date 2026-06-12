# Detectors

Every detector is a stateless `(text, context) -> list[Threat]` function. The
engine builds one shared `ScanContext` per scan (normalised view + decoded
segments computed once) and feeds it to each detector.

List the live registry any time with `shadowshield detectors` or
`shadowshield.registered_detectors()`.

## Built-in detectors

### `prompt_injection` *(flagship)*
Instruction-override and frame attacks. Matches on the **normalised** text and on
**decoded** base64/hex segments (a hidden override is scored *higher*, not lower).
Covers: ignore/disregard/forget previous instructions, new-instruction injection,
authority spoofing ("the real user says…"), persona reassignment ("you are now…"),
fake `<system>` / `<system-reminder>` tags, chat-template tokens (`<|im_start|>`),
and `[INST]` delimiters. Directions: input + output.

### `jailbreak`
Persona/mode unlocks and safety-suppression: DAN/STAN personas, "developer/god
mode", "no restrictions/filters", fiction & hypothetical wrappers around
operational requests, "do not warn/refuse". Direction: input.

### `encoding_obfuscation`
Scores the *carrier* of an attack independent of content: invisible/bidirectional
control characters, homoglyph confusables, and decodable hidden base64/hex blobs.
Directions: input + output.

### `data_exfiltration`
Two jobs. **Input:** exfiltration *instructions* — system-prompt extraction,
markdown-image beacons (`![x](…?d=secret)`), pipe-to-shell, "send the key to…".
**Both directions:** actual **secret material** — private keys, OpenAI/Anthropic/
AWS/GitHub/Slack/Google keys, JWTs — with severity bumped when a secret is leaving
in model *output*. Secrets are never copied into the threat record.

### `anomaly`
Dependency-free heuristics (length, special-char ratio, Shannon entropy, repeat
runs) that corroborate the signature layers and catch novel phrasings. Optionally
upgradeable to a scikit-learn `IsolationForest` via the `[ml]` extra. Direction:
input.

### `llm_self_check` *(optional, gated)*
Consults an application-supplied judge callable `(text, direction) -> LLMJudgement`.
Only runs when `llm_check.enabled` is set, a judge is wired in via
`Shield(llm_judge=…)`, **and** the cheap tiers already scored ≥
`min_score_to_invoke` — so you never pay for a model call on clean traffic. A
judge error fails safe (low-confidence note, never a crash).

## Writing your own

```python
from shadowshield import register_detector, Detector, ScanContext
from shadowshield import Threat, ThreatCategory, Severity, Direction

@register_detector
class MyDetector(Detector):
    name = "my_detector"               # unique; collisions raise at import
    directions = (Direction.INPUT,)    # default is both

    def scan(self, text: str, *, context: ScanContext) -> list[Threat]:
        # Prefer context.normalized.normalized for matching (de-obfuscated),
        # but report spans against the original `text` for useful audit logs.
        ...
        return []
```

Tips:
- Set a realistic `score` (0–1) and `severity`. The aggregator combines them; a
  weak corroborating signal should score ~0.4–0.5, a confident hit ~0.8+.
- Give every detector a unique `name` — it's used in config, weights, and logs.
- Tune trust per deployment with `detectors.<name>.weight` in config.
- Keep it fast and pure. Anything stateful belongs on the `ScanContext`.
