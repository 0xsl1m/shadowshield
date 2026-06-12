---
name: Attack pattern / bypass
about: A prompt-injection, jailbreak, or exfiltration technique ShadowShield misses
title: "[bypass] "
labels: ["bypass", "detection-gap"]
---

<!--
This is the MOST valuable kind of report. Attack-coverage gaps are handled in the
open — please do NOT use the private security email for these. (Use it only for
vulnerabilities in ShadowShield itself: silent detector disabling, ReDoS, audit-log
secret leaks, etc.)
-->

## Reproduction string

```
<paste the minimal payload that should have been caught>
```

## Expected

- **Category:** <e.g. prompt_injection / jailbreak / data_exfiltration>
- **Expected decision:** <block / sanitize / flag>
- **Direction:** <input / output>

## Actual

```python
import shadowshield as ss
r = ss.Shield.for_mode("strict").scan_input("<payload>")
print(r.decision.value, [c.value for c in r.categories])
# observed: allow []
```

## Environment

- ShadowShield version:
- Mode used:

## Bonus

- [ ] I'm willing to open a PR with a signature + regression test.
