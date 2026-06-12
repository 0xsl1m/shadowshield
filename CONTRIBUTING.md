# Contributing to ShadowShield

Thanks for helping make agentic AI safer. ShadowShield is community-driven and
every contribution — a new detection pattern, a framework integration, a bug
report, or a doc fix — moves the whole ecosystem forward.

## Ways to contribute

- **New attack patterns.** Found a prompt-injection or jailbreak technique that
  slips past ShadowShield? Add a signature + a regression test. This is the most
  valuable contribution you can make.
- **New detectors / responders.** Implement the `Detector` or `Responder`
  protocol and register it. See "Extending" below.
- **Framework middleware.** Wire ShadowShield into another framework
  (Haystack, CrewAI, AutoGen, Semantic Kernel, …).
- **Docs & examples.** Clearer docs help everyone.

## Development setup

```bash
git clone https://github.com/0xsl1m/shadowshield
cd shadowshield
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev,all]"
```

## Before you open a PR

```bash
ruff check src tests          # lint
ruff format src tests         # format
mypy src/shadowshield         # type-check
pytest --cov=shadowshield     # tests + coverage
```

All four must pass. New behavior needs tests; new attack patterns need a test
that fails before your fix and passes after.

## Extending ShadowShield

### A custom detector

```python
from shadowshield.detectors import Detector, register_detector
from shadowshield.core.types import Direction, Threat, ThreatCategory, Severity

@register_detector
class MyDetector(Detector):
    name = "my_detector"

    def scan(self, text: str, *, direction: Direction, context) -> list[Threat]:
        if "danger" in text.lower():
            return [Threat(
                category=ThreatCategory.PROMPT_INJECTION,
                severity=Severity.HIGH,
                score=0.9,
                detector=self.name,
                message="Found the literal word 'danger'.",
            )]
        return []
```

Any detector decorated with `@register_detector` is auto-discovered by the
engine. Plugins distributed as separate packages can register via the
`shadowshield.plugins` entry-point group (see `docs/plugins.md`).

## Security disclosures

If you find a vulnerability **in ShadowShield itself** (e.g. a bypass that lets a
detector be silently disabled, or a ReDoS in a pattern), please do **not** open a
public issue. Report it privately via **GitHub Security Advisories** (the
repository's **Security** tab → **Report a vulnerability**). We aim to respond
within 72 hours. See [`SECURITY.md`](SECURITY.md).

Reporting *new attack techniques that ShadowShield should detect* is the
opposite — please open those publicly so the community benefits.

## Code of conduct

Be excellent to each other. Harassment, discrimination, or hostility will not be
tolerated. Report conduct concerns privately to the maintainers via a GitHub
Security Advisory (used here as a confidential contact channel) or by opening an
issue if the matter is not sensitive.

## License

By contributing you agree your contributions are licensed under the MIT License.
