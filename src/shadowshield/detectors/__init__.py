"""Detection layer — the Sentinel-inspired half of ShadowShield.

Importing this package registers every built-in detector via the
``@register_detector`` decorator, so simply importing ``shadowshield`` wires up
the full detection suite. Custom detectors register the same way (see
``CONTRIBUTING.md``).
"""

from .anomaly import AnomalyDetector
from .base import (
    Detector,
    ScanContext,
    build_detectors,
    register_detector,
    registered_detectors,
)
from .canary import CanaryLeakDetector
from .encoding import EncodingObfuscationDetector
from .exfiltration import ExfiltrationDetector
from .jailbreak import JailbreakDetector
from .llm_check import (
    DEFAULT_JUDGE_PROMPT,
    LLMJudge,
    LLMJudgement,
    LLMSelfCheckDetector,
    make_keyword_judge,
)
from .pii import PIIDetector
from .prompt_injection import PromptInjectionDetector

# NOTE: TransformerDetector and VectorSimilarityDetector are intentionally NOT
# auto-registered — they pull models, so they're opt-in (via extra_detectors or
# the Shield use_transformer= / use_vectors= flags).
from .transformer import DEFAULT_MODEL as DEFAULT_TRANSFORMER_MODEL
from .transformer import TransformerDetector
from .vector import DEFAULT_EMBED_MODEL, VectorSimilarityDetector

__all__ = [
    # framework
    "Detector",
    "ScanContext",
    "register_detector",
    "registered_detectors",
    "build_detectors",
    # built-in detectors
    "PromptInjectionDetector",
    "JailbreakDetector",
    "EncodingObfuscationDetector",
    "ExfiltrationDetector",
    "AnomalyDetector",
    "PIIDetector",
    "CanaryLeakDetector",
    "LLMSelfCheckDetector",
    # opt-in model-backed detectors
    "TransformerDetector",
    "DEFAULT_TRANSFORMER_MODEL",
    "VectorSimilarityDetector",
    "DEFAULT_EMBED_MODEL",
    # llm-check helpers
    "LLMJudge",
    "LLMJudgement",
    "make_keyword_judge",
    "DEFAULT_JUDGE_PROMPT",
]
