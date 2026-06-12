"""Third-party integrations that don't belong in the core middleware.

Currently: an AgentDojo defense adapter so ShadowShield can be evaluated as an
agent-level injection defense (security AND utility) on the gold-standard
benchmark. Imports here are lazy — nothing pulls a heavy/optional dependency at
package import time.
"""

from .agentdojo import (
    ShadowShieldVerdict,
    make_agentdojo_defense,
    scan_messages_for_injection,
)

__all__ = [
    "make_agentdojo_defense",
    "scan_messages_for_injection",
    "ShadowShieldVerdict",
]
