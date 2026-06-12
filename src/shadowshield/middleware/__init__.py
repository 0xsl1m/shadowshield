"""Framework integrations — plug ShadowShield into your LLM stack.

Heavy / optional integrations (LangChain) are imported lazily inside their
modules, so importing this package never forces an optional dependency.
"""

from .base import message_direction, message_text, scan_messages
from .decorators import get_default_shield, protect, set_default_shield
from .openai import ShieldedChatClient, guard_conversation

__all__ = [
    "protect",
    "get_default_shield",
    "set_default_shield",
    "ShieldedChatClient",
    "guard_conversation",
    "scan_messages",
    "message_text",
    "message_direction",
]
