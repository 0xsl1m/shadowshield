"""Framework integrations — plug ShadowShield into your LLM stack.

Heavy / optional integrations (LangChain) are imported lazily inside their
modules, so importing this package never forces an optional dependency.
"""

from .anthropic import ShieldedAnthropicClient, guard_anthropic_conversation
from .asgi import ShieldASGIMiddleware
from .base import message_direction, message_text, scan_messages
from .decorators import get_default_shield, protect, set_default_shield
from .litellm import ShieldedLiteLLM, shielded_completion
from .openai import ShieldedChatClient, guard_conversation
from .rag import (
    RAGScanReport,
    ShieldedHaystackRetriever,
    ShieldedLlamaIndexRetriever,
    scan_retrieved_chunks,
)

__all__ = [
    "protect",
    "get_default_shield",
    "set_default_shield",
    "ShieldedChatClient",
    "ShieldedAnthropicClient",
    "ShieldedLiteLLM",
    "ShieldASGIMiddleware",
    "ShieldedLlamaIndexRetriever",
    "ShieldedHaystackRetriever",
    "RAGScanReport",
    "scan_retrieved_chunks",
    "guard_conversation",
    "guard_anthropic_conversation",
    "shielded_completion",
    "scan_messages",
    "message_text",
    "message_direction",
]
