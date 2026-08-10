"""RAG pipeline middleware — scan retrieved context before it reaches the prompt.

Retrieved chunks are untrusted third-party content: a poisoned document is the
classic indirect prompt-injection vector (the model obeys instructions hidden
in its own context). :func:`scan_retrieved_chunks` runs every chunk through the
shield (INPUT direction) and drops, annotates, or rejects hostile chunks before
they are stuffed into the prompt. The LlamaIndex / Haystack wrappers apply the
same policy inside each framework's retriever contract — both are duck-typed,
so neither framework is a dependency of ShadowShield.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..core.shield import Shield
from ..core.types import ScanResult, ThreatBlockedError

_MAX_CHUNKS = 256


@dataclass
class RAGScanReport:
    """Outcome of scanning one retrieval batch.

    Attributes:
        safe_chunks: chunk texts that may enter the prompt (threats dropped or
            replaced, per the chosen policy).
        results: one :class:`ScanResult` per scanned chunk, in input order.
        dropped: how many chunks were removed by the policy.
    """

    safe_chunks: list[str] = field(default_factory=list)
    results: list[ScanResult] = field(default_factory=list)
    dropped: int = 0


def _chunk_text(chunk: Any) -> str:
    """Best-effort text extraction from a retrieved chunk.

    Handles plain strings, dicts (``text`` / ``content`` keys), Haystack
    ``Document`` objects (``.content``), and LlamaIndex nodes (``.text`` or
    ``.get_content()``).
    """
    if isinstance(chunk, str):
        return chunk
    if isinstance(chunk, dict):
        for key in ("text", "content"):
            value = chunk.get(key)
            if isinstance(value, str):
                return value
        return ""
    text = getattr(chunk, "text", None)
    if isinstance(text, str):
        return text
    content = getattr(chunk, "content", None)
    if isinstance(content, str):
        return content
    get_content = getattr(chunk, "get_content", None)
    if callable(get_content):
        try:
            value = get_content()
        except Exception:  # a broken node must not break the pipeline
            return ""
        return value if isinstance(value, str) else ""
    return ""


def scan_retrieved_chunks(
    shield: Shield,
    chunks: list[Any],
    *,
    identity: str | None = None,
    on_threat: str = "drop",
    max_chunks: int = _MAX_CHUNKS,
) -> RAGScanReport:
    """Scan retrieved chunks and return the ones safe to stuff into a prompt.

    Args:
        shield: the :class:`Shield` to enforce.
        chunks: retrieved chunks (strings, dicts, Haystack Documents,
            LlamaIndex nodes — see :func:`_chunk_text`).
        identity: stable identity for rate limiting (e.g. end-user id).
        on_threat: ``"drop"`` (default) removes blocked chunks; ``"keep"``
            reports but retains everything; ``"raise"`` raises
            :class:`ThreatBlockedError` on the first blocked chunk.
        max_chunks: retrieval-fan-out bound — chunks beyond this are ignored
            (and counted as dropped) so a runaway retriever cannot turn one
            query into unbounded scan work.
    """
    if on_threat not in ("drop", "keep", "raise"):
        raise ValueError("on_threat must be 'drop', 'keep', or 'raise'")
    if max_chunks <= 0:
        raise ValueError("max_chunks must be greater than zero")

    report = RAGScanReport()
    for index, chunk in enumerate(chunks):
        if index >= max_chunks:
            report.dropped += 1
            continue
        text = _chunk_text(chunk)
        if not text.strip():
            report.dropped += 1
            continue
        result = shield.scan_input(text, identity=identity)
        report.results.append(result)
        if result.blocked:
            if on_threat == "raise":
                raise ThreatBlockedError(result)
            if on_threat == "drop":
                report.dropped += 1
                continue
        report.safe_chunks.append(result.safe_text)
    return report


class ShieldedLlamaIndexRetriever:
    """Wrap a LlamaIndex-style retriever (``.retrieve(query)``) so every
    returned node is scanned; poisoned nodes are removed before the
    synthesizer ever sees them."""

    def __init__(
        self,
        retriever: Any,
        shield: Shield,
        *,
        identity: str | None = None,
        on_threat: str = "drop",
        max_chunks: int = _MAX_CHUNKS,
    ) -> None:
        if on_threat not in ("drop", "keep", "raise"):
            raise ValueError("on_threat must be 'drop', 'keep', or 'raise'")
        self._retriever = retriever
        self._shield = shield
        self._identity = identity
        self._on_threat = on_threat
        self._max_chunks = max_chunks
        self.last_report: RAGScanReport | None = None

    def retrieve(self, query: Any, *args: Any, **kwargs: Any) -> list[Any]:
        nodes = list(self._retriever.retrieve(query, *args, **kwargs))
        report = RAGScanReport()
        kept: list[Any] = []
        for node_with_score in nodes[: self._max_chunks]:
            # LlamaIndex NodeWithScore wraps the payload in ``.node``.
            node = getattr(node_with_score, "node", node_with_score)
            text = _chunk_text(node)
            if not text.strip():
                report.dropped += 1
                continue
            result = self._shield.scan_input(text, identity=self._identity)
            report.results.append(result)
            if result.blocked:
                if self._on_threat == "raise":
                    raise ThreatBlockedError(result)
                if self._on_threat == "drop":
                    report.dropped += 1
                    continue
            kept.append(node_with_score)
            report.safe_chunks.append(result.safe_text)
        report.dropped += max(0, len(nodes) - self._max_chunks)
        self.last_report = report
        return kept

    def __getattr__(self, item: str) -> Any:
        return getattr(self._retriever, item)


class ShieldedHaystackRetriever:
    """Wrap a Haystack-style retriever (``.run(query=...)`` ->
    ``{"documents": [...]}``) so every returned Document is scanned;
    poisoned documents are removed from the result dict."""

    def __init__(
        self,
        retriever: Any,
        shield: Shield,
        *,
        identity: str | None = None,
        on_threat: str = "drop",
        max_chunks: int = _MAX_CHUNKS,
    ) -> None:
        if on_threat not in ("drop", "keep", "raise"):
            raise ValueError("on_threat must be 'drop', 'keep', or 'raise'")
        self._retriever = retriever
        self._shield = shield
        self._identity = identity
        self._on_threat = on_threat
        self._max_chunks = max_chunks
        self.last_report: RAGScanReport | None = None

    def run(self, *args: Any, **kwargs: Any) -> Any:
        output = self._retriever.run(*args, **kwargs)
        if not isinstance(output, dict) or not isinstance(output.get("documents"), list):
            # Non-standard retriever output: nothing we can safely filter.
            return output
        documents = list(output["documents"])
        report = RAGScanReport()
        kept: list[Any] = []
        for document in documents[: self._max_chunks]:
            text = _chunk_text(document)
            if not text.strip():
                report.dropped += 1
                continue
            result = self._shield.scan_input(text, identity=self._identity)
            report.results.append(result)
            if result.blocked:
                if self._on_threat == "raise":
                    raise ThreatBlockedError(result)
                if self._on_threat == "drop":
                    report.dropped += 1
                    continue
            kept.append(document)
            report.safe_chunks.append(result.safe_text)
        report.dropped += max(0, len(documents) - self._max_chunks)
        self.last_report = report
        return {**output, "documents": kept}

    def __getattr__(self, item: str) -> Any:
        return getattr(self._retriever, item)
