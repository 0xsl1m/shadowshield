"""Streaming guardrails — run me: ``python examples/streaming_scan.py``.

Demonstrates StreamScanner: scan an LLM completion *while it streams* and cut
it mid-flight the moment a terminal verdict (BLOCK/ESCALATE) arrives, instead
of buffering the whole response.
"""

from __future__ import annotations

import shadowshield as ss


def fake_token_stream(text: str, size: int = 12) -> list[str]:
    return [text[i : i + size] for i in range(0, len(text), size)]


def main() -> None:
    shield = ss.Shield.for_mode("balanced")

    print("=== 1. Clean stream passes through ===")
    scanner = shield.stream_scanner(scan_interval_chars=64)
    for chunk in fake_token_stream("Here is a step-by-step focaccia recipe. " * 4):
        terminal = scanner.feed(chunk)
        if terminal is not None:  # pragma: no cover - clean stream
            print("  cut early:", terminal.decision.value)
            break
    print("  final verdict:", scanner.finalize().decision.value)

    print("\n=== 2. Secret leak cut mid-flight ===")
    leaked = "Sure, here you go: the key is sk-" + "A" * 40 + " — and lots more after it."
    scanner = shield.stream_scanner(scan_interval_chars=64)
    emitted = 0
    for chunk in fake_token_stream(leaked):
        terminal = scanner.feed(chunk)
        if terminal is not None:
            print(f"  CUT after {emitted} chars: {terminal.decision.value} "
                  f"(score={terminal.score:.2f})")
            break
        emitted += len(chunk)
    print(f"  withheld {len(leaked) - emitted} chars that a buffered scan "
          "would have emitted first")

    print("\n=== 3. Use it with any streaming SDK ===")
    print("  for event in openai_stream:                  # pseudo-code")
    print("      terminal = scanner.feed(event.delta_text)")
    print("      if terminal: break  # close the stream")


if __name__ == "__main__":
    main()
