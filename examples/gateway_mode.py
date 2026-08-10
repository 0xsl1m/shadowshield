"""Gateway mode & ASGI embedding — run me: ``python examples/gateway_mode.py``.

Two ways to guard OpenAI-compatible traffic without touching application code:

1. The standalone reverse proxy (recommended for SSE — it cuts malicious
   streams mid-flight): ``shadowshield proxy --upstream ...``
2. ShieldASGIMiddleware embedded in any ASGI app (shown here in-process).
"""

from __future__ import annotations

import shadowshield as ss


def main() -> None:
    print("=== 1. Standalone reverse proxy ===")
    print("  pip install shadowshield[dashboard]")
    print("  shadowshield proxy --upstream https://api.openai.com \\")
    print("      --port 8100 --api-key $GATEWAY_KEY")
    print("  # then point any OpenAI SDK at http://localhost:8100/v1 —")
    print("  # requests are scanned pre-flight, completions (incl. SSE streams)")
    print("  # post-flight, and upstream credentials stay in Authorization.")

    print("\n=== 2. Embedded ASGI middleware (in-process) ===")
    from shadowshield.middleware import ShieldASGIMiddleware

    async def app(scope, receive, send):  # any ASGI app
        body = b'{"choices": [{"message": {"role": "assistant", "content": "hi"}}]}'
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": body})

    shield = ss.Shield.for_mode("balanced")
    guarded = ShieldASGIMiddleware(app, shield)
    print(f"  wrapped app: {guarded!r}")
    print("  JSON chat traffic on /v1/chat/completions is now scanned in both")
    print("  directions; SSE passes through (use the proxy for mid-stream cuts).")


if __name__ == "__main__":
    main()
