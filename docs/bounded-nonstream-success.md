# Experimental bounded non-stream success responses

Existing non-stream success handling reads the full upstream response into
memory before applying its one-mebibyte inspection limit. It also forwards
many upstream headers without scanning their values.

The Python-only, default-off `bound_nonstream_success_response=True` option
changes supported guarded non-stream requests in non-shadow modes. It requires
response scanning, requests identity encoding, rejects compressed responses,
redirects, status 206 and any `Content-Range`, and aggregates at most one
mebibyte of raw response bytes before the existing protocol-aware scanning.
It discards upstream response headers and supplies a fixed JSON content type.
When a response exceeds the cap, is incomplete, or cannot be read, it returns
a fixed error without exposing partial bytes or exception text. Existing
coverage receipts remain authoritative; bounded bytes do not imply complete
extraction or an accurate policy.

This option is experimental, off by default, and unavailable through the CLI.
Shadow mode and the default path retain their existing byte and header behavior.
It can disrupt applications that need compression, redirects, range responses,
upstream metadata, or a pre-buffered custom transport. Omitting provider headers
can also affect client features. A deliberately pre-buffered transport fails
closed because HTTPX raw streaming has already been consumed.

The cap applies to the response bytes aggregated by this code, not all memory:
HTTPX/httpcore, a custom transport, the operating system, or a single received
chunk may allocate or prefetch additional data. A one-mebibyte result can be
copied during scanning. The option does not impose a total elapsed deadline or
a global concurrency limit, so slow streams or many concurrent requests may
still exhaust resources. It does not cover streaming requests or the explicit
unscanned model metadata passthrough. Upstream 4xx/5xx error bodies still use
existing unbounded behavior unless the separate error-withholding option is
also enabled. It does not establish complete protocol coverage, safe blocking,
trusted source attribution, or enforcement readiness.
