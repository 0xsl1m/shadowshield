# Optional upstream error withholding

An upstream server can return arbitrary text and headers with a 4xx or 5xx
response. The existing gateway forwards these without scanning them, including
in enforcing modes. A malicious or compromised upstream can therefore expose
untrusted content to a client inside an error response.

An experimental Python-only option,
`suppress_nonstream_upstream_error_details=True`, causes supported guarded
**non-streaming** requests in non-shadow modes to return the original error
status and a fixed, protocol-shaped JSON error, without forwarding upstream
error headers. The gateway closes the upstream response without explicitly
consuming or aggregating its body. HTTPX, httpcore or the operating system may
still prefetch bytes while receiving headers. This reduces exposure to error
bodies; it does not establish that an upstream was safe or that the response was
scanned. Error receipts continue to report `unscanned / upstream_error`.

It defaults to false for compatibility, is not available through the CLI, and
has no effect in shadow mode: existing response bytes and headers are forwarded.
Withholding removes provider error messages and headers, including potential
retry information, and may disrupt client diagnostics or retry behavior.

This option does **not** itself protect requests sent with `stream: true`, the
explicitly permitted unscanned model-metadata route, upstream response headers
before a successful status, or provider data in successful responses. In this
candidate, enforcing modes reject unmatched routes by default; the separate
`require_nonstream_bidirectional=True` option also rejects streaming on guarded
routes. Those controls are independent: explicitly enable both non-stream
inspection and error withholding, and keep unscanned metadata opt-in disabled
for the narrow experiment. Existing success handling still buffers the response before its
inspection limit is checked. Upstream request headers, timeouts and transport
failures are governed by existing behavior. Provider-free integration tests
exercise the combined controls; production use and enforcement readiness are
not established.
