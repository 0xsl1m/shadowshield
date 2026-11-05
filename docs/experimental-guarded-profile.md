# Experimental guarded non-stream candidate

This is a provider-free source candidate, **not a production profile or an
endorsement of blocking**. The existing balanced policy has not met its
qualification criteria. No gateway setting or runtime is changed by this file.

The combined source changes have three independent controls:

1. In enforcing modes, reject unmatched HTTP paths by default. The optional
   model-list compatibility lane is unscanned and must remain disabled when
   evaluating the narrow guarded candidate. Shadow mode still passes unmatched
   traffic through without inspection.
2. The Python-only `require_nonstream_bidirectional=True` option requires both
   scan directions and rejects streaming requests on guarded routes before
   upstream forwarding. It is off by default; this loses streaming support.
3. The Python-only `suppress_nonstream_upstream_error_details=True` option
   replaces 4xx/5xx response bodies and headers with a fixed error for guarded,
   non-streaming requests in enforcing modes. It preserves the upstream status
   but can remove provider diagnostics and retry hints. It is off by default.

The integration tests set both Python options and leave the unscanned metadata
option off. They use only synthetic credentials and in-memory HTTPX transports.
Their assertions cover gateway authentication, an unmatched inference path,
stream rejection, malicious request and response examples, error suppression,
and byte-preserving shadow behavior. The assertions establish behavior only
for those fixtures. They do not validate a real client, provider or policy.

Outstanding limitations include false positives and missed attacks, opaque or
referenced provider content, extraction gaps and long inputs, successful-response
headers and memory buffering, upstream transport failures, WebSockets, and the
absence of a trustworthy provenance boundary. A caller can leave the optional
controls off, and an explicitly enabled unscanned metadata lane is still
uninspected. These facts must remain visible in any later release or pilot plan.
No Anthropic diagnostics, provider requests, or live gateway changes were used.
