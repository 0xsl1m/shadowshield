# Experimental guarded and shadow-observation candidate

This is a provider-free source candidate, **not a production profile or an
endorsement of blocking**. The existing balanced policy has not met its
qualification criteria. No gateway setting or runtime is changed by this file.

The combined source changes have independent controls:

1. Enforcing modes reject unmatched HTTP paths by default. The optional
   model-list compatibility lane remains unscanned and is off by default.
   Shadow mode still forwards unmatched traffic without inspection.
2. The Python-only `require_nonstream_bidirectional=True` option requires both
   scan directions and rejects streaming requests on guarded routes before
   upstream forwarding. It is off by default and loses streaming support.
3. The Python-only `suppress_nonstream_upstream_error_details=True` option
   replaces 4xx/5xx response bodies and headers with a fixed error for guarded,
   non-streaming requests in enforcing modes. It preserves the upstream status
   but may remove provider diagnostics and retry hints. It is off by default.
4. The Python-only `bound_nonstream_success_response=True` option bounds raw
   successful response aggregation and strips upstream headers on guarded,
   non-streaming enforcing paths. It requests identity encoding and rejects
   compressed or partial responses. It is off by default and cannot bound bytes
   allocated by the transport before a chunk reaches the application.
5. The Python-only `experimental_shadow_segments=True` option runs extra
   bounded observations on long JSON text units in shadow mode only. It does
   not enable enforcement or alter existing coverage receipts, which can remain
   partial. It is off by default and rejects non-shadow mode.

Integration tests set the three enforcing options together with unscanned
metadata disabled, and separately test all flags in shadow mode with long JSON.
Tests use synthetic credentials and in-memory HTTPX transports; they cover
key handling, unmatched-route and stream rejection, malicious input and output
examples, error withholding, bounded success and byte-preserving observations.
The assertions apply only to those fixtures; they do not validate a real
client, provider or policy.

Outstanding limitations include false positives and missed attacks, opaque or
referenced provider content, extraction gaps and long inputs, upstream transport
failures, WebSockets, pre-application buffering, and the absence of a trusted
provenance boundary. The optional controls can be left off; an explicitly
allowed model-metadata lane is uninspected. These facts must remain visible in
any later release or pilot plan. No Anthropic diagnostics, provider requests,
or live gateway changes were used.
