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
6. The Python-only `reject_incomplete_extraction=True` option requires the
   bidirectional non-stream option and rejects guarded JSON requests and
   successful responses whose extraction records opaque, media, referenced,
   malformed, unknown or over-budget content. It returns a fixed 503 rather
   than presenting an uninspectable fragment as a malicious finding. It is off
   by default and does not change shadow forwarding. This can reject legitimate
   image/file inputs, retained context, and opaque thinking signatures. It does
   not inspect those contents, guarantee schema completeness, establish detector
   quality or make this policy ready for enforcement. Decoded-segment and finding
   truncation are reported as incomplete; when this option is active they also
   produce a 503 in enforcing mode. Unknown unrecognized fields and upstream
   protocol changes can still escape extraction; no complete schema coverage is
   claimed. This experimental code is not exposed as a CLI flag or deployed.
7. The separate `strict_minimal_text_chat=True` experimental option admits
   only POST Chat Completions without query strings and a minimal body with
   `model`, `messages` and optional `stream: false`; duplicate JSON keys are
   rejected to avoid parser ambiguity. Each message must contain
   only `role` and string `content`. It denies all other protocols, tools,
   format schemas, options, attachments and unknown fields. It requires
   incomplete-extraction rejection, bounded successful responses, upstream-error
   withholding and refuses the unscanned metadata bypass.
   All message content is scanned regardless of caller-supplied role; roles do
   not convey trust. Successful responses must be a minimal synthetic shape:
   an object containing only `choices`, each with only a `message` containing
   only assistant `role` and string `content`. Response duplicate keys, normal
   provider metadata, usage, refusals, and tool calls are rejected. Shadow
   forwarding is unchanged. This is deliberately incompatible with ordinary
   provider responses. It does not establish full coverage, qualify the
   detector or prove client compatibility. If the engine requests sanitization
   or returns modified text, the proxy rejects instead of forwarding the
   original or attempting an unvalidated structured rewrite. This can increase
   benign disruption; evaluations must count these rejections.

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
