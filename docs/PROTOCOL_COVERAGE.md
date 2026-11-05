# Gateway protocol coverage

This source candidate inspects the existing POST `/v1/messages` and
`/v1/responses` routes and their trailing-slash aliases, alongside Chat
Completions and legacy Completions. It changes source inspection only. It does
not activate a gateway, change a provider route, select an enforcement mode,
load credentials, or qualify live traffic.

## Text inspection

Claude Messages carries input in `system` and `messages[].content`, and output
in `content[]`. Text, visible thinking, tool inputs, nested tool results, and
supported server-tool result text need inspection. An SSE response can carry
content in start snapshots, deltas, and terminal snapshots; inspecting only
`choices[].delta.content` misses these formats.

OpenAI Responses carries input in `instructions` and `input`, and generated
items in `output`. Message text, refusals, visible reasoning, function/custom
tool arguments and supported tool outputs need inspection. SSE item/part
snapshots and terminal responses must be inspected even when a prior delta
used the same item ID. An item ID is not evidence that its final content was
already scanned.

The synthetic fixtures follow the provider schemas in the official
[Claude Messages reference](https://platform.claude.com/docs/en/api/messages/create),
[Claude streaming guide](https://platform.claude.com/docs/en/build-with-claude/streaming),
[OpenAI streaming guide](https://developers.openai.com/api/docs/guides/streaming-responses),
and [OpenAI function-calling guide](https://developers.openai.com/api/docs/guides/function-calling).

## Coverage receipts

The proxy emits the structlog event `shadowshield.proxy.coverage` with schema
`shadowshield.proxy.coverage.v1`. Receipt values are enums, counts and booleans.
They contain no request or response content, exception messages, model names,
caller or item IDs, paths, URLs, credentials, or hashes of traffic content.
The configured logging sink determines whether events are retained.

| Field | Meaning |
| --- | --- |
| `protocol` | `chat`, `anthropic`, or `responses` |
| `phase` | `request` or `response` |
| `transport` | `json` or `sse` |
| `status` | `full`, `partial`, `unscanned`, or `failed` |
| `reason` | Fixed classification of a complete scan or a coverage gap |
| `text_units_discovered`, `text_units_scanned` | Extracted units and successful scanner submissions |
| `opaque_units`, `media_units`, `reference_units` | Content that cannot be inspected as inline text |
| `malformed_units`, `scanner_errors` | Parsing and scanner gaps |
| `budget_exceeded` | Inspection stopped at a configured bound |
| `terminal_seen` | The streaming protocol's terminal event was observed |

`full` describes inspection coverage within the supported text schema. It
does not mean benign content, guaranteed attack detection, complete media
inspection, or authorization to enforce. Opaque signatures/encrypted content,
images/audio/files, references to provider-retained context, unsupported
formats, parser failures, truncation and scanner errors must not be reported
as a fully scanned clean result. A `partial` receipt remains a coverage gap
even if the text that was inspected received an ALLOW decision.

Enforcing source modes reject malformed or unsupported text-bearing schemas
and inspection-budget overflows with a native policy/unavailable error.
Known opaque/media/reference fields are counted as gaps and are not fetched
or decoded by the proxy. This does not change the selected mode or policy
preset of any running process.

SSE text is inspected with bounded state. This remains incremental scanning,
so already-forwarded bytes cannot be recalled if a later fragment triggers a
detector. Shadow mode preserves the original request/response body and SSE
framing even on detections, parser failures, size limits and scanner failures.
Existing HTTP authentication and body-admission limits still apply.

Enforcing modes reject unsupported HTTP routes with
`shadowshield_unsupported_route` before forwarding. This includes stored
Responses retrieval, embeddings and file operations; integrations that need
those routes require explicit protocol support before enforcing can be used.
Shadow mode continues to forward unsupported routes without inspection.
Neither proxy health counters nor successful forwarding prove inspection.

Applications constructing the proxy in Python may explicitly set
`allow_unscanned_model_metadata=True` to allow only bodyless GET or HEAD of
`/v1/models` (with an optional trailing slash) in enforcing modes. This narrow
compatibility lane trusts the configured upstream's endpoint semantics and
does not scan its query or response. It is off by default, is not exposed as a
CLI option, and is not a general bypass or a coverage guarantee.

Disabling `scan_request` or `scan_response` in an enforcing proxy skips that
direction entirely; explicit existing callers retain this behavior. A fixed,
content-free startup warning is attempted whenever a direction is disabled;
if the configured log sink fails, forwarding behavior is unchanged. The CLI's
`--no-scan-response` also opts out of response inspection. Such a proxy must not be represented as providing
bidirectional scanning merely because its mode is enforcing.

Python callers may opt into `require_nonstream_bidirectional=True` to require
both scan directions and reject streaming requests on supported guarded routes
before they reach the upstream in enforcing modes. It is off by default and does not change shadow
forwarding. This prevents the known incremental SSE disclosure window for
requests sent through supported guarded routes, at the cost of streaming. It
is not a complete-inspection guarantee: opaque or retained provider content,
unsupported paths, upstream error bodies, scanner quality, and the existing
non-streaming response buffering behavior remain separate limitations. This
option is not exposed in the CLI and has not been qualified for production.

WebSocket transport, provider-retained context, and opaque/media semantics
remain outside source qualification. No provider requests or live-session
evidence are used.

## Reproduce the qualification

From a checkout of the exact source release, with the project's existing test
dependencies installed:

```text
python scripts/qualify_protocol_source.py --output /new/path/qualification.json --receipts /new/path/coverage.jsonl
```

Both output paths must be new. The runner removes the credential-variable
patterns listed in its receipt from its child environment, disables opt-in
telemetry, denies network clients and DNS, forces imports from this checkout,
and uses only in-memory ASGI and
mock provider transports. It records fixed test names and outcomes plus hashes
of source files; it does not persist pytest assertion output or application
logs. Source hashes are checked before and after the run.

On Windows, the async scheduler needs connected socket pairs. The runner
allows only its own ephemeral loopback listener for those pairs, verifies
both peer endpoints, and counts pairs separately. Ordinary loopback clients,
remote connections and DNS remain denied. This test guard is not a sandbox
for executing untrusted Python code.

The source release's manifest binds the immutable Git commit, archive digest,
per-file inventory, qualification, coverage receipts and review record. Local
source qualification is separate from CI image provenance, signing, registry
publication and production deployment. The release grants none of those
actions. Rollback of this source work is to retain the prior candidate commit;
no live rollback is needed because no live state is changed.
