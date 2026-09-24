# ShadowShield 0.10.1

ShadowShield 0.10.1 extends native gateway inspection for Anthropic Messages
and OpenAI Responses while retaining Chat Completions and legacy Completions
coverage. Supported request text, non-streaming response text, structured tool
content, and SSE events now use protocol-aware extraction and native policy
failures.

Enforcing modes fail closed when supported content cannot be inspected within
the bounded extraction, response-body, or SSE-event limits. Shadow mode keeps
its observation contract and preserves original request bodies and stream bytes.
Coverage receipts contain fixed metadata and counters without traffic content.

The release also adds an offline qualification runner with network denial and
source hashing. Stored-response retrieval, WebSocket transport, provider-retained
context, and opaque or media content remain outside the qualified inspection
boundary. This source release does not change any gateway mode, credential,
route, deployment, or running service.
