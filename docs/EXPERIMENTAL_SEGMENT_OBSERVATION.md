# Experimental long-text shadow observation

This source-only candidate adds an opt-in observation for extracted JSON text
units to `create_proxy_app(..., experimental_shadow_segments=True)`. The option
is off by default, rejects enforcing mode, and is not exposed by the CLI. It
does not affect forwarding decisions, scan results, or existing coverage
receipts. SSE is excluded because repeated streaming snapshots require a
separate aggregate-work budget. No runtime deployment is implied.

The observer uses fresh instances of the supported built-in cheap detectors and
copies their configuration; custom and ML cheap detectors cause an
`unsupported_detector_configuration` result, as does any PII backend other
than regex. It intentionally does not call
gated judges or use request identity, history, canaries, or objective. It has
fixed limits of 16 windows and one million scanned characters, including
overlap, and discards all partial findings on budget, decoding, scan, or
finding limits. It publishes only fixed status and aggregate counts to the
proxy log, never snippets, matches, offsets, identities, or error messages.
The proxy admits at most one observation per request and response combined,
with two global non-queuing daemon workers and a two-second await deadline.
Timed-out or cancelled work holds its worker slot until it actually ends; new
observations are skipped when slots are busy. Skips do not change forwarding.

`observed` means only that those windows were inspected by this limited set of
detectors. Overlap cannot guarantee detection of long or cross-window attacks;
normalization can differ by window and unlocated matches cannot be safely
deduplicated or sanitized. The standard proxy coverage receipt continues to mark
oversized text partial. This observation is not detector/config parity, full
protocol coverage, authenticated provenance, or an enforcing-policy verdict.
The underlying issue of an unqualified policy and unknown protocol shapes is
unchanged. Real traffic, provider calls, and live runtime configuration were
not used to test this candidate.
