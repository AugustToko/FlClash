# Experimental local HTTPS relay core

This package is an explicit, authenticated, loopback-only CONNECT TLS relay. It is the next backend stage after the local in-memory handshake self-test. It is not enabled by preparing a CA, opening the safety page, restoring preferences, restarting Core, or starting passive HTTP Capture.

## Implemented boundary

- Bind only `127.0.0.1`, with an ephemeral port and a per-run 256-bit random Basic password.
- Require exactly one matching Host and proxy-authentication header, a bodyless HTTP/1.1 CONNECT, an ASCII DNS authority, and destination port 443. The parent Core also validates the registrable-domain boundary and current allowlist/exclusions.
- Authenticate and authorize before dialing. Upstream uses normal TLS verification and the exact target ServerName; the inspection CA is NOT installed into the upstream trust pool.
- Upstream TLS must verify before CONNECT succeeds and before any client application bytes can reach the origin.
- Downstream SNI must match CONNECT; TLS 1.2 or newer and HTTP/1.1 only. No certificate-pinning bypass or plaintext fallback.
- Relay bytes without retaining headers, URLs, cookies or bodies. Public runtime status contains aggregate counters only. Byte counters describe relayed plaintext bytes, not network-interface totals or a browser waterfall.
- Limit accepted clients, including unauthenticated clients, to 16. CONNECT headers are bounded to 8 KiB; header/handshake deadlines are five seconds; connections have a 120-second absolute lifetime; a runtime expires after ten minutes.
- Stop closes the listener and cancels accepted clients. The package provides a joinable wait for its client workers.

## Parent Core integration

`core/tls_inspection_runtime.go` binds the runtime to the current authority generation, exact fingerprint, policy digest and unique requested runtime identity. A scope-specific stop records bounded cancellation tombstones so stop-before-start cannot resurrect a delayed start. An old identity cannot stop a newer runtime.

The Core keeps leaf certificates and private keys in its existing validated cache. Keys never cross the runtime IPC. Only the start result returns the temporary proxy credential; status results do not contain it.

The production upstream adapter submits an INNER TCP connection through the Mihomo Tunnel rather than directly dialing the Internet. Consequently normal tunnel rules and socket protection remain on the data path. This explicit internal connection does not preserve the original external client's application UID/process identity; it is not transparent TUN/mixed-port interception. A separate bounded set of 16 routed workers covers outstanding tunnel dials across runtime restarts. Mihomo owns completion of an already-in-flight routed dial; runtime Stop does not claim to synchronously join Mihomo's internal workers.

CA rotation/deletion, leaf-policy reset, Core init/shutdown and stopping listeners revoke the runtime. Windows remains unavailable while the existing CA/private-key DACL contract is unavailable.

## Verification

The package tests use a loopback TLS origin, an independent origin CA and a separate inspection CA. They verify actual HTTPS request/response transfer through two TLS sessions, both downstream TLS 1.2 and TLS 1.3, authentication before dial, excluded/invalid targets, upstream trust/hostname rejection before HTTP payload release, client SNI/ALPN rejection, bounded idle clients and cancellation.

Injected private roots and a local dial callback are test seams in the Go package; neither is accepted over production Core IPC.

## Remaining release work

This backend is intentionally kept in a draft stage until the following are complete:

- App start/stop controls, explicit interception consent and temporary credential presentation.
- Provider lifecycle ownership, failed-stop feedback, no auto-start, platform trust loss and resume tests.
- Full production routed-dial integration tests with isolated Mihomo profiles, including reject/route changes and original-process metadata limitations.
- Integration into HTTP Capture with an explicit inspected-versus-passive discriminator and honest metadata boundaries.
- Full Flutter, coverage and relevant native platform gates for the combined branch.
- Device validation. No local test installs a system trust root, changes the system proxy or intercepts the user's traffic.

HTTP/2, HTTP/3, request/response body capture, Rewrite, Map Local and request/response scripts remain separate later stages.
