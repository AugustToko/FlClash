# Authenticated loopback HTTPS relay core

This package is an explicit, authenticated, loopback-only CONNECT TLS relay. It is the next backend stage after the local in-memory handshake self-test. It is not enabled by preparing a CA, opening the safety page, restoring preferences, restarting Core, or starting passive HTTP Capture.

## Implemented boundary

- Bind only `127.0.0.1`, with an ephemeral port and a per-run 256-bit random Basic password.
- Require exactly one matching Host and proxy-authentication header, a bodyless HTTP/1.1 CONNECT, an ASCII DNS authority, and destination port 443. The parent Core also validates the registrable-domain boundary and current allowlist/exclusions.
- Authenticate and authorize before dialing. Upstream uses normal TLS verification and the exact target ServerName; the inspection CA is NOT installed into the upstream trust pool.
- Upstream TLS must verify before CONNECT succeeds and before any client application bytes can reach the origin.
- Downstream SNI must match CONNECT; TLS 1.2 or newer and HTTP/1.1 only. No certificate-pinning bypass or plaintext fallback.
- Relay application bytes byte-for-byte unchanged. When HTTP Capture is active, independent request/response observers may publish an ordered timeline of at most 32 decrypted HTTP/1 transactions. Each current header is bounded to 32 KiB; only request method, query-free path, normalized Host and header names, bounded informational statuses, and the final response status/version/header names are retained. Content-Length and Transfer-Encoding values are read transiently only to skip fixed or chunked bodies. Header and framing values, cookies, reason phrases, bodies, raw bytes and transactions beyond the cap are never retained. Public runtime status still contains aggregate counters only; byte counters describe relayed plaintext bytes, not network-interface totals or a browser waterfall.
- Limit accepted clients, including unauthenticated clients, to 16. CONNECT headers are bounded to 8 KiB; header/handshake deadlines are five seconds; connections have a 120-second absolute lifetime; a runtime expires after ten minutes.
- Stop closes the listener and cancels accepted clients. The package provides a joinable wait for its client workers.

## Parent Core integration

`core/tls_inspection_runtime.go` binds the runtime to the current authority generation, exact fingerprint, policy digest and unique requested runtime identity. A scope-specific stop records bounded cancellation tombstones so stop-before-start cannot resurrect a delayed start. An old identity cannot stop a newer runtime.

The Core keeps leaf certificates and private keys in its existing validated cache. Keys never cross the runtime IPC. Only the start result returns the temporary proxy credential; status results do not contain it.

The production upstream adapter submits an INNER TCP connection through the Mihomo Tunnel rather than directly dialing the Internet. Consequently normal tunnel rules and socket protection remain on the data path. This explicit internal connection does not preserve the original external client's application UID/process identity; it is not transparent TUN/mixed-port interception. A separate bounded set of 16 routed workers covers outstanding tunnel dials across runtime restarts. Mihomo owns completion of an already-in-flight routed dial; runtime Stop does not claim to synchronously join Mihomo's internal workers.

CA rotation/deletion, leaf-policy reset, Core init/shutdown and stopping listeners revoke the runtime. Windows remains unavailable while the existing CA/private-key DACL contract is unavailable.

## App ownership and observability

The HTTPS inspection safety workspace owns explicit start, stop, refresh and temporary credential presentation. A runtime is never restored or auto-started from persisted policy. The App keeps the password in memory only, hides it by default, clears copied settings after a bounded interval when the clipboard still contains the same value, and reports an unconfirmed stop without discarding the runtime identity needed for recovery.

When HTTP Capture is active, Core emits immutable inspected-runtime metadata updates for the same runtime/connection identity. Capture may enrich that row with a bounded, sequence-numbered HTTP/1 transaction timeline alongside TLS versions, ALPN, lifecycle state and aggregate byte counts. The timeline supports sequential and pipelined requests, fixed/chunked framing, informational responses, bodyless statuses and terminal upgrade/tunnel/close-delimited semantics. Ambiguous framing fails the observer closed without changing relay traffic. It never retains CONNECT authorization, header or framing values, cookies, bodies or raw payloads. Passive observations, inspected-runtime metadata and connection candidates remain explicitly distinguishable in the UI and export format.

## Verification

The package tests use a loopback TLS origin, an independent origin CA and a separate inspection CA. They verify actual HTTPS request/response transfer through two TLS sessions, both downstream TLS 1.2 and TLS 1.3, authentication before dial, excluded/invalid targets, upstream trust/hostname rejection before HTTP payload release, client SNI/ALPN rejection, bounded idle clients and cancellation. Metadata tests cover arbitrary read boundaries, query/fragment removal, bounded 1xx handling, 101, 32 KiB truncation, malformed streams, callback panics, update ordering and secret scans while asserting relayed bytes remain unchanged.

Parent-Core tests additionally run the production Mihomo Tunnel handler with live rules and test proxies. They prove that an active route change takes effect for the next runtime connection, a `REJECT` rule blocks the route, and INNER runtime traffic does not invent an external application's UID, process or source address.

Provider, model and widget tests cover explicit confirmation, secure identity failure, start/stop races, unconfirmed-stop recovery, Core and authorization loss, no auto-start, credential redaction and clipboard cleanup, Capture terminal-state merging, source filtering and responsive previews.

Injected private roots and a local dial callback are test seams in the Go package; neither is accepted over production Core IPC.

## Remaining scope

This relay is an explicit per-session local proxy. It does not change the system proxy, transparently redirect TUN/mixed-port traffic, preserve the original application's process identity, bypass certificate pinning or claim that every Android application trusts the user CA. Device validation must therefore separately cover platform CA installation and an opted-in test client.

Header values, bodies, transactions beyond the bounded timeline, HTTP/2, HTTP/3, Rewrite, Map Local and request/response scripts remain separate later stages.
