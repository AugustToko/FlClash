# Authenticated loopback HTTPS relay core

This package is an explicit, authenticated, loopback-only CONNECT TLS relay. It is the next backend stage after the local in-memory handshake self-test. It is not enabled by preparing a CA, opening the safety page, restoring preferences, restarting Core, or starting passive HTTP Capture.

## Implemented boundary

- Bind only `127.0.0.1`, with an ephemeral port and a per-run 256-bit random Basic password.
- Require exactly one matching Host and proxy-authentication header, a bodyless HTTP/1.1 CONNECT, an ASCII DNS authority, and destination port 443. The parent Core also validates the registrable-domain boundary and current allowlist/exclusions.
- Authenticate and authorize before dialing. Upstream uses normal TLS verification and the exact target ServerName; the inspection CA is NOT installed into the upstream trust pool.
- Upstream TLS must verify before CONNECT succeeds and before any client application bytes can reach the origin.
- Downstream SNI must match CONNECT. TLS 1.2 or newer is required, and downstream ALPN is constrained to the already verified upstream protocol: HTTP/1.1 or HTTP/2. There is no certificate-pinning bypass, protocol downgrade, or plaintext fallback.
- Relay application bytes byte-for-byte unchanged. When HTTP Capture is active, independent request/response observers may publish either an ordered timeline of at most 32 decrypted HTTP/1 transactions or a multiplexed timeline of at most 32 client-initiated HTTP/2 streams. HTTP/2 observation validates the client preface, bounded frames, CONTINUATION ordering and HPACK state; it records stream IDs, lifecycle timing, RST_STREAM and GOAWAY without changing relay traffic.
- Capture is metadata-only by default. Header values and bodies require an explicit per-session capture policy. Sensitive values such as Authorization, Cookie, Set-Cookie, tokens, secrets and credentials remain redacted unless separately authorized; callers may add custom header names to the redaction set. Request targets remain query- and fragment-free.
- Body capture has `none`, text-only and all-types modes. Captured data is classified as JSON, form, multipart, image, text or binary; textual values are UTF-8 and binary values are base64. Every body is bounded to 64 KiB, each connection to 256 KiB and each capture session to 8 MiB. Omitted, truncated and exhausted-budget states are explicit. Compressed or unknown binary data is not silently decoded.
- Public runtime status contains aggregate counters and the normalized capture policy. Byte counters describe relayed plaintext bytes, not network-interface totals or a browser waterfall.
- Limit accepted clients, including unauthenticated clients, to 16. CONNECT headers are bounded to 8 KiB; header/handshake deadlines are five seconds; connections have a 120-second absolute lifetime; a runtime expires after ten minutes.
- Stop closes the listener and cancels accepted clients. The package provides a joinable wait for its client workers and clears in-memory capture buffers when a session is stopped or replaced.

## Parent Core integration

`core/tls_inspection_runtime.go` binds the runtime to the current authority generation, exact fingerprint, policy digest and unique requested runtime identity. A scope-specific stop records bounded cancellation tombstones so stop-before-start cannot resurrect a delayed start. An old identity cannot stop a newer runtime.

The Core keeps leaf certificates and private keys in its existing validated cache. Keys never cross the runtime IPC. Only the start result returns the temporary proxy credential; status results do not contain it.

The production upstream adapter submits an INNER TCP connection through the Mihomo Tunnel rather than directly dialing the Internet. Consequently normal tunnel rules and socket protection remain on the data path. This explicit internal connection does not preserve the original external client's application UID/process identity; it is not transparent TUN/mixed-port interception. A separate bounded set of 16 routed workers covers outstanding tunnel dials across runtime restarts. Mihomo owns completion of an already-in-flight routed dial; runtime Stop does not claim to synchronously join Mihomo's internal workers.

CA rotation/deletion, leaf-policy reset, Core init/shutdown and stopping listeners revoke the runtime. Windows remains unavailable while the existing CA/private-key DACL contract is unavailable.

## App ownership and observability

The HTTPS inspection safety workspace owns explicit start, stop, refresh and temporary credential presentation. A runtime is never restored or auto-started from persisted policy. The App keeps the password in memory only, hides it by default, clears copied settings after a bounded interval when the clipboard still contains the same value, and reports an unconfirmed stop without discarding the runtime identity needed for recovery.

HTTP Capture owns the separate content-capture authorization. The policy can be edited only while capture is stopped, is forwarded with the new capture session, and is reset when observation is disabled. The UI explains the metadata-only default before exposing Header values, sensitive values or Body modes.

Core emits immutable inspected-runtime updates for the same runtime/connection identity. HTTP/1 transactions remain sequence-numbered; HTTP/2 streams retain their wire stream IDs and concurrent timing rather than being forced into a linear HTTP/1 model. Details can expand authorized Header values, cookies, JSON, form fields, text and images while retaining redaction and truncation markers. HAR export includes only data authorized and retained by the active policy. Passive observations, inspected-runtime exchanges and connection candidates remain explicitly distinguishable.

## Verification

The package tests use a loopback TLS origin, an independent origin CA and a separate inspection CA. They verify actual HTTPS request/response transfer through two TLS sessions, downstream TLS 1.2 and TLS 1.3, authentication before dial, excluded/invalid targets, upstream trust/hostname rejection before payload release, matching HTTP/1.1 and HTTP/2 ALPN, bounded idle clients and cancellation.

HTTP/1 tests cover arbitrary read boundaries, query/fragment removal, sequential and pipelined transactions, bounded informational responses, fixed/chunked framing, terminal upgrade/tunnel/close-delimited semantics and fail-closed ambiguity. HTTP/2 tests cover concurrent streams, HPACK, out-of-order responses, CONTINUATION violations, bodies, sensitive Header redaction and GOAWAY. Capture-policy tests cover normalization, custom redaction, type-aware omission and per-body/connection/session budgets while secret scans assert that unauthorized values never enter observations.

Parent-Core tests additionally run the production Mihomo Tunnel handler with live rules and test proxies. They prove that an active route change takes effect for the next runtime connection, a `REJECT` rule blocks the route, and INNER runtime traffic does not invent an external application's UID, process or source address.

Provider, model and widget tests cover explicit confirmation, secure identity failure, start/stop races, unconfirmed-stop recovery, Core and authorization loss, no auto-start, credential redaction, capture-policy forwarding and locking, HTTP/2 stream rendering, Header/Cookie/Body previews, HAR export, localization and responsive golden previews.

Injected private roots and a local dial callback are test seams in the Go package; neither is accepted over production Core IPC.

## Remaining scope

This relay is an explicit per-session local proxy. It does not change the system proxy, transparently redirect TUN/mixed-port traffic, preserve the original application's UID/process identity, bypass certificate pinning or claim that every Android application trusts the user CA. Device validation must therefore separately cover platform CA installation and an opted-in test client.

HTTP/3/QUIC inspection, Rewrite, Map Local, Mock Response, request/response scripts, a complete DNS/Connect/TLS/TTFB/Download waterfall, transparent traffic import and original process attribution remain separate later stages.
