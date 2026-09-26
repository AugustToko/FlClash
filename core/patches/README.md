# FlClash Core patches

These patches are applied to the pinned `core/Clash.Meta` submodule in lexical
order. Keeping the delta in the parent repository avoids a submodule pointer to
an inaccessible commit while preserving the upstream Mihomo history.

- Real Flutter builds apply the set through `setup_hooks` before calculating the
  Go build fingerprint.
- `make submodules` and the Go CI job call `tool/apply_core_patches.sh`.
- Application is idempotent: an already-applied patch must pass a reverse
  `git apply --check`; an ambiguous or conflicting tree fails closed.

The current `0001-passive-http-observer.patch` contains the complete bounded
request, TLS ClientHello, and first cleartext HTTP/1 response observer. The
previous request-only form is retained under `migrations/` so a dirty source
tree from an earlier FlClash build can be upgraded transactionally instead of
requiring a manual submodule reset.

All observer stages are opt-in and bounded. They never retain header values,
reason phrases, bodies, certificates, or decrypted TLS application data.
