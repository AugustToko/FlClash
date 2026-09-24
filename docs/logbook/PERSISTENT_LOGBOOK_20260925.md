# Persistent Logbook foundation

## Scope

This change adds an append-only diagnostic event store shared by core logs,
requests, profile and core lifecycle changes, connectivity changes, provider
updates, Geo resource updates, and quick-routing verification.

The first release deliberately does **not** store HTTP request or response
bodies. It establishes the event/session/correlation model needed by future
HTTP capture, runtime scripts, modules, remote dashboards, and CLI tooling.

## Storage and privacy

- Diagnostics are stored in a dedicated `logbook.sqlite` database.
- The configuration database remains unchanged.
- Existing local and WebDAV configuration backups continue to package
  `database.sqlite`; the Logbook is not silently included.
- Default retention is seven days with a hard ceiling of 50,000 events.
- Users can clear the current Profile or all Logbook data from the UI.
- SQLite secure-delete mode is enabled. Profile YAML, subscription credentials,
  and HTTP bodies are not copied into the event model; Core log text can still
  contain operational details and is retained under the same policy.

## Write path

The recorder is non-blocking for Core event handlers:

- 250 ms batch window;
- batches of up to 64 events;
- bounded 2,048-event memory queue;
- an explicit backpressure event when old queued records must be dropped;
- five-second retry after a database write failure;
- automatic pruning every 512 inserts or 30 minutes.

SQLite uses a separate background connection with WAL, `synchronous=NORMAL`,
foreign keys, secure deletion, and a five-second busy timeout, so diagnostic
I/O cannot hold the configuration database writer. Active sessions survive a
manual clear and sessions left open by a crash are closed on the next launch.

## Query surface

The Advanced Configuration page exposes a Logbook view with:

- current-Profile or all-Profile scope;
- event-kind and severity filters;
- multi-term full-text-like search across the normalized event payload;
- 100-row pagination;
- event details with the raw structured JSON payload;
- manual refresh, prune, and clear actions.

## Event sources

The existing `CoreManager` remains the only Core event listener. Logbook writes
are attached beside the existing UI state updates so each event is parsed once
and ordering is preserved. `ConnectivityManager` contributes transport and
SSID transitions. Quick-routing verification history is copied into the same
persistent event stream with its original Profile and request correlation ID.
