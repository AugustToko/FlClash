import 'dart:async';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/database/database.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/app.dart';
import 'package:fl_clash/providers/config.dart';
import 'package:fl_clash/providers/core.dart';
import 'package:fl_clash/providers/logbook.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

bool _hasHttpCaptureServicesBinding() {
  try {
    ServicesBinding.instance;
    return true;
  } on AssertionError {
    return false;
  }
}

final httpCapturePersistenceEnabledProvider = Provider<bool>(
  (_) => _hasHttpCaptureServicesBinding(),
);

final httpCaptureCoreDisableRetryDelayProvider = Provider<Duration>(
  (_) => const Duration(seconds: 1),
);

typedef HttpCaptureCoreControl =
    Future<bool> Function(bool enabled, String sessionId);

final httpCaptureCoreControlProvider = Provider<HttpCaptureCoreControl>((ref) {
  return (enabled, sessionId) async {
    if (ref.read(coreStatusProvider) != CoreStatus.connected) {
      return false;
    }
    return ref
        .read(coreHandlerProvider)
        .setHttpObservationEnabled(
          enabled,
          sessionId: enabled ? sessionId : '',
        );
  };
});

class HttpCaptureState {
  final bool enabled;
  final DateTime? sessionStartedAt;
  final String sessionId;
  final bool coreObserverActive;
  final List<HttpCaptureEntry> entries;
  final int revision;

  const HttpCaptureState({
    this.enabled = false,
    this.sessionStartedAt,
    this.sessionId = '',
    this.coreObserverActive = false,
    this.entries = const [],
    this.revision = 0,
  });

  HttpCaptureState copyWith({
    bool? enabled,
    DateTime? sessionStartedAt,
    bool clearSessionStartedAt = false,
    String? sessionId,
    bool? coreObserverActive,
    List<HttpCaptureEntry>? entries,
    int? revision,
  }) {
    return HttpCaptureState(
      enabled: enabled ?? this.enabled,
      sessionStartedAt: clearSessionStartedAt
          ? null
          : sessionStartedAt ?? this.sessionStartedAt,
      sessionId: sessionId ?? this.sessionId,
      coreObserverActive: coreObserverActive ?? this.coreObserverActive,
      entries: List.unmodifiable(entries ?? this.entries),
      revision: revision ?? this.revision,
    );
  }

  int get sessionEntryCount {
    if (sessionId.isEmpty) {
      return 0;
    }
    return entries.where((entry) => entry.sessionId == sessionId).length;
  }
}

class HttpCaptureNotifier extends Notifier<HttpCaptureState> {
  static const maxEntriesPerScope = 1000;
  static const maxLoadedEntries = 2000;

  Future<void>? _loadOperation;
  Future<void> _writeTail = Future<void>.value();
  Future<void> _coreToggleTail = Future<void>.value();
  final _suppressedIdentities = <String>{};
  final _suppressedConnections = <String>{};
  final _activeConnectionBindings =
      <String, ({int id, int? profileId, DateTime observedAt})>{};
  Timer? _coreDisableRetryTimer;
  DateTime? _lastCoreToggleFailureLogAt;

  @override
  HttpCaptureState build() {
    ref.onDispose(() => _coreDisableRetryTimer?.cancel());
    return const HttpCaptureState();
  }

  String _identity({
    required String scopeKey,
    required String sessionId,
    required String connectionId,
  }) => '$scopeKey\u0000$sessionId\u0000$connectionId';

  String _connectionIdentity({
    required String sessionId,
    required String connectionId,
  }) => '$sessionId\u0000$connectionId';

  String _entryIdentity(HttpCaptureEntry entry) => _identity(
    scopeKey: entry.scopeKey,
    sessionId: entry.sessionId,
    connectionId: entry.connectionId,
  );

  List<HttpCaptureEntry> _bounded(Iterable<HttpCaptureEntry> entries) {
    final values = entries.toList(growable: false)
      ..sort((a, b) {
        final observed = b.observedAt.compareTo(a.observedAt);
        return observed != 0 ? observed : b.id.compareTo(a.id);
      });
    return List.unmodifiable(values.take(maxLoadedEntries));
  }

  HttpCaptureEntry _mergeCanonicalWithMemory(HttpCaptureEntry canonical) {
    HttpCaptureEntry? current;
    for (final entry in state.entries) {
      if (entry.scopeKey == canonical.scopeKey &&
          entry.sessionId == canonical.sessionId &&
          entry.connectionId == canonical.connectionId) {
        current = entry;
        break;
      }
    }
    if (current == null) {
      return canonical;
    }
    final currentResponse = current.httpResponseObservation;
    final canonicalResponse = canonical.httpResponseObservation;
    final currentIsRicher =
        (currentResponse != null && canonicalResponse == null) ||
        current.upload > canonical.upload ||
        current.download > canonical.download;
    return currentIsRicher ? current.copyWith(id: canonical.id) : canonical;
  }

  void _rememberActiveConnection(HttpCaptureEntry entry) {
    if (entry.httpObservation == null ||
        entry.httpResponseObservation != null) {
      _activeConnectionBindings.remove(entry.connectionId);
      return;
    }
    if (!_activeConnectionBindings.containsKey(entry.connectionId) &&
        _activeConnectionBindings.length >= maxLoadedEntries) {
      _activeConnectionBindings.remove(_activeConnectionBindings.keys.first);
    }
    _activeConnectionBindings[entry.connectionId] = (
      id: entry.id,
      profileId: entry.profileId,
      observedAt: entry.observedAt,
    );
  }

  void _upsertMemory(HttpCaptureEntry entry) {
    if (_suppressedIdentities.contains(_entryIdentity(entry))) {
      return;
    }
    final next =
        state.entries
            .where(
              (item) =>
                  item.id != entry.id &&
                  !(item.scopeKey == entry.scopeKey &&
                      item.sessionId == entry.sessionId &&
                      item.connectionId == entry.connectionId),
            )
            .toList(growable: true)
          ..add(entry);
    state = state.copyWith(
      entries: _bounded(next),
      revision: state.revision + 1,
    );
  }

  Future<T> _serialize<T>(Future<T> Function() action) {
    final completer = Completer<T>();
    _writeTail = _writeTail.then((_) async {
      try {
        completer.complete(await action());
      } catch (error, stackTrace) {
        completer.completeError(error, stackTrace);
      }
    });
    return completer.future;
  }

  Future<void> _reconcileInterruptedSessions() async {
    await ref.read(logbookProvider.notifier).reload();
    if (!ref.mounted) {
      return;
    }
    final activeSessionId = state.enabled ? state.sessionId : '';
    final stale = ref
        .read(logbookProvider)
        .where(
          (event) =>
              event.eventType == 'http.capture.session' &&
              event.details['status'] == 'running' &&
              event.correlationId.isNotEmpty &&
              event.correlationId != activeSessionId,
        )
        .toList(growable: false);
    for (final event in stale) {
      final durationMs = DateTime.now()
          .difference(event.createdAt)
          .inMilliseconds;
      await ref
          .read(logbookProvider.notifier)
          .record(
            profileId: event.profileId,
            category: event.category,
            severity: LogbookSeverity.warning,
            eventType: event.eventType,
            title: event.title,
            message: 'capture-interrupted',
            correlationId: event.correlationId,
            details: {
              ...event.details,
              'status': 'interrupted',
              'durationMs': durationMs < 0 ? 0 : durationMs,
            },
          );
    }
  }

  Future<({bool reached, bool active})> _setCoreObservation(
    bool enabled,
    String sessionId,
  ) async {
    try {
      final active = await ref.read(httpCaptureCoreControlProvider)(
        enabled,
        sessionId,
      );
      _lastCoreToggleFailureLogAt = null;
      return (reached: true, active: active);
    } catch (error, stackTrace) {
      final now = DateTime.now();
      final lastLogAt = _lastCoreToggleFailureLogAt;
      if (lastLogAt == null ||
          now.difference(lastLogAt) >= const Duration(seconds: 30)) {
        _lastCoreToggleFailureLogAt = now;
        commonPrint.log(
          'HTTP passive observer toggle failed: ${compactError(error)}, $stackTrace',
          logLevel: LogLevel.warning,
        );
      }
      return (reached: false, active: state.coreObserverActive);
    }
  }

  Future<({bool reached, bool active})> _setCoreObservationSafely(
    bool enabled,
    String sessionId,
  ) async {
    var result = await _setCoreObservation(enabled, sessionId);
    if (enabled) {
      return result;
    }
    for (
      var attempt = 1;
      attempt < 3 && (!result.reached || result.active);
      attempt++
    ) {
      if (!ref.mounted ||
          ref.read(coreStatusProvider) != CoreStatus.connected) {
        return (reached: true, active: false);
      }
      await Future<void>.delayed(const Duration(milliseconds: 50));
      result = await _setCoreObservation(false, '');
    }
    return result;
  }

  void _reconcileCoreDisableRetry() {
    _coreDisableRetryTimer?.cancel();
    _coreDisableRetryTimer = null;
    if (state.enabled ||
        !state.coreObserverActive ||
        ref.read(coreStatusProvider) != CoreStatus.connected) {
      return;
    }
    _coreDisableRetryTimer = Timer(
      ref.read(httpCaptureCoreDisableRetryDelayProvider),
      () {
        _coreDisableRetryTimer = null;
        unawaited(syncCoreObservation());
      },
    );
  }

  Future<void> syncCoreObservation() {
    final completer = Completer<void>();
    _coreToggleTail = _coreToggleTail
        .then((_) async {
          try {
            if (!ref.mounted) {
              return;
            }
            final sessionId = state.sessionId;
            final desired =
                state.enabled &&
                ref.read(coreStatusProvider) == CoreStatus.connected;
            final result = await _setCoreObservationSafely(
              desired,
              desired ? sessionId : '',
            );
            if (!ref.mounted) {
              return;
            }
            final stillDesired =
                state.enabled &&
                state.sessionId == sessionId &&
                ref.read(coreStatusProvider) == CoreStatus.connected;
            final active = desired
                ? stillDesired && result.reached && result.active
                : result.reached
                ? result.active
                // Preserve a previously confirmed active state. If enable
                // never succeeded, a missing/older Core must not be treated as
                // an observer that needs indefinite disable retries.
                : state.coreObserverActive;
            state = state.copyWith(
              coreObserverActive: active,
              revision: state.revision + 1,
            );
            _reconcileCoreDisableRetry();
          } finally {
            if (!completer.isCompleted) {
              completer.complete();
            }
          }
        })
        .catchError((Object error, StackTrace stackTrace) {
          if (!completer.isCompleted) {
            completer.completeError(error, stackTrace);
          }
        });
    return completer.future;
  }

  void markCoreObserverUnavailable() {
    if (!state.coreObserverActive) {
      return;
    }
    state = state.copyWith(
      coreObserverActive: false,
      revision: state.revision + 1,
    );
    _reconcileCoreDisableRetry();
  }

  Future<void> reload() {
    if (!ref.read(httpCapturePersistenceEnabledProvider)) {
      return Future<void>.value();
    }
    final active = _loadOperation;
    if (active != null) {
      return active;
    }
    final operation = () async {
      try {
        final persisted = await _serialize(
          () => database.loadHttpCaptureEntries(limit: maxLoadedEntries),
        );
        if (!ref.mounted) {
          return;
        }
        final byIdentity = <String, HttpCaptureEntry>{
          for (final entry in persisted)
            if (!_suppressedIdentities.contains(_entryIdentity(entry)))
              _entryIdentity(entry): entry,
        };
        for (final entry in state.entries) {
          final key = _entryIdentity(entry);
          final stored = byIdentity[key];
          if (stored == null || entry.observedAt.isAfter(stored.observedAt)) {
            byIdentity[key] = entry;
          }
        }
        state = state.copyWith(
          entries: _bounded(byIdentity.values),
          revision: state.revision + 1,
        );
        await _reconcileInterruptedSessions();
      } catch (error, stackTrace) {
        commonPrint.log(
          'HTTP capture hydration failed: ${compactError(error)}, $stackTrace',
          logLevel: LogLevel.warning,
        );
      } finally {
        _loadOperation = null;
      }
    }();
    _loadOperation = operation;
    return operation;
  }

  Future<void> start() async {
    if (state.enabled) {
      return;
    }
    final now = DateTime.now();
    final sessionId = 'http-capture:${snowflake.id}';
    _activeConnectionBindings.clear();
    _suppressedConnections.clear();
    state = state.copyWith(
      enabled: true,
      sessionStartedAt: now,
      sessionId: sessionId,
      coreObserverActive: false,
      revision: state.revision + 1,
    );
    final logbookWrite = ref
        .read(logbookProvider.notifier)
        .record(
          category: LogbookCategory.network,
          severity: LogbookSeverity.info,
          eventType: 'http.capture.session',
          title: 'http.capture.session',
          message: 'capture-started',
          correlationId: sessionId,
          details: const {'status': 'running', 'observationOnly': true},
        );
    // Enable the Core observer before waiting for local history persistence so
    // connections created immediately after the user taps Start are eligible.
    await syncCoreObservation();
    await logbookWrite;
  }

  Future<void> stop() async {
    if (!state.enabled) {
      return;
    }
    final startedAt = state.sessionStartedAt;
    final sessionId = state.sessionId;
    final count = state.sessionEntryCount;
    final coreObserverActive = state.coreObserverActive;
    state = state.copyWith(
      enabled: false,
      clearSessionStartedAt: true,
      sessionId: '',
      revision: state.revision + 1,
    );
    await syncCoreObservation();
    if (sessionId.isEmpty) {
      return;
    }
    final durationMs = startedAt == null
        ? 0
        : DateTime.now().difference(startedAt).inMilliseconds;
    await ref
        .read(logbookProvider.notifier)
        .record(
          category: LogbookCategory.network,
          severity: LogbookSeverity.success,
          eventType: 'http.capture.session',
          title: 'http.capture.session',
          message: '$count observations · $durationMs ms',
          correlationId: sessionId,
          details: {
            'status': 'completed',
            'observationOnly': true,
            'coreObserverActive': coreObserverActive,
            'count': count,
            'durationMs': durationMs,
          },
        );
  }

  Future<HttpCaptureEntry?> observe(TrackerInfo tracker) async {
    if (!state.enabled || !shouldCaptureHttpObservation(tracker)) {
      return null;
    }
    final observationSessionId = tracker.observation?.sessionId ?? '';
    if (observationSessionId.isNotEmpty &&
        observationSessionId != state.sessionId) {
      return null;
    }
    if (_suppressedConnections.contains(
      _connectionIdentity(sessionId: state.sessionId, connectionId: tracker.id),
    )) {
      return null;
    }
    HttpCaptureEntry? previous;
    for (final current in state.entries) {
      if (current.sessionId == state.sessionId &&
          current.connectionId == tracker.id) {
        previous = current;
        break;
      }
    }
    final binding = _activeConnectionBindings[tracker.id];
    final profileId = previous != null
        ? previous.profileId
        : binding != null
        ? binding.profileId
        : ref.read(currentProfileIdProvider);
    final id = previous?.id ?? binding?.id ?? snowflake.id;
    final observedAt = previous?.observedAt ?? binding?.observedAt;
    final entry = HttpCaptureEntry.fromTracker(
      id: id,
      tracker: tracker,
      sessionId: state.sessionId,
      profileId: profileId,
      // A response-side Tracker update enriches the original observation; it
      // must not reorder or move the connection into a newly selected Profile.
      observedAt: observedAt,
    );
    if (_suppressedIdentities.contains(_entryIdentity(entry))) {
      return null;
    }
    _rememberActiveConnection(entry);
    _upsertMemory(entry);
    if (!ref.read(httpCapturePersistenceEnabledProvider)) {
      return entry;
    }
    try {
      final canonical = await _serialize(
        () => database.upsertHttpCaptureEntry(
          entry,
          maxEntriesPerScope: maxEntriesPerScope,
        ),
      );
      if (ref.mounted &&
          !_suppressedIdentities.contains(_entryIdentity(canonical))) {
        final resolved = _mergeCanonicalWithMemory(canonical);
        _rememberActiveConnection(resolved);
        _upsertMemory(resolved);
        return resolved;
      }
      return canonical;
    } catch (error, stackTrace) {
      commonPrint.log(
        'HTTP capture persistence failed: ${compactError(error)}, $stackTrace',
        logLevel: LogLevel.warning,
      );
      return entry;
    }
  }

  Future<void> remove(int id) async {
    HttpCaptureEntry? target;
    for (final entry in state.entries) {
      if (entry.id == id) {
        target = entry;
        break;
      }
    }

    final targetIdentity = target == null ? null : _entryIdentity(target);
    if (targetIdentity != null) {
      _suppressedIdentities.add(targetIdentity);
      _suppressedConnections.add(
        _connectionIdentity(
          sessionId: target!.sessionId,
          connectionId: target.connectionId,
        ),
      );
      _activeConnectionBindings.remove(target.connectionId);
    }

    bool matchesTarget(HttpCaptureEntry entry) {
      final value = target;
      return entry.id == id ||
          (value != null &&
              entry.scopeKey == value.scopeKey &&
              entry.sessionId == value.sessionId &&
              entry.connectionId == value.connectionId);
    }

    void removeFromMemory() {
      state = state.copyWith(
        entries: state.entries.where((entry) => !matchesTarget(entry)).toList(),
        revision: state.revision + 1,
      );
    }

    removeFromMemory();
    if (!ref.read(httpCapturePersistenceEnabledProvider)) {
      return;
    }
    try {
      final value = target;
      await _serialize(
        () => value == null
            ? database.deleteHttpCaptureEntry(id)
            : database.deleteHttpCaptureEntryByIdentity(
                scopeKey: value.scopeKey,
                sessionId: value.sessionId,
                connectionId: value.connectionId,
              ),
      );
      if (ref.mounted) {
        removeFromMemory();
      }
    } catch (error, stackTrace) {
      commonPrint.log(
        'HTTP capture delete failed: ${compactError(error)}, $stackTrace',
        logLevel: LogLevel.warning,
      );
    }
  }

  Future<void> clear({int? profileId, bool includeGlobal = false}) async {
    bool shouldRemove(HttpCaptureEntry entry) {
      if (profileId == null) {
        return true;
      }
      if (entry.profileId == profileId) {
        return true;
      }
      return includeGlobal && entry.profileId == null;
    }

    for (final entry in state.entries.where(shouldRemove)) {
      _suppressedIdentities.add(_entryIdentity(entry));
      _suppressedConnections.add(
        _connectionIdentity(
          sessionId: entry.sessionId,
          connectionId: entry.connectionId,
        ),
      );
    }
    final pendingToRemove = _activeConnectionBindings.entries
        .where((item) {
          final bindingProfileId = item.value.profileId;
          if (profileId == null) {
            return true;
          }
          if (bindingProfileId == profileId) {
            return true;
          }
          return includeGlobal && bindingProfileId == null;
        })
        .map((item) => item.key)
        .toList(growable: false);
    for (final connectionId in pendingToRemove) {
      final binding = _activeConnectionBindings.remove(connectionId)!;
      final scopeKey = binding.profileId == null
          ? 'global'
          : 'profile:${binding.profileId}';
      _suppressedIdentities.add(
        _identity(
          scopeKey: scopeKey,
          sessionId: state.sessionId,
          connectionId: connectionId,
        ),
      );
      _suppressedConnections.add(
        _connectionIdentity(
          sessionId: state.sessionId,
          connectionId: connectionId,
        ),
      );
    }

    void clearFromMemory() {
      state = state.copyWith(
        entries: state.entries.where((entry) => !shouldRemove(entry)).toList(),
        revision: state.revision + 1,
      );
    }

    clearFromMemory();
    if (!ref.read(httpCapturePersistenceEnabledProvider)) {
      return;
    }
    try {
      await _serialize(
        () => database.clearHttpCaptureEntries(
          profileId: profileId,
          includeGlobal: includeGlobal,
        ),
      );
      if (ref.mounted) {
        clearFromMemory();
      }
    } catch (error, stackTrace) {
      commonPrint.log(
        'HTTP capture clear failed: ${compactError(error)}, $stackTrace',
        logLevel: LogLevel.warning,
      );
    }
  }
}

final httpCaptureProvider =
    NotifierProvider<HttpCaptureNotifier, HttpCaptureState>(
      HttpCaptureNotifier.new,
    );
