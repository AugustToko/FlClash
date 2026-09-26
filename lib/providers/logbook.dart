import 'dart:async';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/database/database.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/models/models.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

bool _hasServicesBinding() {
  try {
    ServicesBinding.instance;
    return true;
  } on AssertionError {
    return false;
  }
}

final logbookPersistenceEnabledProvider = Provider<bool>(
  (_) => _hasServicesBinding(),
);

class LogbookNotifier extends Notifier<List<LogbookEvent>> {
  static const maxEntriesPerScope = 500;
  static const maxLoadedEntries = 1000;

  Future<void>? _loadOperation;
  Future<void> _writeTail = Future<void>.value();

  @override
  List<LogbookEvent> build() => const [];

  List<LogbookEvent> _bounded(Iterable<LogbookEvent> events) {
    final values = events.toList(growable: false)
      ..sort((first, second) {
        final updated = second.updatedAt.compareTo(first.updatedAt);
        return updated != 0 ? updated : second.id.compareTo(first.id);
      });
    return List.unmodifiable(values.take(maxLoadedEntries));
  }

  void _upsertMemory(LogbookEvent event) {
    final next =
        state
            .where(
              (entry) =>
                  entry.id != event.id &&
                  (event.correlationId.isEmpty ||
                      entry.identity != event.identity),
            )
            .toList(growable: true)
          ..add(event);
    state = _bounded(next);
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

  Future<void> reload() {
    if (!ref.read(logbookPersistenceEnabledProvider)) {
      return Future<void>.value();
    }
    final active = _loadOperation;
    if (active != null) {
      return active;
    }
    final operation = () async {
      try {
        final persisted = await _serialize(
          () => database.loadLogbookEvents(limit: maxLoadedEntries),
        );
        if (!ref.mounted) {
          return;
        }
        final byIdentity = <String, LogbookEvent>{
          for (final event in persisted) event.identity: event,
        };
        for (final event in state) {
          final persistedEvent = byIdentity[event.identity];
          if (persistedEvent == null ||
              event.updatedAt.isAfter(persistedEvent.updatedAt)) {
            byIdentity[event.identity] = event;
          }
        }
        state = _bounded(byIdentity.values);
      } catch (error, stackTrace) {
        commonPrint.log(
          'logbook hydration failed: ${compactError(error)}, $stackTrace',
          logLevel: LogLevel.warning,
        );
      } finally {
        _loadOperation = null;
      }
    }();
    _loadOperation = operation;
    return operation;
  }

  Future<LogbookEvent> record({
    int? profileId,
    required LogbookCategory category,
    required LogbookSeverity severity,
    required String eventType,
    required String title,
    String message = '',
    String correlationId = '',
    Map<String, Object?> details = const {},
    DateTime? now,
  }) async {
    final timestamp = now ?? DateTime.now();
    final identityProbe = LogbookEvent(
      id: -1,
      profileId: profileId,
      createdAt: timestamp,
      updatedAt: timestamp,
      category: category,
      severity: severity,
      eventType: eventType,
      title: title,
      message: message,
      correlationId: correlationId,
      details: Map<String, Object?>.unmodifiable(details),
    );
    LogbookEvent? existing;
    if (correlationId.isNotEmpty) {
      for (final entry in state) {
        if (entry.identity == identityProbe.identity) {
          existing = entry;
          break;
        }
      }
    }
    final optimistic = identityProbe.copyWith(
      id: existing?.id ?? snowflake.id,
      createdAt: existing?.createdAt ?? timestamp,
    );
    _upsertMemory(optimistic);
    if (!ref.read(logbookPersistenceEnabledProvider)) {
      return optimistic;
    }
    try {
      final canonical = await _serialize(
        () => database.upsertLogbookEvent(
          optimistic,
          maxEntriesPerScope: maxEntriesPerScope,
        ),
      );
      if (ref.mounted) {
        _upsertMemory(canonical);
      }
      return canonical;
    } catch (error, stackTrace) {
      commonPrint.log(
        'logbook write failed: ${compactError(error)}, $stackTrace',
        logLevel: LogLevel.warning,
      );
      return optimistic;
    }
  }

  Future<void> remove(int id) async {
    void removeFromMemory() {
      state = List.unmodifiable(state.where((entry) => entry.id != id));
    }

    removeFromMemory();
    if (!ref.read(logbookPersistenceEnabledProvider)) {
      return;
    }
    try {
      await _serialize(() => database.deleteLogbookEvent(id));
      if (ref.mounted) {
        removeFromMemory();
      }
    } catch (error, stackTrace) {
      commonPrint.log(
        'logbook delete failed: ${compactError(error)}, $stackTrace',
        logLevel: LogLevel.warning,
      );
    }
  }

  Future<void> clear({int? profileId, bool includeGlobal = false}) async {
    void clearFromMemory() {
      state = List.unmodifiable(
        state.where((entry) {
          if (profileId == null) {
            return false;
          }
          if (entry.profileId == profileId) {
            return false;
          }
          return !(includeGlobal && entry.profileId == null);
        }),
      );
    }

    clearFromMemory();
    if (!ref.read(logbookPersistenceEnabledProvider)) {
      return;
    }
    try {
      await _serialize(
        () => database.clearLogbook(
          profileId: profileId,
          includeGlobal: includeGlobal,
        ),
      );
      if (ref.mounted) {
        clearFromMemory();
      }
    } catch (error, stackTrace) {
      commonPrint.log(
        'logbook clear failed: ${compactError(error)}, $stackTrace',
        logLevel: LogLevel.warning,
      );
    }
  }
}

final logbookProvider = NotifierProvider<LogbookNotifier, List<LogbookEvent>>(
  LogbookNotifier.new,
);
