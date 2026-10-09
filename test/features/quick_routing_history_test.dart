import 'dart:async';

import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/features/features.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/quick_routing.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:riverpod/riverpod.dart';

class _ControlledDiagnosticsPersistence
    implements QuickRoutingDiagnosticsPersistence {
  final loadCompleter = Completer<List<QuickRoutingVerificationRecord>>();
  int clearCount = 0;

  @override
  Future<List<QuickRoutingVerificationRecord>> loadProfile(
    int profileId, {
    int limit = QuickRoutingVerificationHistory.maxEntries,
  }) {
    return loadCompleter.future;
  }

  @override
  Future<QuickRoutingVerificationRecord> upsert(
    QuickRoutingVerificationRecord record, {
    int maxEntries = QuickRoutingVerificationHistory.maxEntries,
  }) async {
    return record;
  }

  @override
  Future<void> remove(int id) async {}

  @override
  Future<void> clearProfile(int profileId) async {
    clearCount++;
  }
}

void main() {
  const selection = QuickRoutingSelection(
    candidate: QuickRoutingCandidate(
      ruleAction: RuleAction.DOMAIN,
      content: 'api.example.com',
    ),
    target: 'DIRECT',
    lifetime: QuickRoutingLifetime.session,
  );

  QuickRoutingVerificationRecord record({
    required int id,
    required int profileId,
    required String requestId,
    required DateTime checkedAt,
    DateTime? createdAt,
    String host = 'api.example.com',
  }) {
    return QuickRoutingVerificationRecord(
      id: id,
      profileId: profileId,
      createdAt: createdAt ?? checkedAt,
      checkedAt: checkedAt,
      trackerInfo: TrackerInfo(
        id: requestId,
        start: checkedAt,
        metadata: Metadata(host: host),
        chains: const [],
        rule: 'MATCH',
        rulePayload: '',
      ),
      selection: selection,
      appliedRule: const Rule(
        id: -1,
        ruleAction: RuleAction.DOMAIN,
        content: 'api.example.com',
        ruleTarget: 'DIRECT',
      ),
      verification: const QuickRoutingVerification(
        status: QuickRoutingVerificationStatus.verified,
        result: null,
        issues: [],
      ),
    );
  }

  test('retention is bounded independently for every profile', () {
    final container = ProviderContainer();
    addTearDown(container.dispose);
    final notifier = container.read(
      quickRoutingVerificationHistoryProvider.notifier,
    );
    final base = DateTime.utc(2026, 9, 24);

    for (
      var index = 0;
      index < QuickRoutingVerificationHistory.maxEntries + 5;
      index++
    ) {
      notifier.upsertRecord(
        record(
          id: index,
          profileId: 1,
          requestId: 'one-$index',
          checkedAt: base.add(Duration(seconds: index)),
        ),
      );
    }
    for (var index = 0; index < 3; index++) {
      notifier.upsertRecord(
        record(
          id: 1000 + index,
          profileId: 2,
          requestId: 'two-$index',
          checkedAt: base.add(Duration(minutes: index)),
        ),
      );
    }

    final entries = container.read(quickRoutingVerificationHistoryProvider);
    expect(entries.where((entry) => entry.profileId == 1), hasLength(100));
    expect(entries.where((entry) => entry.profileId == 2), hasLength(3));
  });

  test('hydration keeps a newer in-memory result for the same identity', () {
    final container = ProviderContainer();
    addTearDown(container.dispose);
    final notifier = container.read(
      quickRoutingVerificationHistoryProvider.notifier,
    );
    final base = DateTime.utc(2026, 9, 24);
    final persisted = record(
      id: 10,
      profileId: 1,
      requestId: 'same',
      checkedAt: base,
    );
    final current = record(
      id: 20,
      profileId: 1,
      requestId: 'same',
      checkedAt: base.add(const Duration(minutes: 1)),
    );
    notifier.upsertRecord(current);

    notifier.mergePersisted([
      persisted,
      record(id: 30, profileId: 1, requestId: 'other', checkedAt: base),
    ]);

    final entries = container.read(quickRoutingVerificationHistoryProvider);
    expect(entries, hasLength(2));
    expect(
      entries.firstWhere((entry) => entry.trackerInfo.id == 'same').id,
      current.id,
    );
  });

  test('canonical database identity replaces the optimistic record', () {
    final container = ProviderContainer();
    addTearDown(container.dispose);
    final notifier = container.read(
      quickRoutingVerificationHistoryProvider.notifier,
    );
    final base = DateTime.utc(2026, 9, 24);
    final optimistic = record(
      id: 99,
      profileId: 1,
      requestId: 'same',
      checkedAt: base.add(const Duration(minutes: 1)),
    );
    notifier.upsertRecord(optimistic);
    final canonical = optimistic.copyWith(id: 10, createdAt: base);

    expect(notifier.replaceRecord(canonical), isTrue);
    final restored = container
        .read(quickRoutingVerificationHistoryProvider)
        .single;
    expect(restored.id, 10);
    expect(restored.createdAt, base);
  });

  test('clear remains authoritative over an in-flight hydration', () async {
    final persistence = _ControlledDiagnosticsPersistence();
    final container = ProviderContainer(
      overrides: [
        quickRoutingDiagnosticsPersistenceProvider.overrideWithValue(
          persistence,
        ),
      ],
    );
    addTearDown(container.dispose);
    final notifier = container.read(
      quickRoutingVerificationHistoryProvider.notifier,
    );
    final coordinator = container.read(
      quickRoutingDiagnosticsCoordinatorProvider,
    );
    final persisted = record(
      id: 10,
      profileId: 1,
      requestId: 'persisted',
      checkedAt: DateTime.utc(2026, 9, 24),
    );

    final hydration = coordinator.hydrate(notifier, 1);
    final clearing = coordinator.clearProfile(notifier, 1);
    persistence.loadCompleter.complete([persisted]);

    await hydration;
    await clearing;

    expect(
      container
          .read(quickRoutingVerificationHistoryProvider)
          .where((entry) => entry.profileId == 1),
      isEmpty,
    );
    expect(persistence.clearCount, 1);
  });
}
