import 'package:drift/native.dart';
import 'package:fl_clash/database/database.dart';
import 'package:fl_clash/models/models.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  late Database database;

  QuickRoutingDiagnosticSnapshot snapshot({
    required int id,
    required String fingerprint,
    required DateTime checkedAt,
    String status = 'mismatch',
  }) {
    return QuickRoutingDiagnosticSnapshot(
      id: id,
      profileId: 1,
      fingerprint: fingerprint,
      createdAt: DateTime.utc(2026, 9, 24),
      checkedAt: checkedAt,
      status: status,
      searchText: 'api.example.com $status',
      payload: '{"fingerprint":"$fingerprint"}',
    );
  }

  setUp(() async {
    database = Database(NativeDatabase.memory());
    await database.profilesDao.putAll([
      const Profile(id: 1, autoUpdateDuration: Duration.zero).toCompanion(),
    ]);
  });

  tearDown(() async {
    await database.close();
  });

  test('diagnostic snapshots survive a database round trip', () async {
    final value = snapshot(
      id: 10,
      fingerprint: 'request-1',
      checkedAt: DateTime.utc(2026, 9, 24, 1),
    );

    final stored = await database.upsertQuickRoutingDiagnostic(value);
    final loaded = await database.loadQuickRoutingDiagnostics(profileId: 1);

    expect(stored.id, 10);
    expect(loaded, hasLength(1));
    expect(loaded.single.fingerprint, value.fingerprint);
    expect(loaded.single.checkedAt.isAtSameMomentAs(value.checkedAt), isTrue);
    expect(loaded.single.payload, value.payload);
  });

  test('upsert preserves identity and creation time for one fingerprint', () async {
    final createdAt = DateTime.utc(2026, 9, 24);
    final first = snapshot(
      id: 10,
      fingerprint: 'request-1',
      checkedAt: createdAt,
    );
    await database.upsertQuickRoutingDiagnostic(first);

    final replacement = QuickRoutingDiagnosticSnapshot(
      id: 99,
      profileId: 1,
      fingerprint: first.fingerprint,
      createdAt: createdAt.add(const Duration(hours: 2)),
      checkedAt: createdAt.add(const Duration(hours: 3)),
      status: 'verified',
      searchText: 'updated',
      payload: '{"updated":true}',
    );
    final stored = await database.upsertQuickRoutingDiagnostic(replacement);

    expect(stored.id, first.id);
    expect(stored.createdAt.isAtSameMomentAs(first.createdAt), isTrue);
    expect(stored.checkedAt.isAtSameMomentAs(replacement.checkedAt), isTrue);
    expect(stored.status, 'verified');
    expect(await database.countQuickRoutingDiagnostics(1), 1);
  });

  test('retention keeps the newest entries for each profile', () async {
    final base = DateTime.utc(2026, 9, 24);
    for (var index = 0; index < 4; index++) {
      await database.upsertQuickRoutingDiagnostic(
        snapshot(
          id: index + 1,
          fingerprint: 'request-$index',
          checkedAt: base.add(Duration(minutes: index)),
        ),
        maxEntries: 2,
      );
    }

    final loaded = await database.loadQuickRoutingDiagnostics(profileId: 1);
    expect(loaded.map((entry) => entry.id), [4, 3]);
    expect(await database.countQuickRoutingDiagnostics(1), 2);
  });

  test('delete and clear remove persisted diagnostics', () async {
    final base = DateTime.utc(2026, 9, 24);
    await database.upsertQuickRoutingDiagnostic(
      snapshot(id: 1, fingerprint: 'one', checkedAt: base),
    );
    await database.upsertQuickRoutingDiagnostic(
      snapshot(
        id: 2,
        fingerprint: 'two',
        checkedAt: base.add(const Duration(minutes: 1)),
      ),
    );

    await database.deleteQuickRoutingDiagnostic(1);
    expect(
      (await database.loadQuickRoutingDiagnostics(profileId: 1))
          .map((entry) => entry.id),
      [2],
    );

    await database.clearQuickRoutingDiagnostics(1);
    expect(await database.countQuickRoutingDiagnostics(1), 0);
  });
}
