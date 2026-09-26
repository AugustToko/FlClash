import 'package:drift/native.dart';
import 'package:fl_clash/database/database.dart';
import 'package:fl_clash/models/models.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  late Database database;

  LogbookEvent event({
    required int id,
    required DateTime time,
    int? profileId,
    String correlationId = '',
    LogbookSeverity severity = LogbookSeverity.info,
    String title = 'Event',
  }) {
    return LogbookEvent(
      id: id,
      profileId: profileId,
      createdAt: time,
      updatedAt: time,
      category: LogbookCategory.routing,
      severity: severity,
      eventType: 'routing.test',
      title: title,
      message: 'api.example.com',
      correlationId: correlationId,
      details: const {'target': 'DIRECT'},
    );
  }

  setUp(() async {
    database = Database(NativeDatabase.memory());
    await database.customSelect('SELECT 1').get();
  });

  tearDown(() async {
    await database.close();
  });

  test('logbook events survive a database round trip', () async {
    final time = DateTime.utc(2026, 9, 25, 1);
    final stored = await database.upsertLogbookEvent(
      event(id: 1, time: time, profileId: 7),
    );
    final loaded = await database.loadLogbookEvents();

    expect(stored.id, 1);
    expect(loaded, hasLength(1));
    expect(loaded.single.profileId, 7);
    expect(loaded.single.category, LogbookCategory.routing);
    expect(loaded.single.details['target'], 'DIRECT');
  });

  test(
    'correlated events update in place and preserve creation identity',
    () async {
      final createdAt = DateTime.utc(2026, 9, 25, 1);
      final first = await database.upsertLogbookEvent(
        event(
          id: 10,
          time: createdAt,
          profileId: 7,
          correlationId: 'request-1',
        ),
      );
      final updatedAt = createdAt.add(const Duration(minutes: 2));
      final updated = await database.upsertLogbookEvent(
        event(
          id: 99,
          time: updatedAt,
          profileId: 7,
          correlationId: 'request-1',
          severity: LogbookSeverity.error,
          title: 'Updated',
        ),
      );

      expect(updated.id, first.id);
      expect(updated.createdAt, first.createdAt);
      expect(updated.updatedAt, updatedAt);
      expect(updated.severity, LogbookSeverity.error);
      expect(updated.title, 'Updated');
      expect(await database.countLogbookEvents(profileId: 7), 1);
    },
  );

  test('uncorrelated events remain independent', () async {
    final base = DateTime.utc(2026, 9, 25);
    await database.upsertLogbookEvent(event(id: 1, time: base));
    await database.upsertLogbookEvent(
      event(id: 2, time: base.add(const Duration(seconds: 1))),
    );

    expect(await database.countLogbookEvents(), 2);
  });

  test('retention is enforced independently for each scope', () async {
    final base = DateTime.utc(2026, 9, 25);
    for (var index = 0; index < 4; index++) {
      await database.upsertLogbookEvent(
        event(
          id: index + 1,
          time: base.add(Duration(minutes: index)),
          profileId: 1,
        ),
        maxEntriesPerScope: 2,
      );
    }
    await database.upsertLogbookEvent(
      event(id: 100, time: base, profileId: 2),
      maxEntriesPerScope: 2,
    );

    final profileOne = await database.loadLogbookEvents(
      profileId: 1,
      includeGlobal: false,
    );
    final profileTwo = await database.loadLogbookEvents(
      profileId: 2,
      includeGlobal: false,
    );
    expect(profileOne.map((value) => value.id), [4, 3]);
    expect(profileTwo.map((value) => value.id), [100]);
  });

  test('profile loading can include global events', () async {
    final base = DateTime.utc(2026, 9, 25);
    await database.upsertLogbookEvent(event(id: 1, time: base));
    await database.upsertLogbookEvent(
      event(id: 2, time: base.add(const Duration(seconds: 1)), profileId: 7),
    );
    await database.upsertLogbookEvent(
      event(id: 3, time: base.add(const Duration(seconds: 2)), profileId: 8),
    );

    final loaded = await database.loadLogbookEvents(profileId: 7);
    expect(loaded.map((value) => value.id), [2, 1]);
  });

  test('delete and clear remove the requested events', () async {
    final base = DateTime.utc(2026, 9, 25);
    await database.upsertLogbookEvent(event(id: 1, time: base, profileId: 1));
    await database.upsertLogbookEvent(event(id: 2, time: base, profileId: 2));

    await database.deleteLogbookEvent(1);
    expect(await database.countLogbookEvents(profileId: 1), 0);
    expect(await database.countLogbookEvents(profileId: 2), 1);

    await database.clearLogbook();
    expect(await database.countLogbookEvents(), 0);
  });
}
