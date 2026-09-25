import 'package:drift/native.dart';
import 'package:fl_clash/database/database.dart';
import 'package:fl_clash/models/models.dart';
import 'package:flutter_test/flutter_test.dart';

HttpCaptureEntry capture({
  required int id,
  required String connectionId,
  String sessionId = 'session-1',
  int? profileId = 1,
  DateTime? observedAt,
  HttpCaptureProtocol protocol = HttpCaptureProtocol.tls,
}) {
  final now = observedAt ?? DateTime.utc(2026, 9, 25, 10);
  return HttpCaptureEntry(
    id: id,
    connectionId: connectionId,
    sessionId: sessionId,
    profileId: profileId,
    startedAt: now.subtract(const Duration(milliseconds: 50)),
    observedAt: now,
    protocol: protocol,
    evidence: 'known-tls-port',
    network: 'tcp',
    host: 'api.example.com',
    destinationIP: '1.1.1.1',
    destinationPort: 443,
    sourceIP: '10.0.0.2',
    sourcePort: 50000,
    process: 'example',
    processPath: '/data/app/example',
    uid: 10001,
    rule: 'Domain',
    rulePayload: 'api.example.com',
    chains: const ['Proxy', 'HK-01'],
    upload: 0,
    download: 0,
    remoteDestination: '',
  );
}

void main() {
  late Database database;

  setUp(() async {
    database = Database(NativeDatabase.memory());
    await database.profilesDao.putAll([
      const Profile(
        id: 1,
        label: 'Capture profile',
        autoUpdateDuration: Duration.zero,
      ).toCompanion(),
    ]);
  });

  tearDown(() => database.close());

  test('HTTP observations survive a database round trip', () async {
    final entry = capture(id: 1, connectionId: 'connection-1');

    final stored = await database.upsertHttpCaptureEntry(entry);
    final loaded = await database.loadHttpCaptureEntries(
      profileId: 1,
      includeGlobal: false,
    );

    expect(stored.id, 1);
    expect(loaded, hasLength(1));
    expect(loaded.single.connectionId, 'connection-1');
    expect(loaded.single.origin, 'https://api.example.com');
    expect(await database.countHttpCaptureEntries(profileId: 1), 1);
  });

  test('same scope and connection update in place', () async {
    final first = capture(
      id: 10,
      connectionId: 'same',
      observedAt: DateTime.utc(2026, 9, 25, 10),
    );
    final second = capture(
      id: 11,
      connectionId: 'same',
      observedAt: DateTime.utc(2026, 9, 25, 10, 1),
      protocol: HttpCaptureProtocol.http,
    );

    await database.upsertHttpCaptureEntry(first);
    final updated = await database.upsertHttpCaptureEntry(second);

    expect(updated.id, first.id);
    expect(updated.protocol, HttpCaptureProtocol.http);
    expect(updated.observedAt, second.observedAt);
    expect(await database.countHttpCaptureEntries(profileId: 1), 1);
  });

  test(
    'the same connection id in another session remains independent',
    () async {
      await database.upsertHttpCaptureEntry(
        capture(id: 20, connectionId: 'same', sessionId: 'session-a'),
      );
      await database.upsertHttpCaptureEntry(
        capture(id: 21, connectionId: 'same', sessionId: 'session-b'),
      );

      final loaded = await database.loadHttpCaptureEntries(
        profileId: 1,
        includeGlobal: false,
      );
      expect(loaded, hasLength(2));
      expect(loaded.map((entry) => entry.sessionId).toSet(), {
        'session-a',
        'session-b',
      });
    },
  );

  test('retention is enforced independently per scope', () async {
    for (var index = 0; index < 4; index++) {
      await database.upsertHttpCaptureEntry(
        capture(
          id: 100 + index,
          connectionId: 'profile-$index',
          observedAt: DateTime.utc(2026, 9, 25, 10, index),
        ),
        maxEntriesPerScope: 2,
      );
      await database.upsertHttpCaptureEntry(
        capture(
          id: 200 + index,
          connectionId: 'global-$index',
          profileId: null,
          observedAt: DateTime.utc(2026, 9, 25, 11, index),
        ),
        maxEntriesPerScope: 3,
      );
    }

    expect(await database.countHttpCaptureEntries(profileId: 1), 2);
    final all = await database.loadHttpCaptureEntries();
    expect(all.where((entry) => entry.profileId == null), hasLength(3));
  });

  test('profile deletion removes its local capture history', () async {
    await database.upsertHttpCaptureEntry(
      capture(id: 301, connectionId: 'profile-entry'),
    );
    await database.upsertHttpCaptureEntry(
      capture(id: 302, connectionId: 'global-entry', profileId: null),
    );

    await database.profiles.remove((table) => table.id.equals(1));

    expect(await database.countHttpCaptureEntries(profileId: 1), 0);
    expect(await database.countHttpCaptureEntries(), 1);
  });

  test('unknown profile ids are rejected', () async {
    await expectLater(
      database.upsertHttpCaptureEntry(
        capture(id: 401, connectionId: 'orphan', profileId: 999),
      ),
      throwsA(anything),
    );
  });

  test('identity deletion does not depend on the current row id', () async {
    await database.upsertHttpCaptureEntry(
      capture(
        id: 450,
        connectionId: 'identity-delete',
        sessionId: 'identity-session',
      ),
    );

    await database.deleteHttpCaptureEntryByIdentity(
      scopeKey: 'profile:1',
      sessionId: 'identity-session',
      connectionId: 'identity-delete',
    );

    expect(await database.countHttpCaptureEntries(profileId: 1), 0);
  });

  test('delete and clear remove only requested scopes', () async {
    final first = await database.upsertHttpCaptureEntry(
      capture(id: 501, connectionId: 'first'),
    );
    await database.upsertHttpCaptureEntry(
      capture(id: 502, connectionId: 'second'),
    );
    await database.upsertHttpCaptureEntry(
      capture(id: 503, connectionId: 'global', profileId: null),
    );

    await database.deleteHttpCaptureEntry(first.id);
    expect(await database.countHttpCaptureEntries(profileId: 1), 1);

    await database.clearHttpCaptureEntries(profileId: 1);
    expect(await database.countHttpCaptureEntries(profileId: 1), 0);
    expect(await database.countHttpCaptureEntries(), 1);
  });
}
