import 'package:drift/native.dart';
import 'package:fl_clash/database/database.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/config.dart';
import 'package:fl_clash/providers/http_capture.dart';
import 'package:fl_clash/providers/logbook.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

TrackerInfo tracker({
  String id = 'connection-1',
  String network = 'tcp',
  String host = 'api.example.com',
  String port = '443',
}) {
  return TrackerInfo(
    id: id,
    upload: 1,
    download: 2,
    start: DateTime.now().subtract(const Duration(milliseconds: 20)),
    metadata: Metadata(
      uid: 10001,
      network: network,
      sourceIP: '10.0.0.2',
      sourcePort: '50000',
      destinationIP: '1.1.1.1',
      destinationPort: port,
      host: host,
      process: 'example',
    ),
    chains: const ['Proxy'],
    rule: 'Domain',
    rulePayload: 'api.example.com',
  );
}

ProviderContainer container({
  bool persistence = false,
  bool logbookPersistence = false,
}) {
  return ProviderContainer(
    overrides: [
      currentProfileIdProvider.overrideWithBuild((_, _) => 1),
      httpCapturePersistenceEnabledProvider.overrideWithValue(persistence),
      logbookPersistenceEnabledProvider.overrideWithValue(logbookPersistence),
    ],
  );
}

void main() {
  test('capture is opt-in and records only HTTP candidates', () async {
    final scope = container();
    addTearDown(scope.dispose);
    final notifier = scope.read(httpCaptureProvider.notifier);

    expect(await notifier.observe(tracker()), isNull);
    await notifier.start();
    expect(scope.read(httpCaptureProvider).enabled, isTrue);

    final captured = await notifier.observe(tracker());
    final ignored = await notifier.observe(
      tracker(id: 'dns', network: 'udp', host: 'dns.example', port: '53'),
    );

    expect(captured, isNotNull);
    expect(ignored, isNull);
    expect(scope.read(httpCaptureProvider).entries, hasLength(1));
    expect(
      scope.read(httpCaptureProvider).entries.single.protocol,
      HttpCaptureProtocol.tls,
    );

    await notifier.stop();

    expect(scope.read(httpCaptureProvider).enabled, isFalse);
    expect(scope.read(logbookProvider), hasLength(1));
    final event = scope.read(logbookProvider).single;
    expect(event.eventType, 'http.capture.session');
    expect(event.profileId, isNull);
    expect(event.details['status'], 'completed');
    expect(event.details['count'], 1);
    expect(event.details['observationOnly'], isTrue);
  });

  test('same connection updates rather than duplicating', () async {
    final scope = container();
    addTearDown(scope.dispose);
    final notifier = scope.read(httpCaptureProvider.notifier);
    await notifier.start();

    await notifier.observe(tracker(id: 'same'));
    await notifier.observe(tracker(id: 'same'));

    expect(scope.read(httpCaptureProvider).entries, hasLength(1));
  });

  test('the same connection can be observed in separate sessions', () async {
    final scope = container();
    addTearDown(scope.dispose);
    final notifier = scope.read(httpCaptureProvider.notifier);

    await notifier.start();
    await notifier.observe(tracker(id: 'reused'));
    await notifier.stop();
    await Future<void>.delayed(const Duration(microseconds: 1));
    await notifier.start();
    await notifier.observe(tracker(id: 'reused'));

    final entries = scope.read(httpCaptureProvider).entries;
    expect(entries, hasLength(2));
    expect(entries.map((entry) => entry.sessionId).toSet(), hasLength(2));
  });

  test('remove and clear stay authoritative in memory', () async {
    final scope = container();
    addTearDown(scope.dispose);
    final notifier = scope.read(httpCaptureProvider.notifier);
    await notifier.start();
    final first = await notifier.observe(tracker(id: 'first'));
    await notifier.observe(tracker(id: 'second'));

    await notifier.remove(first!.id);
    expect(
      scope
          .read(httpCaptureProvider)
          .entries
          .map((entry) => entry.connectionId),
      ['second'],
    );

    await notifier.clear(profileId: 1);
    expect(scope.read(httpCaptureProvider).entries, isEmpty);
  });

  test('stale running sessions are reconciled as interrupted', () async {
    final originalDatabase = database;
    final testDatabase = Database(NativeDatabase.memory());
    database = testDatabase;
    addTearDown(() async {
      database = originalDatabase;
      await testDatabase.close();
    });

    final first = container(persistence: true, logbookPersistence: true);
    await first.read(httpCaptureProvider.notifier).start();
    expect(first.read(logbookProvider).single.details['status'], 'running');
    first.dispose();

    final second = container(persistence: true, logbookPersistence: true);
    addTearDown(second.dispose);
    await second.read(httpCaptureProvider.notifier).reload();

    final event = second.read(logbookProvider).single;
    expect(second.read(httpCaptureProvider).enabled, isFalse);
    expect(event.eventType, 'http.capture.session');
    expect(event.severity, LogbookSeverity.warning);
    expect(event.details['status'], 'interrupted');
    expect(event.details['observationOnly'], isTrue);
    expect(event.details['durationMs'], isA<int>());
  });

  test(
    'deleting an optimistic update cannot resurrect its canonical row',
    () async {
      final originalDatabase = database;
      final testDatabase = Database(NativeDatabase.memory());
      database = testDatabase;
      addTearDown(() async {
        database = originalDatabase;
        await testDatabase.close();
      });
      await testDatabase.profilesDao.putAll([
        const Profile(
          id: 1,
          label: 'Capture profile',
          autoUpdateDuration: Duration.zero,
        ).toCompanion(),
      ]);

      final scope = container(persistence: true);
      addTearDown(scope.dispose);
      final notifier = scope.read(httpCaptureProvider.notifier);
      await notifier.start();
      final sessionId = scope.read(httpCaptureProvider).sessionId;
      await testDatabase.upsertHttpCaptureEntry(
        HttpCaptureEntry.fromTracker(
          id: 1,
          tracker: tracker(id: 'race'),
          sessionId: sessionId,
          profileId: 1,
        ),
      );
      await notifier.reload();
      expect(scope.read(httpCaptureProvider).entries.single.id, 1);

      final observe = notifier.observe(tracker(id: 'race'));
      final optimistic = scope.read(httpCaptureProvider).entries.single;
      expect(optimistic.id, isNot(1));
      final remove = notifier.remove(optimistic.id);
      await Future.wait<void>([observe.then((_) {}), remove]);

      expect(scope.read(httpCaptureProvider).entries, isEmpty);
      expect(await testDatabase.countHttpCaptureEntries(profileId: 1), 0);
    },
  );

  test('capture persists and reloads across provider containers', () async {
    final originalDatabase = database;
    final testDatabase = Database(NativeDatabase.memory());
    database = testDatabase;
    addTearDown(() async {
      database = originalDatabase;
      await testDatabase.close();
    });
    await testDatabase.profilesDao.putAll([
      const Profile(
        id: 1,
        label: 'Capture profile',
        autoUpdateDuration: Duration.zero,
      ).toCompanion(),
    ]);

    final first = container(persistence: true);
    final firstNotifier = first.read(httpCaptureProvider.notifier);
    await firstNotifier.start();
    await firstNotifier.observe(tracker());
    first.dispose();

    final second = container(persistence: true);
    addTearDown(second.dispose);
    await second.read(httpCaptureProvider.notifier).reload();

    expect(second.read(httpCaptureProvider).enabled, isFalse);
    expect(second.read(httpCaptureProvider).entries, hasLength(1));
    expect(
      second.read(httpCaptureProvider).entries.single.connectionId,
      'connection-1',
    );
  });
}
