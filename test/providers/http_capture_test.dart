import 'dart:async';

import 'package:drift/native.dart';

import 'package:fl_clash/database/database.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/app.dart';
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
  DateTime? start,
  ProtocolObservation? observation,
}) {
  return TrackerInfo(
    id: id,
    upload: 1,
    download: 2,
    start: start ?? DateTime.now().subtract(const Duration(milliseconds: 20)),
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
    observation: observation,
  );
}

ProviderContainer container({
  bool persistence = false,
  bool logbookPersistence = false,
  CoreStatus coreStatus = CoreStatus.disconnected,
  HttpCaptureCoreControl? coreControl,
  Duration? coreDisableRetryDelay,
}) {
  return ProviderContainer(
    overrides: [
      currentProfileIdProvider.overrideWithBuild((_, _) => 1),
      coreStatusProvider.overrideWithBuild((_, _) => coreStatus),
      httpCapturePersistenceEnabledProvider.overrideWithValue(persistence),
      logbookPersistenceEnabledProvider.overrideWithValue(logbookPersistence),
      if (coreControl != null)
        httpCaptureCoreControlProvider.overrideWithValue(coreControl),
      if (coreDisableRetryDelay != null)
        httpCaptureCoreDisableRetryDelayProvider.overrideWithValue(
          coreDisableRetryDelay,
        ),
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

  test(
    'response updates enrich the same connection without reordering',
    () async {
      final scope = container();
      addTearDown(scope.dispose);
      final notifier = scope.read(httpCaptureProvider.notifier);
      await notifier.start();
      final sessionId = scope.read(httpCaptureProvider).sessionId;
      final startedAt = DateTime.utc(2026, 9, 26, 6);

      final initial = await notifier.observe(
        tracker(
          id: 'same',
          host: '',
          port: '18080',
          start: startedAt,
          observation: ProtocolObservation(
            sessionId: sessionId,
            kind: 'http1',
            observedBytes: 72,
            http: const HttpProtocolObservation(
              method: 'GET',
              target: '/health',
              version: 'HTTP/1.1',
              host: 'service.example',
              headersComplete: true,
            ),
          ),
        ),
      );
      final firstObservedAt = initial!.observedAt;

      final updated = await notifier.observe(
        tracker(
          id: 'same',
          host: '',
          port: '18080',
          start: startedAt,
          observation: ProtocolObservation(
            sessionId: sessionId,
            kind: 'http1',
            observedBytes: 72,
            http: const HttpProtocolObservation(
              method: 'GET',
              target: '/health',
              version: 'HTTP/1.1',
              host: 'service.example',
              headersComplete: true,
            ),
            httpResponse: const HttpResponseProtocolObservation(
              version: 'HTTP/1.1',
              statusCode: 204,
              informationalStatusCodes: [100],
              headerNames: ['date', 'server'],
              headersComplete: true,
              observedBytes: 64,
              observedAfterMilliseconds: 37,
            ),
          ),
        ),
      );

      final entries = scope.read(httpCaptureProvider).entries;
      expect(entries, hasLength(1));
      expect(updated?.id, initial.id);
      expect(updated?.observedAt, firstObservedAt);
      expect(entries.single.httpResponseObservation?.statusCode, 204);
      expect(entries.single.httpResponseObservation?.headerNames, [
        'date',
        'server',
      ]);
    },
  );

  test(
    'a response update stays in the Profile that observed the request',
    () async {
      final scope = container();
      addTearDown(scope.dispose);
      final notifier = scope.read(httpCaptureProvider.notifier);
      await notifier.start();
      final sessionId = scope.read(httpCaptureProvider).sessionId;
      final startedAt = DateTime.utc(2026, 9, 26, 7);
      final request = ProtocolObservation(
        sessionId: sessionId,
        kind: 'http1',
        observedBytes: 64,
        http: const HttpProtocolObservation(
          method: 'GET',
          target: '/profile',
          version: 'HTTP/1.1',
          host: 'service.example',
          headersComplete: true,
        ),
      );
      final initial = await notifier.observe(
        tracker(
          id: 'profile-bound',
          host: '',
          port: '18080',
          start: startedAt,
          observation: request,
        ),
      );
      expect(initial?.profileId, 1);

      scope.read(currentProfileIdProvider.notifier).value = 2;
      final updated = await notifier.observe(
        tracker(
          id: 'profile-bound',
          host: '',
          port: '18080',
          start: startedAt,
          observation: ProtocolObservation(
            sessionId: sessionId,
            kind: 'http1',
            observedBytes: 64,
            http: request.http,
            httpResponse: const HttpResponseProtocolObservation(
              version: 'HTTP/1.1',
              statusCode: 204,
              headersComplete: true,
              observedBytes: 36,
            ),
          ),
        ),
      );

      expect(updated?.profileId, 1);
      expect(scope.read(httpCaptureProvider).entries, hasLength(1));
      expect(scope.read(httpCaptureProvider).entries.single.profileId, 1);
      expect(
        scope
            .read(httpCaptureProvider)
            .entries
            .single
            .httpResponseObservation
            ?.statusCode,
        204,
      );
    },
  );

  test(
    'a deleted active connection is not recreated by a response update',
    () async {
      final scope = container();
      addTearDown(scope.dispose);
      final notifier = scope.read(httpCaptureProvider.notifier);
      await notifier.start();
      final sessionId = scope.read(httpCaptureProvider).sessionId;
      final startedAt = DateTime.utc(2026, 9, 26, 7);
      final request = ProtocolObservation(
        sessionId: sessionId,
        kind: 'http1',
        observedBytes: 64,
        http: const HttpProtocolObservation(
          method: 'GET',
          target: '/deleted',
          version: 'HTTP/1.1',
          host: 'service.example',
          headersComplete: true,
        ),
      );
      final initial = await notifier.observe(
        tracker(
          id: 'deleted-live',
          host: '',
          port: '18080',
          start: startedAt,
          observation: request,
        ),
      );
      expect(initial, isNotNull);

      await notifier.remove(initial!.id);
      expect(scope.read(httpCaptureProvider).entries, isEmpty);

      final delayed = await notifier.observe(
        tracker(
          id: 'deleted-live',
          host: '',
          port: '18080',
          start: startedAt,
          observation: ProtocolObservation(
            sessionId: sessionId,
            kind: 'http1',
            observedBytes: 64,
            http: request.http,
            httpResponse: const HttpResponseProtocolObservation(
              version: 'HTTP/1.1',
              statusCode: 200,
              headerNames: ['content-type'],
              headersComplete: true,
              observedBytes: 48,
            ),
          ),
        ),
      );

      expect(delayed, isNull);
      expect(scope.read(httpCaptureProvider).entries, isEmpty);
    },
  );

  test('delete remains authoritative after switching Profiles', () async {
    final scope = container();
    addTearDown(scope.dispose);
    final notifier = scope.read(httpCaptureProvider.notifier);
    await notifier.start();
    final sessionId = scope.read(httpCaptureProvider).sessionId;
    final request = ProtocolObservation(
      sessionId: sessionId,
      kind: 'http1',
      observedBytes: 64,
      http: const HttpProtocolObservation(
        method: 'GET',
        target: '/deleted-profile',
        version: 'HTTP/1.1',
        host: 'service.example',
        headersComplete: true,
      ),
    );
    final initial = await notifier.observe(
      tracker(
        id: 'deleted-across-profile',
        host: '',
        port: '18080',
        observation: request,
      ),
    );
    expect(initial?.profileId, 1);
    await notifier.remove(initial!.id);
    scope.read(currentProfileIdProvider.notifier).value = 2;

    final delayed = await notifier.observe(
      tracker(
        id: 'deleted-across-profile',
        host: '',
        port: '18080',
        observation: ProtocolObservation(
          sessionId: sessionId,
          kind: 'http1',
          observedBytes: 64,
          http: request.http,
          httpResponse: const HttpResponseProtocolObservation(
            version: 'HTTP/1.1',
            statusCode: 200,
            headersComplete: true,
            observedBytes: 40,
          ),
        ),
      ),
    );

    expect(delayed, isNull);
    expect(scope.read(httpCaptureProvider).entries, isEmpty);
  });

  test(
    'clear prevents a pending response from recreating the request',
    () async {
      final scope = container();
      addTearDown(scope.dispose);
      final notifier = scope.read(httpCaptureProvider.notifier);
      await notifier.start();
      final sessionId = scope.read(httpCaptureProvider).sessionId;
      final request = ProtocolObservation(
        sessionId: sessionId,
        kind: 'http1',
        observedBytes: 64,
        http: const HttpProtocolObservation(
          method: 'GET',
          target: '/clear',
          version: 'HTTP/1.1',
          host: 'service.example',
          headersComplete: true,
        ),
      );
      await notifier.observe(
        tracker(
          id: 'cleared-live',
          host: '',
          port: '18080',
          observation: request,
        ),
      );
      await notifier.clear(profileId: 1);
      expect(scope.read(httpCaptureProvider).entries, isEmpty);

      final delayed = await notifier.observe(
        tracker(
          id: 'cleared-live',
          host: '',
          port: '18080',
          observation: ProtocolObservation(
            sessionId: sessionId,
            kind: 'http1',
            observedBytes: 64,
            http: request.http,
            httpResponse: const HttpResponseProtocolObservation(
              version: 'HTTP/1.1',
              statusCode: 200,
              headersComplete: true,
              observedBytes: 40,
            ),
          ),
        ),
      );

      expect(delayed, isNull);
      expect(scope.read(httpCaptureProvider).entries, isEmpty);
    },
  );

  test('the same connection can be observed in separate sessions', () async {
    final scope = container();
    addTearDown(scope.dispose);
    final notifier = scope.read(httpCaptureProvider.notifier);

    await notifier.start();
    await notifier.observe(tracker(id: 'reused'));
    await notifier.stop();
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
    'an older canonical request cannot overwrite a newer response snapshot',
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
      final startedAt = DateTime.utc(2026, 9, 26, 8);
      final request = ProtocolObservation(
        sessionId: sessionId,
        kind: 'http1',
        observedBytes: 64,
        http: const HttpProtocolObservation(
          method: 'GET',
          target: '/race',
          version: 'HTTP/1.1',
          host: 'service.example',
          headersComplete: true,
        ),
      );
      final responsePresence = <bool>[];
      final subscription = scope.listen<HttpCaptureState>(httpCaptureProvider, (
        _,
        next,
      ) {
        if (next.entries case [final entry]) {
          responsePresence.add(entry.httpResponseObservation != null);
        }
      });
      addTearDown(subscription.close);

      final initialFuture = notifier.observe(
        tracker(
          id: 'canonical-race',
          host: '',
          port: '18080',
          start: startedAt,
          observation: request,
        ),
      );
      final responseFuture = notifier.observe(
        tracker(
          id: 'canonical-race',
          host: '',
          port: '18080',
          start: startedAt,
          observation: ProtocolObservation(
            sessionId: sessionId,
            kind: 'http1',
            observedBytes: 64,
            http: request.http,
            httpResponse: const HttpResponseProtocolObservation(
              version: 'HTTP/1.1',
              statusCode: 201,
              headersComplete: true,
              observedBytes: 48,
            ),
          ),
        ),
      );
      await Future.wait([initialFuture, responseFuture]);

      final entries = scope.read(httpCaptureProvider).entries;
      expect(entries, hasLength(1));
      expect(entries.single.httpResponseObservation?.statusCode, 201);
      final firstResponse = responsePresence.indexOf(true);
      expect(firstResponse, isNonNegative);
      expect(
        responsePresence.skip(firstResponse),
        everyElement(isTrue),
        reason:
            'persistence must not roll a response snapshot back to request-only',
      );
    },
  );

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
      expect(optimistic.id, 1);
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

  test('capture session toggles the Core passive observer', () async {
    final calls = <({bool enabled, String sessionId})>[];
    final scope = container(
      coreStatus: CoreStatus.connected,
      coreControl: (enabled, sessionId) async {
        calls.add((enabled: enabled, sessionId: sessionId));
        return enabled;
      },
    );
    addTearDown(scope.dispose);
    final notifier = scope.read(httpCaptureProvider.notifier);

    await notifier.start();
    expect(scope.read(httpCaptureProvider).coreObserverActive, isTrue);
    final sessionId = scope.read(httpCaptureProvider).sessionId;
    expect(calls, [(enabled: true, sessionId: sessionId)]);

    await notifier.stop();
    expect(scope.read(httpCaptureProvider).coreObserverActive, isFalse);
    expect(calls, [
      (enabled: true, sessionId: sessionId),
      (enabled: false, sessionId: ''),
    ]);
    expect(
      scope.read(logbookProvider).single.details['coreObserverActive'],
      isTrue,
    );
  });

  test('a late enable is serialized before the final disable', () async {
    final enableResult = Completer<bool>();
    final calls = <({bool enabled, String sessionId})>[];
    final scope = container(
      coreStatus: CoreStatus.connected,
      coreControl: (enabled, sessionId) {
        calls.add((enabled: enabled, sessionId: sessionId));
        return enabled ? enableResult.future : Future<bool>.value(false);
      },
    );
    addTearDown(scope.dispose);
    final notifier = scope.read(httpCaptureProvider.notifier);

    final start = notifier.start();
    while (calls.isEmpty) {
      await Future<void>.delayed(Duration.zero);
    }
    final stop = notifier.stop();
    enableResult.complete(true);
    await Future.wait([start, stop]);

    expect(calls.map((call) => call.enabled), [true, false]);
    expect(calls.first.sessionId, isNotEmpty);
    expect(calls.last.sessionId, isEmpty);
    expect(scope.read(httpCaptureProvider).enabled, isFalse);
    expect(scope.read(httpCaptureProvider).coreObserverActive, isFalse);
  });

  test('stopping retries a failed Core observer disable', () async {
    var disableAttempts = 0;
    final calls = <({bool enabled, String sessionId})>[];
    final scope = container(
      coreStatus: CoreStatus.connected,
      coreControl: (enabled, sessionId) async {
        calls.add((enabled: enabled, sessionId: sessionId));
        if (enabled) {
          return true;
        }
        disableAttempts++;
        if (disableAttempts < 3) {
          throw StateError('temporary Core IPC failure');
        }
        return false;
      },
    );
    addTearDown(scope.dispose);
    final notifier = scope.read(httpCaptureProvider.notifier);

    await notifier.start();
    expect(scope.read(httpCaptureProvider).coreObserverActive, isTrue);
    await notifier.stop();

    expect(calls.map((call) => call.enabled), [true, false, false, false]);
    expect(calls.first.sessionId, isNotEmpty);
    expect(calls.skip(1).every((call) => call.sessionId.isEmpty), isTrue);
    expect(scope.read(httpCaptureProvider).enabled, isFalse);
    expect(scope.read(httpCaptureProvider).coreObserverActive, isFalse);
  });

  test('a failed disable keeps retrying until Core confirms it', () async {
    var disableAttempts = 0;
    final calls = <({bool enabled, String sessionId})>[];
    final scope = container(
      coreStatus: CoreStatus.connected,
      coreDisableRetryDelay: Duration.zero,
      coreControl: (enabled, sessionId) async {
        calls.add((enabled: enabled, sessionId: sessionId));
        if (enabled) {
          return true;
        }
        disableAttempts++;
        if (disableAttempts <= 3) {
          throw StateError('Core is temporarily unavailable');
        }
        return false;
      },
    );
    addTearDown(scope.dispose);
    final notifier = scope.read(httpCaptureProvider.notifier);

    await notifier.start();
    await notifier.stop();
    expect(scope.read(httpCaptureProvider).coreObserverActive, isTrue);

    final deadline = DateTime.now().add(const Duration(seconds: 2));
    while (scope.read(httpCaptureProvider).coreObserverActive) {
      if (DateTime.now().isAfter(deadline)) {
        fail('Core observer disable retry did not converge');
      }
      await Future<void>.delayed(Duration.zero);
    }

    expect(calls.map((call) => call.enabled), [
      true,
      false,
      false,
      false,
      false,
    ]);
    expect(calls.first.sessionId, isNotEmpty);
    expect(calls.skip(1).every((call) => call.sessionId.isEmpty), isTrue);
    expect(scope.read(httpCaptureProvider).enabled, isFalse);
  });

  test('a delayed Core observation cannot cross capture sessions', () async {
    final scope = container();
    addTearDown(scope.dispose);
    final notifier = scope.read(httpCaptureProvider.notifier);

    await notifier.start();
    final firstSession = scope.read(httpCaptureProvider).sessionId;
    await notifier.stop();
    await notifier.start();
    final secondSession = scope.read(httpCaptureProvider).sessionId;

    final stale = await notifier.observe(
      tracker(
        id: 'stale-core-observation',
        host: '',
        port: '18080',
        observation: ProtocolObservation(
          sessionId: firstSession,
          kind: 'http1',
          observedBytes: 64,
          http: const HttpProtocolObservation(
            method: 'GET',
            target: '/stale',
            version: 'HTTP/1.1',
            host: 'stale.example',
            headersComplete: true,
          ),
        ),
      ),
    );
    final current = await notifier.observe(
      tracker(
        id: 'current-core-observation',
        host: '',
        port: '18080',
        observation: ProtocolObservation(
          sessionId: secondSession,
          kind: 'http1',
          observedBytes: 64,
          http: const HttpProtocolObservation(
            method: 'GET',
            target: '/current',
            version: 'HTTP/1.1',
            host: 'current.example',
            headersComplete: true,
          ),
        ),
      ),
    );

    expect(firstSession, isNot(secondSession));
    expect(stale, isNull);
    expect(current?.connectionId, 'current-core-observation');
    expect(scope.read(httpCaptureProvider).entries, hasLength(1));
  });

  test('Core protocol metadata is retained by the capture pipeline', () async {
    const observation = ProtocolObservation(
      kind: 'http1',
      observedBytes: 96,
      http: HttpProtocolObservation(
        method: 'GET',
        target: '/health',
        version: 'HTTP/1.1',
        host: 'service.example',
        headerNames: ['host'],
        headersComplete: true,
      ),
      httpResponse: HttpResponseProtocolObservation(
        version: 'HTTP/1.1',
        statusCode: 200,
        headerNames: ['content-type'],
        headersComplete: true,
        observedBytes: 48,
        observedAfterMilliseconds: 12,
      ),
    );
    final scope = container();
    addTearDown(scope.dispose);
    final notifier = scope.read(httpCaptureProvider.notifier);
    await notifier.start();

    final captured = await notifier.observe(
      tracker(
        id: 'core-http',
        network: 'tcp',
        host: '',
        port: '18080',
        observation: observation,
      ),
    );

    expect(captured, isNotNull);
    expect(captured?.evidence, 'core-http1');
    expect(captured?.httpObservation?.target, '/health');
    expect(captured?.httpResponseObservation?.statusCode, 200);
  });
}
