import 'dart:convert';
import 'dart:io';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/common/theme.dart';
import 'package:fl_clash/core/core.dart';
import 'package:fl_clash/core/interface.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/l10n/l10n.dart';
import 'package:fl_clash/manager/core_manager.dart';
import 'package:fl_clash/manager/status_manager.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/app.dart';
import 'package:fl_clash/providers/config.dart';
import 'package:fl_clash/providers/core.dart';
import 'package:fl_clash/providers/database.dart';
import 'package:fl_clash/providers/http_capture.dart';
import 'package:fl_clash/providers/logbook.dart';
import 'package:fl_clash/providers/state.dart';
import 'package:fl_clash/state.dart';
import 'package:material_ui/material_ui.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';
import 'package:path_provider_platform_interface/path_provider_platform_interface.dart';
import 'package:riverpod_annotation/riverpod_annotation.dart';

import '../helpers/test_profiles.dart';

class _MockCoreHandlerInterface extends Mock implements CoreHandlerInterface {}

class _FakePathProvider extends PathProviderPlatform {
  final String root;

  _FakePathProvider(this.root);

  @override
  Future<String?> getTemporaryPath() async => root;

  @override
  Future<String?> getApplicationSupportPath() async => root;

  @override
  Future<String?> getApplicationCachePath() async => root;
}

const _nullProfileSetupState = SetupState(
  profileId: null,
  profileLastUpdateDate: null,
  overwriteType: OverwriteType.standard,
  rules: [],
  proxyGroups: [],
  addedRules: [],
  script: null,
  overrideDns: false,
  dns: Dns(),
);

const _crash = CoreEvent(type: CoreEventType.crash, data: 'boom');

CoreEvent _geoUpdate({
  bool updating = false,
  bool skipped = false,
  String? error,
}) {
  return CoreEvent(
    type: CoreEventType.geoUpdate,
    data: <String, dynamic>{
      'type': 'MMDB',
      'updating': updating,
      'skipped': skipped,
      'error': error,
    },
  );
}

_MockCoreHandlerInterface _coreInterface() {
  final coreInterface = _MockCoreHandlerInterface();
  when(() => coreInterface.startLog()).thenAnswer((_) {});
  when(() => coreInterface.stopLog()).thenAnswer((_) {});
  when(
    () => coreInterface.setHttpObservationEnabled(
      any(),
      sessionId: any(named: 'sessionId'),
    ),
  ).thenAnswer(
    (invocation) async => invocation.positionalArguments.first as bool,
  );
  return coreInterface;
}

Future<ProviderContainer> _pumpCoreManager(
  WidgetTester tester,
  CoreHandlerInterface coreInterface, {
  List<Override> overrides = const [],
}) async {
  final container = ProviderContainer(
    overrides: [
      coreHandlerProvider.overrideWithValue(
        CoreController.scoped(coreInterface),
      ),
      ...overrides,
    ],
  );
  addTearDown(container.dispose);
  await tester.pumpWidget(
    UncontrolledProviderScope(
      container: container,
      child: MaterialApp(
        navigatorKey: globalState.navigatorKey,
        localizationsDelegates: const [AppLocalizations.delegate],
        supportedLocales: AppLocalizations.delegate.supportedLocales,
        builder: (context, child) {
          globalState.measure = Measure.of(context, 1);
          globalState.theme = CommonTheme.of(context, 1);
          return StatusManager(child: child!);
        },
        home: const CoreManager(child: SizedBox()),
      ),
    ),
  );
  return container;
}

// Loading.stop leaves a minDuration timer (up to 1000ms) pending after
// setupConfig resolves. Polling on the actual outcome instead of a fixed
// pump budget avoids racing it, and draining past it here keeps its
// callback from firing on a disposed container.
Future<void> _waitForSetupToSettle(
  WidgetTester tester,
  bool Function() condition,
) async {
  await tester.runAsync(() async {
    final deadline = DateTime.now().add(const Duration(seconds: 10));
    while (!condition() && DateTime.now().isBefore(deadline)) {
      await tester.pump();
      await Future<void>.delayed(const Duration(milliseconds: 5));
    }
    final drainDeadline = DateTime.now().add(
      const Duration(milliseconds: 1100),
    );
    while (DateTime.now().isBefore(drainDeadline)) {
      await tester.pump();
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
  });
}

void main() {
  late Directory profileSwitchTempDir;

  setUpAll(() async {
    registerFallbackValue(const SetupParams(selectedMap: {}, testUrl: ''));
    await AppLocalizations.load(const Locale('en'));
    profileSwitchTempDir = Directory.systemTemp.createTempSync(
      'core_manager_test',
    );
    PathProviderPlatform.instance = _FakePathProvider(
      profileSwitchTempDir.path,
    );
  });

  tearDownAll(() {
    try {
      profileSwitchTempDir.deleteSync(recursive: true);
    } catch (_) {}
  });

  testWidgets('request events feed the opt-in HTTP capture pipeline', (
    tester,
  ) async {
    final container = await _pumpCoreManager(
      tester,
      _coreInterface(),
      overrides: [
        currentProfileIdProvider.overrideWithBuild((_, _) => 7),
        httpCapturePersistenceEnabledProvider.overrideWithValue(false),
        logbookPersistenceEnabledProvider.overrideWithValue(false),
      ],
    );
    await container.read(httpCaptureProvider.notifier).start();
    final captureSessionId = container.read(httpCaptureProvider).sessionId;
    final tracker = TrackerInfo(
      id: 'capture-request',
      upload: 12,
      download: 34,
      start: DateTime.utc(2026, 9, 25, 10),
      metadata: const Metadata(
        uid: 10001,
        network: 'tcp',
        sourceIP: '10.0.0.2',
        sourcePort: '52000',
        destinationIP: '1.1.1.1',
        destinationPort: '443',
        host: 'api.example.com',
        process: 'example.app',
      ),
      chains: const ['Proxy', 'HK-01'],
      rule: 'Domain',
      rulePayload: 'api.example.com',
      observation: ProtocolObservation(
        sessionId: captureSessionId,
        kind: 'tls-client-hello',
        observedBytes: 288,
        tls: const TlsClientHelloObservation(
          serverName: 'api.example.com',
          alpn: ['h2', 'http/1.1'],
          legacyVersion: 'TLS 1.2',
          supportedVersions: ['TLS 1.3', 'TLS 1.2'],
          clientHelloComplete: true,
        ),
      ),
    );

    coreEventManager.sendEvent(
      CoreEvent(
        type: CoreEventType.request,
        data: jsonDecode(jsonEncode(tracker)),
      ),
    );
    await tester.pump();

    expect(container.read(requestsProvider), hasLength(1));
    final entries = container.read(httpCaptureProvider).entries;
    expect(entries, hasLength(1));
    expect(entries.single.connectionId, 'capture-request');
    expect(entries.single.protocol, HttpCaptureProtocol.tls);
    expect(entries.single.evidence, 'core-tls-client-hello');
    expect(entries.single.tlsObservation?.alpn, ['h2', 'http/1.1']);
    expect(entries.single.profileId, 7);
  });

  testWidgets('an active capture follows Core reconnect and disconnect', (
    tester,
  ) async {
    final coreInterface = _coreInterface();
    final container = await _pumpCoreManager(
      tester,
      coreInterface,
      overrides: [
        httpCapturePersistenceEnabledProvider.overrideWithValue(false),
        logbookPersistenceEnabledProvider.overrideWithValue(false),
      ],
    );
    final capture = container.read(httpCaptureProvider.notifier);
    await capture.start();
    expect(container.read(httpCaptureProvider).coreObserverActive, isFalse);

    container.read(coreStatusProvider.notifier).value = CoreStatus.connected;
    await tester.pump();
    await tester.pump();
    expect(container.read(httpCaptureProvider).coreObserverActive, isTrue);
    verify(
      () => coreInterface.setHttpObservationEnabled(
        true,
        sessionId: any(named: 'sessionId'),
      ),
    ).called(1);

    container.read(coreStatusProvider.notifier).value = CoreStatus.disconnected;
    await tester.pump();
    expect(container.read(httpCaptureProvider).coreObserverActive, isFalse);

    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('duplicate crash events disconnect the core only once', (
    tester,
  ) async {
    final coreInterface = _MockCoreHandlerInterface();
    when(() => coreInterface.stopLog()).thenAnswer((_) {});
    when(
      () => coreInterface.setHttpObservationEnabled(
        any(),
        sessionId: any(named: 'sessionId'),
      ),
    ).thenAnswer(
      (invocation) async => invocation.positionalArguments.first as bool,
    );
    final container = ProviderContainer(
      overrides: [
        coreHandlerProvider.overrideWithValue(
          CoreController.scoped(coreInterface),
        ),
      ],
    );
    addTearDown(container.dispose);
    await tester.pumpWidget(
      UncontrolledProviderScope(
        container: container,
        child: const MaterialApp(home: CoreManager(child: SizedBox())),
      ),
    );
    container.read(coreStatusProvider.notifier).value = CoreStatus.connected;
    final transitions = <CoreStatus>[];
    final subscription = container.listen<CoreStatus>(
      coreStatusProvider,
      (_, next) => transitions.add(next),
    );
    addTearDown(subscription.close);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);

    coreEventManager.sendEvent(_crash);
    coreEventManager.sendEvent(_crash);
    await tester.pump();

    expect(container.read(coreStatusProvider), CoreStatus.disconnected);
    expect(transitions, [CoreStatus.disconnected]);
    verifyNever(() => coreInterface.stop());

    await tester.pumpWidget(const SizedBox());
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
  });

  testWidgets('a crash while the app is visible surfaces the message', (
    tester,
  ) async {
    final coreInterface = _coreInterface();
    final container = await _pumpCoreManager(tester, coreInterface);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    container.read(coreStatusProvider.notifier).value = CoreStatus.connected;

    coreEventManager.sendEvent(_crash);
    await tester.pump();

    expect(container.read(coreStatusProvider), CoreStatus.disconnected);
    expect(find.text('boom'), findsOneWidget);

    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('a crash is ignored when the core is not connected', (
    tester,
  ) async {
    final coreInterface = _coreInterface();
    final container = await _pumpCoreManager(tester, coreInterface);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    container.read(coreStatusProvider.notifier).value = CoreStatus.connecting;
    final transitions = <CoreStatus>[];
    final subscription = container.listen<CoreStatus>(
      coreStatusProvider,
      (_, next) => transitions.add(next),
    );
    addTearDown(subscription.close);

    coreEventManager.sendEvent(_crash);
    await tester.pump();

    expect(container.read(coreStatusProvider), CoreStatus.connecting);
    expect(transitions, isEmpty);
    expect(find.text('boom'), findsNothing);

    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('the log stream follows the openLogs setting', (tester) async {
    final coreInterface = _coreInterface();
    final container = await _pumpCoreManager(tester, coreInterface);

    verify(() => coreInterface.stopLog()).called(1);
    verifyNever(() => coreInterface.startLog());

    container
        .read(appSettingProvider.notifier)
        .update((state) => state.copyWith(openLogs: true));
    await tester.pump();

    verify(() => coreInterface.startLog()).called(1);

    container
        .read(appSettingProvider.notifier)
        .update((state) => state.copyWith(openLogs: false));
    await tester.pump();

    verify(() => coreInterface.stopLog()).called(1);

    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('core logs are recorded for the logs view', (tester) async {
    final coreInterface = _coreInterface();
    final container = await _pumpCoreManager(tester, coreInterface);

    coreEventManager.sendEvent(
      const CoreEvent(
        type: CoreEventType.log,
        data: {'LogLevel': 'info', 'Payload': 'hello'},
      ),
    );
    await tester.pump();

    expect(
      container.read(logsProvider).list.map((log) => log.payload),
      contains('hello'),
    );

    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('geo events are forwarded to the geo resource action', (
    tester,
  ) async {
    final coreInterface = _coreInterface();
    final container = await _pumpCoreManager(tester, coreInterface);
    final key = GeoResource.MMDB.updatingKey;
    final subscription = container.listen<bool>(
      isUpdatingProvider(key),
      (_, _) {},
    );
    addTearDown(subscription.close);

    coreEventManager.sendEvent(_geoUpdate(updating: true));
    await tester.pump();

    expect(container.read(isUpdatingProvider(key)), isTrue);

    coreEventManager.sendEvent(_geoUpdate(error: 'background failure'));
    await tester.pump();

    expect(container.read(isUpdatingProvider(key)), isFalse);
    expect(find.text('background failure'), findsNothing);

    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('non-geo Core errors retain global notifications', (
    tester,
  ) async {
    final coreInterface = _coreInterface();
    await _pumpCoreManager(tester, coreInterface);

    coreEventManager.sendEvent(
      const CoreEvent(
        type: CoreEventType.log,
        data: {'LogLevel': 'error', 'Payload': 'core failure'},
      ),
    );
    await tester.pump();

    expect(find.text('core failure'), findsOneWidget);

    await tester.pumpWidget(const SizedBox.shrink());
  });

  group('profile switch failure', () {
    late Profile previous;
    late Profile next;
    List<Override> profileOverrides() => [
      initProvider.overrideWithBuild((_, _) => true),
      profilesProvider.overrideWith(() => TestProfiles([previous, next])),
      currentProfileIdProvider.overrideWithBuild((_, _) => previous.id),
      setupStateProvider.overrideWith((_, _) => _nullProfileSetupState),
    ];

    setUp(() {
      previous = Profile.normal(label: 'previous');
      next = Profile.normal(label: 'next');
    });

    testWidgets('keeps the selected profile when Core rejects it', (
      tester,
    ) async {
      final coreInterface = _coreInterface();
      var setupCalls = 0;
      when(() => coreInterface.setupConfig(any())).thenAnswer((_) async {
        setupCalls++;
        return 'rejected';
      });
      final container = await _pumpCoreManager(
        tester,
        coreInterface,
        overrides: profileOverrides(),
      );
      globalState.container = container;

      container.read(currentProfileIdProvider.notifier).value = next.id;
      await _waitForSetupToSettle(tester, () => setupCalls >= 1);

      expect(container.read(currentProfileIdProvider), next.id);
      expect(setupCalls, 1);

      await tester.pumpWidget(const SizedBox.shrink());
    });

    testWidgets('rapid A -> B -> C settles on C even when both are rejected', (
      tester,
    ) async {
      final coreInterface = _coreInterface();
      var setupCalls = 0;
      when(() => coreInterface.setupConfig(any())).thenAnswer((_) async {
        setupCalls++;
        return 'rejected';
      });
      final a = Profile.normal(label: 'a');
      final b = Profile.normal(label: 'b');
      final c = Profile.normal(label: 'c');
      final container = await _pumpCoreManager(
        tester,
        coreInterface,
        overrides: [
          initProvider.overrideWithBuild((_, _) => true),
          profilesProvider.overrideWith(() => TestProfiles([a, b, c])),
          currentProfileIdProvider.overrideWithBuild((_, _) => a.id),
          setupStateProvider.overrideWith((_, _) => _nullProfileSetupState),
        ],
      );
      globalState.container = container;

      container.read(currentProfileIdProvider.notifier).value = b.id;
      container.read(currentProfileIdProvider.notifier).value = c.id;
      await _waitForSetupToSettle(tester, () => setupCalls >= 2);

      expect(container.read(currentProfileIdProvider), c.id);
      expect(setupCalls, 2);

      await tester.pumpWidget(const SizedBox.shrink());
    });

    testWidgets(
      'a missing profile id recovers to a fallback without looping when '
      'the fallback is also rejected',
      (tester) async {
        final coreInterface = _coreInterface();
        var setupCalls = 0;
        when(() => coreInterface.setupConfig(any())).thenAnswer((_) async {
          setupCalls++;
          return 'rejected';
        });
        const missingId = -1;
        final container = await _pumpCoreManager(
          tester,
          coreInterface,
          overrides: [
            initProvider.overrideWithBuild((_, _) => true),
            profilesProvider.overrideWith(() => TestProfiles([previous])),
            currentProfileIdProvider.overrideWithBuild((_, _) => null),
            setupStateProvider.overrideWith((_, _) => _nullProfileSetupState),
          ],
        );
        globalState.container = container;

        container.read(currentProfileIdProvider.notifier).value = missingId;
        await _waitForSetupToSettle(
          tester,
          () => container.read(currentProfileIdProvider) == previous.id,
        );

        expect(setupCalls, lessThanOrEqualTo(3));
        expect(container.read(currentProfileIdProvider), previous.id);

        await tester.pumpWidget(const SizedBox.shrink());
      },
    );
  });
}
