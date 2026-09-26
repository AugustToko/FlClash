import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/app.dart';
import 'package:fl_clash/providers/config.dart';
import 'package:fl_clash/providers/http_capture.dart';
import 'package:fl_clash/providers/logbook.dart';
import 'package:fl_clash/state.dart';
import 'package:fl_clash/views/http_capture.dart';
import 'package:fl_clash/views/logbook.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';

import '../helpers/test_app.dart';

HttpCaptureEntry _entry({
  required int id,
  required HttpCaptureProtocol protocol,
  required String evidence,
  required String host,
  required int port,
  required String process,
  required String rule,
  required List<String> chains,
  int minutesAgo = 0,
  int upload = 0,
  int download = 0,
  String network = 'tcp',
  int? profileId = 7,
  ProtocolObservation? observation,
}) {
  final observedAt = DateTime(
    2026,
    9,
    25,
    18,
    30,
  ).subtract(Duration(minutes: minutesAgo));
  return HttpCaptureEntry(
    id: id,
    connectionId: 'connection-$id',
    sessionId: 'preview-session',
    profileId: profileId,
    startedAt: observedAt.subtract(const Duration(milliseconds: 42)),
    observedAt: observedAt,
    protocol: protocol,
    evidence: evidence,
    network: network,
    host: host,
    destinationIP: switch (id) {
      1 => '104.18.12.123',
      2 => '142.250.70.14',
      3 => '1.1.1.1',
      _ => '203.0.113.10',
    },
    destinationPort: port,
    sourceIP: '10.0.0.2',
    sourcePort: 52000 + id,
    process: process,
    processPath: '/data/app/$process/base.apk',
    uid: 10000 + id,
    rule: rule,
    rulePayload: host,
    chains: chains,
    upload: upload,
    download: download,
    remoteDestination: '',
    observation: observation,
  );
}

List<HttpCaptureEntry> _previewEntries() => [
  _entry(
    id: 1,
    protocol: HttpCaptureProtocol.tls,
    evidence: 'core-tls-client-hello',
    host: 'api.openai.com',
    port: 443,
    process: 'com.openai.chatgpt',
    rule: 'RuleSet',
    chains: const ['OpenAI', '香港自动选择', 'HK-01'],
    minutesAgo: 1,
    upload: 12890,
    download: 486210,
    observation: const ProtocolObservation(
      kind: 'tls-client-hello',
      observedBytes: 312,
      tls: TlsClientHelloObservation(
        serverName: 'api.openai.com',
        alpn: ['h2', 'http/1.1'],
        legacyVersion: 'TLS 1.2',
        supportedVersions: ['TLS 1.3', 'TLS 1.2'],
        encryptedClientHello: true,
        clientHelloComplete: true,
      ),
    ),
  ),
  _entry(
    id: 2,
    protocol: HttpCaptureProtocol.quic,
    evidence: 'known-quic-port',
    host: 'www.youtube.com',
    port: 443,
    process: 'com.google.android.youtube',
    rule: 'DomainSuffix',
    chains: const ['Streaming', 'SG-02'],
    minutesAgo: 3,
    upload: 8120,
    download: 2480000,
    network: 'udp',
  ),
  _entry(
    id: 3,
    protocol: HttpCaptureProtocol.http,
    evidence: 'core-http1',
    host: 'router.home',
    port: 80,
    process: 'com.android.chrome',
    rule: 'Domain',
    chains: const ['DIRECT'],
    minutesAgo: 5,
    upload: 1024,
    download: 6048,
    observation: const ProtocolObservation(
      kind: 'http1',
      observedBytes: 126,
      http: HttpProtocolObservation(
        method: 'GET',
        target: '/status',
        version: 'HTTP/1.1',
        host: 'router.home',
        headerNames: ['host', 'accept', 'user-agent'],
        headersComplete: true,
      ),
    ),
  ),
  _entry(
    id: 4,
    protocol: HttpCaptureProtocol.unknown,
    evidence: 'host-observed',
    host: 'telemetry.example.net',
    port: 5228,
    process: 'com.example.client',
    rule: 'Match',
    chains: const ['Proxy', 'JP-01'],
    minutesAgo: 8,
    upload: 792,
    download: 320,
    profileId: 8,
  ),
];

class _HttpCaptureLogbook extends LogbookNotifier {
  @override
  List<LogbookEvent> build() {
    final time = DateTime(2026, 9, 25, 18, 30);
    return [
      LogbookEvent(
        id: 99,
        profileId: 7,
        createdAt: time,
        updatedAt: time,
        category: LogbookCategory.network,
        severity: LogbookSeverity.success,
        eventType: 'http.capture.session',
        title: 'http.capture.session',
        message: '3 个条目 · 42000 ms',
        correlationId: 'preview-session',
        details: const {
          'status': 'completed',
          'observationOnly': true,
          'count': 3,
          'durationMs': 42000,
        },
      ),
    ];
  }

  @override
  Future<void> reload() async {}
}

class _PreviewHttpCapture extends HttpCaptureNotifier {
  @override
  HttpCaptureState build() {
    final entries = _previewEntries();
    return HttpCaptureState(
      enabled: true,
      sessionStartedAt: DateTime(2026, 9, 25, 18),
      sessionId: 'preview-session',
      coreObserverActive: true,
      entries: entries,
    );
  }

  @override
  Future<void> reload() async {}

  @override
  Future<void> start() async {
    state = state.copyWith(
      enabled: true,
      sessionStartedAt: DateTime(2026, 9, 25, 18),
      sessionId: 'preview-session',
      coreObserverActive: true,
      revision: state.revision + 1,
    );
  }

  @override
  Future<void> stop() async {
    state = state.copyWith(
      enabled: false,
      clearSessionStartedAt: true,
      sessionId: '',
      coreObserverActive: false,
      revision: state.revision + 1,
    );
  }

  void markCoreObserverStopping() {
    state = state.copyWith(
      enabled: false,
      clearSessionStartedAt: true,
      sessionId: '',
      coreObserverActive: true,
      revision: state.revision + 1,
    );
  }
}

Future<ProviderContainer> _pumpCapture(
  WidgetTester tester, {
  required Size size,
}) async {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);

  final container = ProviderContainer(
    overrides: [
      httpCaptureProvider.overrideWith(_PreviewHttpCapture.new),
      httpCapturePersistenceEnabledProvider.overrideWithValue(false),
      logbookPersistenceEnabledProvider.overrideWithValue(false),
      currentProfileIdProvider.overrideWithBuild((_, _) => 7),
      viewSizeProvider.overrideWithBuild((_, _) => size),
    ],
  );
  addTearDown(container.dispose);
  globalState.container = container;

  await tester.pumpWidget(
    UncontrolledProviderScope(
      container: container,
      child: const TestApp(
        locale: Locale('zh', 'CN'),
        child: HttpCaptureView(),
      ),
    ),
  );
  await tester.pumpAndSettle();
  return container;
}

void main() {
  testWidgets('HTTP capture declares its observation-only boundary', (
    tester,
  ) async {
    await _pumpCapture(tester, size: const Size(430, 932));

    expect(find.text('HTTP 捕获'), findsWidgets);
    expect(find.textContaining('仅在主动开启时进行被动观察'), findsOneWidget);
    expect(find.text('https://api.openai.com'), findsOneWidget);
    expect(find.textContaining('Core 已观察到 TLS ClientHello'), findsOneWidget);
    expect(find.textContaining('UNKNOWN'), findsNothing);
    expect(find.textContaining('200'), findsNothing);
  });

  testWidgets('a pending Core disable remains visible', (tester) async {
    final container = await _pumpCapture(tester, size: const Size(430, 932));
    final notifier =
        container.read(httpCaptureProvider.notifier) as _PreviewHttpCapture;

    notifier.markCoreObserverStopping();
    await tester.pumpAndSettle();

    expect(find.text('Core 观察器仍在停止中'), findsOneWidget);
    expect(find.byIcon(Icons.privacy_tip_outlined), findsOneWidget);
  });

  testWidgets('capture toggle stops and restarts the current session', (
    tester,
  ) async {
    final container = await _pumpCapture(tester, size: const Size(430, 932));

    expect(container.read(httpCaptureProvider).enabled, isTrue);
    await tester.tap(find.byKey(const ValueKey('http-capture-toggle')));
    await tester.pumpAndSettle();
    expect(container.read(httpCaptureProvider).enabled, isFalse);
    expect(find.text('已停止'), findsOneWidget);

    await tester.tap(find.byKey(const ValueKey('http-capture-toggle')));
    await tester.pumpAndSettle();
    expect(container.read(httpCaptureProvider).enabled, isTrue);
    expect(find.text('正在捕获'), findsOneWidget);
  });

  testWidgets('protocol and profile filters constrain the observation list', (
    tester,
  ) async {
    await _pumpCapture(tester, size: const Size(430, 932));

    expect(find.text('telemetry.example.net'), findsNothing);
    await tester.tap(find.text('TLS / HTTPS').last);
    await tester.pumpAndSettle();

    expect(find.text('https://api.openai.com'), findsOneWidget);
    expect(find.text('https://www.youtube.com'), findsNothing);
    expect(find.text('http://router.home'), findsNothing);

    await tester.tap(find.text('当前配置'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('全部').first);
    await tester.pumpAndSettle();
    final scrollable = find.byType(Scrollable).last;
    for (var index = 0; index < 5; index++) {
      await tester.drag(scrollable, const Offset(0, -360));
      await tester.pumpAndSettle();
    }

    expect(find.text('tcp://telemetry.example.net:5228'), findsOneWidget);
  });

  testWidgets('details keep HAR limitations explicit', (tester) async {
    await _pumpCapture(tester, size: const Size(430, 932));

    await tester.tap(find.text('https://api.openai.com'));
    await tester.pumpAndSettle();

    expect(find.textContaining('HAR 导出仍仅表示观察结果'), findsOneWidget);
    expect(find.text('api.openai.com'), findsWidgets);
    expect(find.text('h2, http/1.1'), findsOneWidget);
    expect(
      find.text('RuleSet(api.openai.com)', skipOffstage: false),
      findsOneWidget,
    );
    expect(
      find.text('OpenAI → 香港自动选择 → HK-01', skipOffstage: false),
      findsOneWidget,
    );
    expect(find.byIcon(Icons.alt_route, skipOffstage: false), findsWidgets);
  });

  testWidgets('HTTP capture Logbook event reopens the source page', (
    tester,
  ) async {
    const size = Size(430, 932);
    tester.view.physicalSize = size;
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final container = ProviderContainer(
      overrides: [
        httpCaptureProvider.overrideWith(_PreviewHttpCapture.new),
        httpCapturePersistenceEnabledProvider.overrideWithValue(false),
        logbookProvider.overrideWith(_HttpCaptureLogbook.new),
        logbookPersistenceEnabledProvider.overrideWithValue(false),
        currentProfileIdProvider.overrideWithBuild((_, _) => 7),
        viewSizeProvider.overrideWithBuild((_, _) => size),
      ],
    );
    addTearDown(container.dispose);
    globalState.container = container;

    await tester.pumpWidget(
      UncontrolledProviderScope(
        container: container,
        child: const TestApp(locale: Locale('zh', 'CN'), child: LogbookView()),
      ),
    );
    await tester.pumpAndSettle();
    expect(find.text('HTTP 捕获已停止'), findsOneWidget);

    await tester.tap(find.text('3 个条目 · 42000 ms'));
    await tester.pumpAndSettle();
    await tester.tap(find.byIcon(Icons.open_in_new));
    await tester.pumpAndSettle();

    expect(find.byType(HttpCaptureView), findsOneWidget);
  });

  testWidgets('HTTP capture mobile preview', (tester) async {
    await _pumpCapture(tester, size: const Size(430, 932));

    await expectLater(
      find.byType(HttpCaptureView),
      matchesGoldenFile('../goldens/http_capture_mobile_preview.png'),
    );
  });

  testWidgets('HTTP capture detail preview', (tester) async {
    await _pumpCapture(tester, size: const Size(430, 932));
    await tester.tap(find.text('https://api.openai.com'));
    await tester.pumpAndSettle();

    await expectLater(
      find.byType(Overlay).first,
      matchesGoldenFile('../goldens/http_capture_detail_preview.png'),
    );
  });

  testWidgets('HTTP capture HTTP/1 detail preview', (tester) async {
    await _pumpCapture(tester, size: const Size(430, 932));
    await tester.tap(find.text('HTTP').last);
    await tester.pumpAndSettle();
    await tester.tap(find.text('http://router.home'));
    await tester.pumpAndSettle();

    expect(find.text('GET'), findsOneWidget);
    expect(find.text('/status'), findsOneWidget);
    expect(find.text('host, accept, user-agent'), findsOneWidget);

    await expectLater(
      find.byType(Overlay).first,
      matchesGoldenFile('../goldens/http_capture_http1_detail_preview.png'),
    );
  });

  testWidgets('HTTP capture desktop preview', (tester) async {
    await _pumpCapture(tester, size: const Size(1280, 800));

    await expectLater(
      find.byType(HttpCaptureView),
      matchesGoldenFile('../goldens/http_capture_desktop_preview.png'),
    );
  });
}
