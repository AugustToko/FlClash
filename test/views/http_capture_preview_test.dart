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
    sessionId: 'http-capture:preview-session',
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

HttpCaptureEntry _runtimeEntry() {
  final startedAt = DateTime(2026, 9, 25, 18, 28);
  final observation = TlsInspectionRuntimeObservation.fromJson({
    'sessionId': 'http-capture:preview-session',
    'connectionId': '0123456789abcdef0123456789abcdef',
    'runtimeId': 'abcdef0123456789abcdef0123456789',
    'host': 'secure.example.com',
    'state': 'completed',
    'startedAt': startedAt.toUtc().toIso8601String(),
    'completedAt': startedAt
        .add(const Duration(seconds: 3))
        .toUtc()
        .toIso8601String(),
    'downstreamTlsVersion': 'TLS 1.3',
    'upstreamTlsVersion': 'TLS 1.2',
    'alpn': 'http/1.1',
    'uploaded': 2048,
    'downloaded': 8192,
    'httpTransactionsTruncated': true,
    'httpTransactions': [
      {
        'sequence': 1,
        'requestObservedAfterMilliseconds': 8,
        'request': {
          'method': 'GET',
          'target': '/items',
          'version': 'HTTP/1.1',
          'host': 'secure.example.com',
          'headerNames': ['host', 'authorization', 'accept'],
          'headersComplete': true,
        },
        'response': {
          'version': 'HTTP/1.1',
          'statusCode': 200,
          'headerNames': ['content-type', 'set-cookie'],
          'headersComplete': true,
          'observedBytes': 112,
          'observedAfterMilliseconds': 36,
        },
      },
      {
        'sequence': 2,
        'requestObservedAfterMilliseconds': 64,
        'request': {
          'method': 'POST',
          'target': '/items/next',
          'version': 'HTTP/1.1',
          'host': 'secure.example.com',
          'headerNames': ['host', 'content-length', 'content-type'],
          'headersComplete': true,
        },
        'response': {
          'version': 'HTTP/1.1',
          'statusCode': 204,
          'informationalStatusCodes': [103],
          'headerNames': ['x-request-id'],
          'headersComplete': true,
          'observedBytes': 72,
          'observedAfterMilliseconds': 91,
        },
      },
    ],
  });
  return HttpCaptureEntry.fromInspectionRuntime(
    id: 5,
    observation: observation,
    profileId: 7,
    observedAt: startedAt,
  );
}

HttpCaptureEntry _truncatedRuntimeEntryWithoutTransactions() {
  final startedAt = DateTime(2026, 9, 25, 18, 27);
  return HttpCaptureEntry.fromInspectionRuntime(
    id: 6,
    observation: TlsInspectionRuntimeObservation.fromJson({
      'sessionId': 'http-capture:preview-session',
      'connectionId': '11111111111111111111111111111111',
      'runtimeId': 'abcdef0123456789abcdef0123456789',
      'host': 'broken.example.com',
      'state': 'completed',
      'startedAt': startedAt.toUtc().toIso8601String(),
      'completedAt': startedAt
          .add(const Duration(seconds: 1))
          .toUtc()
          .toIso8601String(),
      'downstreamTlsVersion': 'TLS 1.3',
      'upstreamTlsVersion': 'TLS 1.3',
      'alpn': 'http/1.1',
      'uploaded': 32,
      'downloaded': 64,
      'httpTransactionsTruncated': true,
    }),
    profileId: 7,
    observedAt: startedAt,
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
  _runtimeEntry(),
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
      httpResponse: HttpResponseProtocolObservation(
        version: 'HTTP/1.1',
        statusCode: 200,
        informationalStatusCodes: [103],
        headerNames: ['content-type', 'cache-control', 'server'],
        headersComplete: true,
        observedBytes: 118,
        observedAfterMilliseconds: 35,
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
        correlationId: 'http-capture:preview-session',
        details: const {
          'status': 'completed',
          'metadataOnly': true,
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
  final List<HttpCaptureEntry>? _entries;

  _PreviewHttpCapture({List<HttpCaptureEntry>? entries}) : _entries = entries;

  @override
  HttpCaptureState build() {
    final entries = _entries ?? _previewEntries();
    return HttpCaptureState(
      enabled: true,
      sessionStartedAt: DateTime(2026, 9, 25, 18),
      sessionId: 'http-capture:preview-session',
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
      sessionId: 'http-capture:preview-session',
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
    expect(find.textContaining('选择性捕获会组合'), findsOneWidget);
    expect(find.text('https://api.openai.com'), findsOneWidget);
    expect(find.textContaining('Core 已观察到 TLS ClientHello'), findsOneWidget);
    expect(find.textContaining('UNKNOWN'), findsNothing);
    expect(find.textContaining('中继载荷只经过内存'), findsOneWidget);
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

    final target = find.text('https://api.openai.com');
    await tester.ensureVisible(target);
    await tester.pumpAndSettle();
    await tester.tap(target);
    await tester.pumpAndSettle();

    expect(find.textContaining('HAR 导出仍仅包含元数据'), findsOneWidget);
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

  testWidgets('inspected runtime source filter and details stay explicit', (
    tester,
  ) async {
    await _pumpCapture(tester, size: const Size(430, 932));

    final sourceFilter = find.text('本地检查中继');
    await tester.ensureVisible(sourceFilter);
    await tester.pumpAndSettle();
    await tester.tap(sourceFilter);
    await tester.pumpAndSettle();
    expect(find.text('https://secure.example.com'), findsOneWidget);
    expect(find.text('https://api.openai.com'), findsNothing);
    expect(find.textContaining('GET'), findsWidgets);
    expect(find.textContaining('200'), findsWidgets);
    expect(find.textContaining('2 个事务'), findsOneWidget);
    expect(find.textContaining('事务时间线已截断'), findsOneWidget);

    final target = find.text('https://secure.example.com');
    await tester.ensureVisible(target);
    await tester.tap(target);
    await tester.pumpAndSettle();

    expect(find.textContaining('显式授权的回环 HTTPS 中继'), findsOneWidget);
    expect(find.text('本地检查中继'), findsWidgets);
    expect(find.text('HTTP/1 事务时间线', skipOffstage: false), findsOneWidget);
    expect(find.text('2 个事务', skipOffstage: false), findsWidgets);
    expect(find.text('事务 #1', skipOffstage: false), findsOneWidget);
    expect(find.text('事务 #2', skipOffstage: false), findsOneWidget);
    expect(
      find.textContaining('GET /items', skipOffstage: false),
      findsWidgets,
    );
    expect(
      find.textContaining('POST /items/next', skipOffstage: false),
      findsWidgets,
    );
    expect(find.text('200', skipOffstage: false), findsWidgets);
    expect(find.text('204', skipOffstage: false), findsWidgets);
    expect(find.text('事务时间线已截断', skipOffstage: false), findsWidgets);

    final downstreamTls = find.text('TLS 1.3', skipOffstage: false);
    final detailsList = find.byType(ListView).last;
    for (
      var index = 0;
      index < 8 && downstreamTls.evaluate().isEmpty;
      index++
    ) {
      await tester.drag(detailsList, const Offset(0, -280));
      await tester.pumpAndSettle();
    }
    expect(downstreamTls, findsOneWidget);
    expect(find.text('TLS 1.2', skipOffstage: false), findsOneWidget);
    expect(find.text('http/1.1', skipOffstage: false), findsWidgets);
  });

  testWidgets('truncated empty runtime timeline stays explicit in details', (
    tester,
  ) async {
    const size = Size(430, 932);
    tester.view.physicalSize = size;
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final container = ProviderContainer(
      overrides: [
        httpCaptureProvider.overrideWith(
          () => _PreviewHttpCapture(
            entries: [_truncatedRuntimeEntryWithoutTransactions()],
          ),
        ),
        httpCapturePersistenceEnabledProvider.overrideWithValue(false),
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
    final target = find.text('https://broken.example.com');
    await tester.ensureVisible(target);
    await tester.tap(target);
    await tester.pumpAndSettle();
    expect(find.text('HTTP/1 事务时间线', skipOffstage: false), findsOneWidget);
    expect(find.text('0 个事务', skipOffstage: false), findsOneWidget);
    expect(find.text('事务时间线已截断', skipOffstage: false), findsWidgets);
  });

  testWidgets('HTTP capture inspected-runtime list preview', (tester) async {
    await _pumpCapture(tester, size: const Size(430, 932));
    final sourceFilter = find.text('本地检查中继');
    await tester.ensureVisible(sourceFilter);
    await tester.pumpAndSettle();
    await tester.tap(sourceFilter);
    await tester.pumpAndSettle();

    await expectLater(
      find.byType(HttpCaptureView),
      matchesGoldenFile('../goldens/http_capture_runtime_list_preview.png'),
    );
  });

  testWidgets('HTTP capture inspected-runtime detail preview', (tester) async {
    await _pumpCapture(tester, size: const Size(430, 932));
    final sourceFilter = find.text('本地检查中继');
    await tester.ensureVisible(sourceFilter);
    await tester.pumpAndSettle();
    await tester.tap(sourceFilter);
    await tester.pumpAndSettle();
    final target = find.text('https://secure.example.com');
    await tester.ensureVisible(target);
    await tester.tap(target);
    await tester.pumpAndSettle();

    await expectLater(
      find.byType(Overlay).first,
      matchesGoldenFile('../goldens/http_capture_runtime_detail_preview.png'),
    );

    final detailsList = find.byType(ListView).last;
    await tester.drag(detailsList, const Offset(0, -520));
    await tester.pumpAndSettle();
    await expectLater(
      find.byType(Overlay).first,
      matchesGoldenFile('../goldens/http_capture_runtime_timeline_preview.png'),
    );
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
    final target = find.text('https://api.openai.com');
    await tester.ensureVisible(target);
    await tester.pumpAndSettle();
    await tester.tap(target);
    await tester.pumpAndSettle();

    await expectLater(
      find.byType(Overlay).first,
      matchesGoldenFile('../goldens/http_capture_detail_preview.png'),
    );
  });

  testWidgets('HTTP capture HTTP/1 detail preview', (tester) async {
    await _pumpCapture(tester, size: const Size(430, 932));
    await tester.tap(find.widgetWithText(FilterChip, 'HTTP'));
    await tester.pumpAndSettle();
    final target = find.text('http://router.home');
    for (var index = 0; index < 6 && target.evaluate().isEmpty; index++) {
      await tester.drag(find.byType(CustomScrollView), const Offset(0, -260));
      await tester.pumpAndSettle();
    }
    expect(target, findsOneWidget);
    await tester.tap(target);
    await tester.pumpAndSettle();

    expect(find.text('GET'), findsOneWidget);
    expect(find.text('/status'), findsOneWidget);
    expect(find.text('host, accept, user-agent'), findsOneWidget);
    expect(find.text('已观察响应', skipOffstage: false), findsOneWidget);
    expect(find.text('200', skipOffstage: false), findsOneWidget);
    expect(
      find.text('content-type, cache-control, server', skipOffstage: false),
      findsOneWidget,
    );
    expect(find.text('103', skipOffstage: false), findsOneWidget);

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
