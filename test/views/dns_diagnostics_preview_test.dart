import 'package:fl_clash/core/controller.dart';
import 'package:fl_clash/core/method.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/app.dart';
import 'package:fl_clash/providers/config.dart';
import 'package:fl_clash/providers/logbook.dart';
import 'package:fl_clash/state.dart';
import 'package:fl_clash/views/dns_diagnostics.dart';
import 'package:fl_clash/views/logbook.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';

import '../helpers/test_app.dart';

CoreDnsQueryResult _dnsPreviewResult({
  String name = 'api.example.com',
  String secret = 'verification=private-token',
}) {
  return CoreDnsQueryResult(
    input: name,
    name: name,
    questionName: name,
    queryType: DnsDiagnosticQueryType.txt,
    requestedResolver: DnsDiagnosticResolver.defaultResolver,
    resolver: DnsDiagnosticResolver.system,
    durationMs: 37,
    rcode: 0,
    status: 'NOERROR',
    authoritative: false,
    truncated: false,
    recursionAvailable: true,
    authenticatedData: true,
    checkingDisabled: false,
    complete: true,
    answers: [
      CoreDnsRecord(
        section: 'answer',
        name: name,
        type: 'CNAME',
        recordClass: 'IN',
        ttl: 120,
        data: 'edge.example.net',
      ),
      const CoreDnsRecord(
        section: 'answer',
        name: 'edge.example.net',
        type: 'A',
        recordClass: 'IN',
        ttl: 60,
        data: '1.1.1.1',
      ),
      CoreDnsRecord(
        section: 'answer',
        name: name,
        type: 'TXT',
        recordClass: 'IN',
        ttl: 300,
        data: secret,
      ),
    ],
    authority: const [
      CoreDnsRecord(
        section: 'authority',
        name: 'example.com',
        type: 'NS',
        recordClass: 'IN',
        ttl: 600,
        data: 'ns1.example.com',
      ),
    ],
    additional: const [
      CoreDnsRecord(
        section: 'additional',
        name: 'ns1.example.com',
        type: 'A',
        recordClass: 'IN',
        ttl: 600,
        data: '192.0.2.53',
      ),
    ],
    warnings: const ['default-resolver-unavailable'],
  );
}

Future<ProviderContainer> _pumpDnsDiagnostics(
  WidgetTester tester, {
  required Size size,
  DnsDiagnosticQueryReader? reader,
  bool runQuery = true,
}) async {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);

  final container = ProviderContainer(
    overrides: [
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
      child: TestApp(
        locale: const Locale('zh', 'CN'),
        child: DnsDiagnosticsView(
          initialName: 'api.example.com',
          initialQueryType: DnsDiagnosticQueryType.txt,
          queryReader:
              reader ??
              ({
                required name,
                required queryType,
                required resolver,
                required timeout,
              }) async => _dnsPreviewResult(name: name),
        ),
      ),
    ),
  );
  await tester.pumpAndSettle();
  if (runQuery) {
    await tester.tap(find.byKey(const ValueKey('dns-diagnostics-run')));
    await tester.pumpAndSettle();
  }
  return container;
}

void main() {
  testWidgets(
    'DNS diagnostics query renders records and keeps Logbook private',
    (tester) async {
      DnsDiagnosticQueryType? receivedType;
      DnsDiagnosticResolver? receivedResolver;
      Duration? receivedTimeout;
      const privateAnswer = 'verification=private-token';
      final container = await _pumpDnsDiagnostics(
        tester,
        size: const Size(430, 932),
        reader:
            ({
              required name,
              required queryType,
              required resolver,
              required timeout,
            }) async {
              receivedType = queryType;
              receivedResolver = resolver;
              receivedTimeout = timeout;
              return _dnsPreviewResult(name: name, secret: privateAnswer);
            },
      );

      expect(receivedType, DnsDiagnosticQueryType.txt);
      expect(receivedResolver, DnsDiagnosticResolver.defaultResolver);
      expect(receivedTimeout, const Duration(seconds: 5));
      expect(find.text('NOERROR (0)'), findsOneWidget);
      expect(find.text('edge.example.net'), findsWidgets);
      expect(find.text(privateAnswer), findsOneWidget);

      final events = container.read(logbookProvider);
      expect(events, hasLength(1));
      final event = events.single;
      expect(event.eventType, 'dns.query');
      expect(event.category, LogbookCategory.dns);
      expect(event.severity, LogbookSeverity.warning);
      expect(event.details['status'], 'completed');
      expect(event.details['answerCount'], 3);
      expect(event.details['resolver'], 'system');
      expect(event.searchText, isNot(contains(privateAnswer)));
      expect(event.details.containsKey('answers'), isFalse);
    },
  );

  testWidgets('DNS diagnostics failure records only a coarse failure kind', (
    tester,
  ) async {
    const privateError = 'private upstream response body';
    final container = await _pumpDnsDiagnostics(
      tester,
      size: const Size(430, 932),
      reader:
          ({
            required name,
            required queryType,
            required resolver,
            required timeout,
          }) async {
            throw const CoreMethodException(
              code: 'dns_query_failed',
              message: privateError,
              details: {'failureKind': 'timeout'},
            );
          },
    );

    expect(find.text('DNS 查询失败'), findsOneWidget);
    expect(find.text(privateError), findsOneWidget);
    final event = container.read(logbookProvider).single;
    expect(event.severity, LogbookSeverity.error);
    expect(event.details['status'], 'failed');
    expect(event.details['failureKind'], 'timeout');
    expect(event.searchText, isNot(contains(privateError)));
  });

  testWidgets('DNS Logbook event opens the prefilled diagnostics page', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(430, 932);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final container = ProviderContainer(
      overrides: [
        logbookPersistenceEnabledProvider.overrideWithValue(false),
        currentProfileIdProvider.overrideWithBuild((_, _) => 7),
        viewSizeProvider.overrideWithBuild((_, _) => const Size(430, 932)),
      ],
    );
    addTearDown(container.dispose);
    globalState.container = container;
    await container
        .read(logbookProvider.notifier)
        .record(
          profileId: 7,
          category: LogbookCategory.dns,
          severity: LogbookSeverity.success,
          eventType: 'dns.query',
          title: 'dns.query',
          message: 'api.example.com · TXT · 37 ms',
          details: const {
            'status': 'completed',
            'name': 'api.example.com',
            'queryType': 'TXT',
            'requestedResolver': 'system',
          },
        );

    await tester.pumpWidget(
      UncontrolledProviderScope(
        container: container,
        child: const TestApp(locale: Locale('zh', 'CN'), child: LogbookView()),
      ),
    );
    await tester.pumpAndSettle();
    expect(find.text('DNS 查询完成'), findsOneWidget);
    await tester.tap(find.text('api.example.com · TXT · 37 ms'));
    await tester.pumpAndSettle();
    await tester.tap(find.byIcon(Icons.open_in_new));
    await tester.pumpAndSettle();

    expect(find.byType(DnsDiagnosticsView), findsOneWidget);
    final field = tester.widget<TextField>(
      find.byKey(const ValueKey('dns-diagnostics-name')),
    );
    expect(field.controller?.text, 'api.example.com');
    final view = tester.widget<DnsDiagnosticsView>(
      find.byType(DnsDiagnosticsView),
    );
    expect(view.initialQueryType, DnsDiagnosticQueryType.txt);
    expect(view.initialResolver, DnsDiagnosticResolver.system);
  });

  testWidgets('DNS diagnostics mobile preview', (tester) async {
    await _pumpDnsDiagnostics(tester, size: const Size(430, 932));

    await expectLater(
      find.byType(DnsDiagnosticsView),
      matchesGoldenFile('../goldens/dns_diagnostics_mobile_preview.png'),
    );
  });

  testWidgets('DNS diagnostics desktop preview', (tester) async {
    await _pumpDnsDiagnostics(tester, size: const Size(1280, 800));

    await expectLater(
      find.byType(DnsDiagnosticsView),
      matchesGoldenFile('../goldens/dns_diagnostics_desktop_preview.png'),
    );
  });
}
