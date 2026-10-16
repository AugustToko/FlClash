import 'dart:async';

import 'package:fl_clash/core/core.dart';
import 'package:fl_clash/views/dns_diagnostics.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';

import '../helpers/test_app.dart';

CoreDnsQueryResult _result({String name = 'api.example.com'}) {
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
    answers: const [
      CoreDnsRecord(
        section: 'answer',
        name: 'api.example.com',
        type: 'CNAME',
        recordClass: 'IN',
        ttl: 120,
        data: 'edge.example.net',
      ),
      CoreDnsRecord(
        section: 'answer',
        name: 'edge.example.net',
        type: 'A',
        recordClass: 'IN',
        ttl: 60,
        data: '1.1.1.1',
      ),
    ],
    authority: const [],
    additional: const [],
    warnings: const ['default-resolver-unavailable'],
  );
}

Future<void> _pump(
  WidgetTester tester, {
  required Size size,
  required DnsDiagnosticQueryReader reader,
}) async {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
  await tester.pumpWidget(
    TestApp(
      locale: const Locale('zh', 'CN'),
      wrapInProviderScope: true,
      child: DnsDiagnosticsView(
        initialName: 'api.example.com',
        initialQueryType: DnsDiagnosticQueryType.txt,
        queryReader: reader,
      ),
    ),
  );
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('runs a structured query and renders records', (tester) async {
    DnsDiagnosticQueryType? receivedType;
    DnsDiagnosticResolver? receivedResolver;
    Duration? receivedTimeout;
    await _pump(
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
            return _result(name: name);
          },
    );

    await tester.tap(find.byKey(const ValueKey('dns-diagnostics-run')));
    await tester.pumpAndSettle();

    expect(receivedType, DnsDiagnosticQueryType.txt);
    expect(receivedResolver, DnsDiagnosticResolver.defaultResolver);
    expect(receivedTimeout, const Duration(seconds: 5));
    expect(find.text('NOERROR (0)'), findsOneWidget);
    expect(find.text('edge.example.net'), findsWidgets);
    expect(find.text('1.1.1.1'), findsOneWidget);
    expect(find.text('当前 Core 解析器不可用，已改用系统 DNS'), findsOneWidget);
  });

  testWidgets('shows a structured Core failure', (tester) async {
    await _pump(
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
              message: 'resolver deadline exceeded',
              details: {'failureKind': 'timeout'},
            );
          },
    );

    await tester.tap(find.byKey(const ValueKey('dns-diagnostics-run')));
    await tester.pumpAndSettle();

    expect(find.text('DNS 查询失败'), findsOneWidget);
    expect(find.text('resolver deadline exceeded'), findsOneWidget);
  });

  testWidgets('contains an in-flight query after disposal', (tester) async {
    final completer = Completer<CoreDnsQueryResult>();
    await _pump(
      tester,
      size: const Size(430, 932),
      reader:
          ({
            required name,
            required queryType,
            required resolver,
            required timeout,
          }) => completer.future,
    );

    await tester.tap(find.byKey(const ValueKey('dns-diagnostics-run')));
    await tester.pump();
    await tester.pumpWidget(const SizedBox.shrink());
    completer.complete(_result());
    await tester.pumpAndSettle();

    expect(tester.takeException(), isNull);
  });

  testWidgets('stacks selectors on mobile and aligns them on desktop', (
    tester,
  ) async {
    Future<CoreDnsQueryResult> reader({
      required String name,
      required DnsDiagnosticQueryType queryType,
      required DnsDiagnosticResolver resolver,
      required Duration timeout,
    }) async => _result(name: name);

    await _pump(tester, size: const Size(430, 932), reader: reader);
    final typeFinder = find.byType(DropdownMenu<DnsDiagnosticQueryType>);
    final resolverFinder = find.byType(DropdownMenu<DnsDiagnosticResolver>);
    expect(
      tester.getTopLeft(typeFinder).dy,
      lessThan(tester.getTopLeft(resolverFinder).dy),
    );

    await _pump(tester, size: const Size(1280, 800), reader: reader);
    expect(
      tester.getTopLeft(typeFinder).dy,
      tester.getTopLeft(resolverFinder).dy,
    );
  });
}
