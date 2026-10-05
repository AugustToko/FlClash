import 'dart:async';

import 'package:fl_clash/core/core.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/tls_inspection.dart';
import 'package:fl_clash/state.dart';
import 'package:fl_clash/views/tls_handshake_card.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';

import '../helpers/test_app.dart';

const _generation = '0123456789abcdef0123456789abcdef';
const _digest =
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
final _fingerprint = List.filled(32, 'AA').join(':');
final _leafFingerprint = List.filled(32, 'BB').join(':');

TlsInspectionState _readyState() => TlsInspectionState(
  rulesValidated: true,
  authority: TlsInspectionAuthorityStatus(
    state: 'ready',
    ready: true,
    generation: _generation,
    fingerprintSha256: _fingerprint,
    subject: 'CN=FlClash Local Inspection CA,O=FlClash',
    serialNumber: '01',
    notBefore: DateTime.utc(2026, 1),
    notAfter: DateTime.utc(2029, 1),
    createdAt: DateTime.utc(2026, 1),
    algorithm: 'ECDSA P-256 / SHA-256',
    keyStorage: 'app-data-file',
    keyPermissionsRestricted: true,
    trustState: 'unknown',
    trustCapability: 'manual-only',
    certificateFileName: 'flclash-local-inspection-ca.crt',
  ),
  policy: TlsInspectionPolicy(
    prepared: true,
    acknowledgedRiskVersion: tlsInspectionRiskVersion,
    manuallyTrustedFingerprint: _fingerprint,
    allowlist: const [
      TlsInspectionDomainRule(
        host: 'example.com',
        scope: TlsInspectionRuleScope.subdomains,
      ),
    ],
  ),
  leafCache: TlsInspectionLeafCacheStatus(
    state: 'ready',
    ready: true,
    generation: _generation,
    authorityFingerprintSha256: _fingerprint,
    policyDigest: _digest,
    entryCount: 1,
    capacity: tlsInspectionLeafCacheCapacity,
    leafValiditySeconds: tlsInspectionLeafMaxValidity.inSeconds,
    algorithm: 'ECDSA P-256 / SHA-256',
    keyStorage: 'app-data-file',
    keyPermissionsRestricted: true,
    privateKeysExported: false,
    runtimeAuthorizationPresent: true,
    updatedAt: DateTime.utc(2026, 10, 5),
    contractValid: true,
  ),
);

TlsInspectionLeafCertificateStatus _leafResult(String host) {
  final now = DateTime.now().toUtc();
  return TlsInspectionLeafCertificateStatus(
    host: host,
    generation: _generation,
    authorityFingerprintSha256: _fingerprint,
    policyDigest: _digest,
    fingerprintSha256: _leafFingerprint,
    serialNumber: '0123456789abcdef',
    notBefore: now.subtract(const Duration(minutes: 5)),
    notAfter: now.add(const Duration(hours: 23)),
    algorithm: 'ECDSA P-256 / SHA-256',
    keyStorage: 'app-data-file',
    contractValid: true,
  );
}

class _HandshakeNotifier extends TlsInspectionNotifier {
  TlsInspectionState initial = _readyState();
  Completer<TlsInspectionLeafCertificateStatus>? gate;
  CoreMethodException? error;
  int calls = 0;
  bool requestedHandshake = false;

  @override
  TlsInspectionState build() => initial;

  @override
  Future<TlsInspectionLeafCertificateStatus> prepareLeafCertificate(
    String host, {
    bool verifyHandshake = false,
  }) async {
    calls++;
    requestedHandshake = verifyHandshake;
    final failure = error;
    if (failure != null) {
      throw failure;
    }
    return gate == null ? _leafResult(host) : gate!.future;
  }

  void revoke() {
    state = state.copyWith(policy: state.policy.copyWith(prepared: false));
  }
}

Future<_HandshakeNotifier> _pump(
  WidgetTester tester, {
  Size size = const Size(430, 932),
  _HandshakeNotifier? notifier,
}) async {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
  final value = notifier ?? _HandshakeNotifier();
  final container = ProviderContainer(
    overrides: [tlsInspectionProvider.overrideWith(() => value)],
  );
  addTearDown(container.dispose);
  globalState.container = container;
  await tester.pumpWidget(
    UncontrolledProviderScope(
      container: container,
      child: TestApp(
        locale: const Locale('zh', 'CN'),
        child: Scaffold(
          appBar: AppBar(title: const Text('HTTPS 检查安全')),
          body: SingleChildScrollView(
            padding: const EdgeInsets.all(16),
            child: Center(
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 960),
                child: const TlsHandshakeCard(),
              ),
            ),
          ),
        ),
      ),
    ),
  );
  await tester.pumpAndSettle();
  return value;
}

Future<void> _run(WidgetTester tester) async {
  await tester.enterText(
    find.byKey(const Key('tls-handshake-domain')),
    'api.example.com',
  );
  await tester.testTextInput.receiveAction(TextInputAction.done);
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('self-test remains disabled until safety preparation completes', (
    tester,
  ) async {
    final notifier = _HandshakeNotifier()..initial = const TlsInspectionState();
    await _pump(tester, notifier: notifier);
    await tester.enterText(
      find.byKey(const Key('tls-handshake-domain')),
      'api.example.com',
    );
    await tester.pump();
    final button = tester.widget<FilledButton>(
      find.byKey(const Key('tls-handshake-run')),
    );
    expect(button.onPressed, isNull);
    await tester.testTextInput.receiveAction(TextInputAction.done);
    await tester.pumpAndSettle();
    expect(notifier.calls, 0);
    expect(find.text('请先完成 CA、信任验证和域名白名单准备。'), findsOneWidget);
  });

  testWidgets(
    'explicit self-test shows locally verified versions and no upstream claim',
    (tester) async {
      final notifier = await _pump(tester);
      expect(notifier.initial.prepared, isTrue);
      await _run(tester);
      expect(notifier.calls, 1);
      expect(notifier.requestedHandshake, isTrue);
      expect(find.text('本次握手自检通过'), findsOneWidget);
      expect(find.text('TLS 1.2'), findsOneWidget);
      expect(find.text('TLS 1.3'), findsOneWidget);
      expect(find.textContaining('不连接目标服务器'), findsOneWidget);
      expect(find.textContaining('不等于系统或目标 App 信任该 CA'), findsOneWidget);
    },
  );

  testWidgets(
    'concurrent submit is suppressed and a pending operation stays visible',
    (tester) async {
      final gate = Completer<TlsInspectionLeafCertificateStatus>();
      final notifier = _HandshakeNotifier()..gate = gate;
      await _pump(tester, notifier: notifier);
      await tester.enterText(
        find.byKey(const Key('tls-handshake-domain')),
        'api.example.com',
      );
      await tester.testTextInput.receiveAction(TextInputAction.done);
      await tester.pump();
      expect(find.text('正在验证握手'), findsOneWidget);
      final button = tester.widget<FilledButton>(
        find.byKey(const Key('tls-handshake-run')),
      );
      expect(button.onPressed, isNull);
      expect(notifier.calls, 1);
      gate.complete(_leafResult('api.example.com'));
      await tester.pumpAndSettle();
      expect(find.text('本次握手自检通过'), findsOneWidget);
    },
  );

  testWidgets(
    'failure clears progress and never reveals raw Core exception text',
    (tester) async {
      final notifier = _HandshakeNotifier()
        ..error = const CoreMethodException(
          code: 'leaf_handshake_failed',
          message: 'private-test-secret-not-for-UI',
        );
      await _pump(tester, notifier: notifier);
      await _run(tester);
      expect(find.text('本次握手自检通过'), findsNothing);
      expect(find.textContaining('private-test-secret'), findsNothing);
      expect(find.byType(CircularProgressIndicator), findsNothing);
      expect(find.text('本地 TLS 握手验证失败，请检查 CA 和白名单后重试。'), findsOneWidget);
      expect(
        tester
            .widget<FilledButton>(find.byKey(const Key('tls-handshake-run')))
            .onPressed,
        isNotNull,
      );
    },
  );

  testWidgets('old Core is reported as unverified rather than successful', (
    tester,
  ) async {
    final notifier = _HandshakeNotifier()
      ..error = const CoreMethodException(
        code: 'leaf_handshake_unverified',
        message: 'missing proof',
      );
    await _pump(tester, notifier: notifier);
    await _run(tester);
    expect(find.textContaining('当前 Core 未确认'), findsOneWidget);
    expect(find.text('本次握手自检通过'), findsNothing);
  });

  testWidgets('revoking preparation invalidates the displayed proof', (
    tester,
  ) async {
    final notifier = await _pump(tester);
    await _run(tester);
    notifier.revoke();
    await tester.pumpAndSettle();
    expect(find.text('本次握手自检通过'), findsNothing);
    expect(find.text('该结果不再对应当前 CA 或策略，请重新验证。'), findsOneWidget);
    expect(find.text('TLS 1.3'), findsNothing);
  });

  testWidgets('editing the domain clears a previous result', (tester) async {
    await _pump(tester);
    await _run(tester);
    await tester.enterText(
      find.byKey(const Key('tls-handshake-domain')),
      'other.example.com',
    );
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('tls-handshake-result')), findsNothing);
  });

  testWidgets('disposal before a result arrives does not call setState', (
    tester,
  ) async {
    final gate = Completer<TlsInspectionLeafCertificateStatus>();
    final notifier = _HandshakeNotifier()..gate = gate;
    await _pump(tester, notifier: notifier);
    await tester.enterText(
      find.byKey(const Key('tls-handshake-domain')),
      'api.example.com',
    );
    await tester.testTextInput.receiveAction(TextInputAction.done);
    await tester.pump();
    await tester.pumpWidget(const SizedBox());
    gate.complete(_leafResult('api.example.com'));
    await tester.pumpAndSettle();
    expect(tester.takeException(), isNull);
  });

  testWidgets('TLS handshake ready mobile preview', (tester) async {
    await _pump(tester);
    await tester.enterText(
      find.byKey(const Key('tls-handshake-domain')),
      'api.example.com',
    );
    FocusManager.instance.primaryFocus?.unfocus();
    await tester.pumpAndSettle();
    await expectLater(
      find.byType(Scaffold),
      matchesGoldenFile('../goldens/tls_handshake_ready_preview.png'),
    );
  });

  testWidgets('TLS handshake verified mobile preview', (tester) async {
    await _pump(tester);
    await _run(tester);
    FocusManager.instance.primaryFocus?.unfocus();
    await tester.pumpAndSettle();
    await expectLater(
      find.byType(Scaffold),
      matchesGoldenFile('../goldens/tls_handshake_verified_preview.png'),
    );
  });

  testWidgets('TLS handshake failed mobile preview', (tester) async {
    final notifier = _HandshakeNotifier()
      ..error = const CoreMethodException(
        code: 'leaf_handshake_failed',
        message: 'test failure',
      );
    await _pump(tester, notifier: notifier);
    await _run(tester);
    FocusManager.instance.primaryFocus?.unfocus();
    await tester.pumpAndSettle();
    await expectLater(
      find.byType(Scaffold),
      matchesGoldenFile('../goldens/tls_handshake_failed_preview.png'),
    );
  });

  testWidgets('TLS handshake desktop preview', (tester) async {
    await _pump(tester, size: const Size(1280, 800));
    await _run(tester);
    FocusManager.instance.primaryFocus?.unfocus();
    await tester.pumpAndSettle();
    await expectLater(
      find.byType(Scaffold),
      matchesGoldenFile('../goldens/tls_handshake_desktop_preview.png'),
    );
  });
}
