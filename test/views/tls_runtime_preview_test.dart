import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/app.dart';
import 'package:fl_clash/providers/tls_inspection.dart';
import 'package:fl_clash/providers/tls_inspection_runtime.dart';
import 'package:fl_clash/state.dart';
import 'package:fl_clash/views/tls_runtime_card.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';

import '../helpers/code_preview.dart';
import '../helpers/test_app.dart';

const _id = '0123456789abcdef0123456789abcdef';
const _generation = 'abcdef0123456789abcdef0123456789';
const _runtimeProof = 'fedcba9876543210fedcba9876543210';
const _digest =
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const _fingerprint =
    'AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:'
    'AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA';
const _password =
    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

late TlsInspectionState _foundation;
late TlsInspectionRuntimeState _runtime;

class _FoundationPreview extends TlsInspectionNotifier {
  @override
  TlsInspectionState build() => _foundation;

  @override
  Future<void> reload() async {}
}

class _RuntimePreview extends TlsInspectionRuntimeNotifier {
  @override
  TlsInspectionRuntimeState build() => _runtime;

  @override
  Future<void> reconcile() async {}

  @override
  Future<TlsInspectionRuntimeStart> start({required bool confirmed}) async {
    final access = _runningState().access!;
    state = _runningState();
    return access;
  }

  @override
  Future<void> stop({String reason = 'user'}) async {
    state = const TlsInspectionRuntimeState();
  }
}

TlsInspectionState _preparedFoundation() {
  final authority = TlsInspectionAuthorityStatus(
    state: 'ready',
    ready: true,
    generation: _generation,
    fingerprintSha256: _fingerprint,
    subject: 'CN=FlClash Local Inspection CA',
    serialNumber: '01',
    notBefore: DateTime.utc(2026, 1, 1),
    notAfter: DateTime.utc(2030, 1, 1),
    algorithm: 'ECDSA P-256 / SHA-256',
    keyStorage: 'app-data-file',
    keyPermissionsRestricted: true,
    trustState: 'unknown',
    trustCapability: 'manual-only',
    certificateFileName: 'flclash-local-inspection-ca.crt',
  );
  return TlsInspectionState(
    rulesValidated: true,
    authority: authority,
    policy: const TlsInspectionPolicy(
      prepared: true,
      acknowledgedRiskVersion: tlsInspectionRiskVersion,
      manuallyTrustedFingerprint: _fingerprint,
      allowlist: [
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
      entryCount: 4,
      capacity: tlsInspectionLeafCacheCapacity,
      leafValiditySeconds: tlsInspectionLeafMaxValidity.inSeconds,
      algorithm: 'ECDSA P-256 / SHA-256',
      keyStorage: 'app-data-file',
      keyPermissionsRestricted: true,
      privateKeysExported: false,
      runtimeAuthorizationPresent: true,
      runtimeProofId: _runtimeProof,
      updatedAt: DateTime.utc(2026, 10, 6, 12),
      contractValid: true,
    ),
  );
}

TlsInspectionRuntimeStatus _status() => TlsInspectionRuntimeStatus(
  id: _id,
  state: 'running',
  address: '127.0.0.1:32000',
  generation: _generation,
  authorityFingerprint: _fingerprint,
  policyDigest: _digest,
  runtimeProofId: _runtimeProof,
  expiresAt: DateTime.utc(2030, 1, 1, 12, 10),
  active: 2,
  accepted: 8,
  completed: 5,
  failed: 1,
  uploaded: 153600,
  downloaded: 1048576,
);

TlsInspectionRuntimeState _runningState() {
  final status = _status();
  return TlsInspectionRuntimeState(
    phase: TlsInspectionRuntimePhase.running,
    requestedId: _id,
    status: status,
    access: TlsInspectionRuntimeStart(
      status: status,
      username: 'flclash',
      password: _password,
    ),
  );
}

TlsInspectionRuntimeState _stopUnconfirmedState() {
  final running = _runningState();
  return running.copyWith(
    phase: TlsInspectionRuntimePhase.stopUnconfirmed,
    errorCode: 'runtime_stop_unconfirmed',
  );
}

Future<ProviderContainer> _pump(
  WidgetTester tester, {
  required Size size,
  required TlsInspectionState foundation,
  required TlsInspectionRuntimeState runtime,
  TextScaler? textScaler,
}) async {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
  _foundation = foundation;
  _runtime = runtime;
  final container = ProviderContainer(
    overrides: [
      tlsInspectionProvider.overrideWith(_FoundationPreview.new),
      tlsInspectionRuntimeProvider.overrideWith(_RuntimePreview.new),
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
        theme: codePreviewTheme,
        child: MediaQuery(
          data: MediaQueryData.fromView(
            tester.view,
          ).copyWith(textScaler: textScaler),
          child: Scaffold(
            appBar: AppBar(title: const Text('HTTPS 检查安全')),
            body: SingleChildScrollView(
              padding: const EdgeInsets.all(16),
              child: Center(
                child: ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 960),
                  child: const TlsInspectionRuntimeCard(),
                ),
              ),
            ),
          ),
        ),
      ),
    ),
  );
  await tester.pumpAndSettle();
  return container;
}

Future<void> _tapCopySettings(WidgetTester tester) async {
  final button = find.widgetWithText(OutlinedButton, '复制代理设置');
  await tester.ensureVisible(button);
  await tester.pumpAndSettle();
  final viewHeight =
      tester.view.physicalSize.height / tester.view.devicePixelRatio;
  final bottom = tester.getBottomRight(button).dy;
  if (bottom > viewHeight - 24) {
    await tester.drag(
      find.byType(SingleChildScrollView),
      Offset(0, -(bottom - viewHeight + 48)),
    );
    await tester.pumpAndSettle();
  }
  await tester.tap(button);
}

void main() {
  setUpAll(loadCodePreviewFonts);

  testWidgets('runtime start remains disabled before preparation', (
    tester,
  ) async {
    await _pump(
      tester,
      size: const Size(430, 932),
      foundation: const TlsInspectionState(),
      runtime: const TlsInspectionRuntimeState(),
    );
    final button = tester.widget<FilledButton>(
      find.widgetWithText(FilledButton, '启动中继'),
    );
    expect(button.onPressed, isNull);
    expect(find.text('请先完成 CA、平台信任、白名单和叶证书缓存准备。'), findsOneWidget);
  });

  testWidgets('running runtime hides and explicitly copies credentials', (
    tester,
  ) async {
    String? copied;
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    messenger.setMockMethodCallHandler(SystemChannels.platform, (call) async {
      if (call.method == 'Clipboard.setData') {
        copied = (call.arguments as Map<Object?, Object?>)['text'] as String?;
      }
      return null;
    });
    addTearDown(
      () => messenger.setMockMethodCallHandler(SystemChannels.platform, null),
    );

    await _pump(
      tester,
      size: const Size(430, 932),
      foundation: _preparedFoundation(),
      runtime: _runningState(),
    );
    expect(find.text(_password), findsNothing);
    await tester.tap(find.byTooltip('显示密码'));
    await tester.pump();
    expect(find.text(_password), findsOneWidget);
    await tester.tap(find.byTooltip('复制代理地址'));
    await tester.pump();
    expect(copied, '127.0.0.1:32000');
    await _tapCopySettings(tester);
    await tester.pumpAndSettle();
    expect(copied, contains('host=127.0.0.1'));
    expect(copied, contains('username=flclash'));
    expect(copied, contains('password=$_password'));
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    await tester.pump();
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pump();
  });

  testWidgets('clipboard write failure is contained and localized', (
    tester,
  ) async {
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    messenger.setMockMethodCallHandler(SystemChannels.platform, (call) async {
      if (call.method == 'Clipboard.setData') {
        throw PlatformException(code: 'clipboard-unavailable');
      }
      return null;
    });
    addTearDown(
      () => messenger.setMockMethodCallHandler(SystemChannels.platform, null),
    );

    await _pump(
      tester,
      size: const Size(430, 932),
      foundation: _preparedFoundation(),
      runtime: _runningState(),
    );
    await _tapCopySettings(tester);
    await tester.pump();

    expect(tester.takeException(), isNull);
    await tester.pump(const Duration(minutes: 1));
    expect(tester.takeException(), isNull);
  });

  testWidgets('copied credentials clear after one minute when unchanged', (
    tester,
  ) async {
    String? clipboard;
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    messenger.setMockMethodCallHandler(SystemChannels.platform, (call) async {
      switch (call.method) {
        case 'Clipboard.setData':
          clipboard =
              (call.arguments as Map<Object?, Object?>)['text'] as String?;
        case 'Clipboard.getData':
          return <String, Object?>{'text': clipboard};
      }
      return null;
    });
    addTearDown(
      () => messenger.setMockMethodCallHandler(SystemChannels.platform, null),
    );

    await _pump(
      tester,
      size: const Size(430, 932),
      foundation: _preparedFoundation(),
      runtime: _runningState(),
    );
    await _tapCopySettings(tester);
    await tester.pump();
    expect(clipboard, contains('password=$_password'));

    await tester.pump(const Duration(minutes: 1));
    await tester.pump();
    expect(clipboard, '');
  });

  testWidgets('backgrounding hides and clears temporary credentials', (
    tester,
  ) async {
    String? clipboard;
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    messenger.setMockMethodCallHandler(SystemChannels.platform, (call) async {
      switch (call.method) {
        case 'Clipboard.setData':
          clipboard =
              (call.arguments as Map<Object?, Object?>)['text'] as String?;
        case 'Clipboard.getData':
          return <String, Object?>{'text': clipboard};
      }
      return null;
    });
    addTearDown(
      () => messenger.setMockMethodCallHandler(SystemChannels.platform, null),
    );

    await _pump(
      tester,
      size: const Size(430, 932),
      foundation: _preparedFoundation(),
      runtime: _runningState(),
    );
    await tester.tap(find.byTooltip('显示密码'));
    await _tapCopySettings(tester);
    await tester.pump();
    expect(find.text(_password), findsOneWidget);
    expect(clipboard, contains('password=$_password'));

    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);
    await tester.pump();
    expect(find.text(_password), findsNothing);
    expect(clipboard, '');
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
    await tester.pump();
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    await tester.pump();
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pump();
  });

  testWidgets('clipboard cleanup preserves replacement content', (
    tester,
  ) async {
    String? clipboard;
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    messenger.setMockMethodCallHandler(SystemChannels.platform, (call) async {
      switch (call.method) {
        case 'Clipboard.setData':
          clipboard =
              (call.arguments as Map<Object?, Object?>)['text'] as String?;
        case 'Clipboard.getData':
          return <String, Object?>{'text': clipboard};
      }
      return null;
    });
    addTearDown(
      () => messenger.setMockMethodCallHandler(SystemChannels.platform, null),
    );

    await _pump(
      tester,
      size: const Size(430, 932),
      foundation: _preparedFoundation(),
      runtime: _runningState(),
    );
    await _tapCopySettings(tester);
    await tester.pump();
    clipboard = 'replacement';
    await tester.pump(const Duration(minutes: 1));
    await tester.pump();
    expect(clipboard, 'replacement');
  });

  testWidgets('runtime card remains usable on narrow large-text layouts', (
    tester,
  ) async {
    await _pump(
      tester,
      size: const Size(320, 800),
      foundation: _preparedFoundation(),
      runtime: _runningState(),
      textScaler: const TextScaler.linear(1.4),
    );

    expect(tester.takeException(), isNull);
    expect(find.text('复制代理设置'), findsOneWidget);
    expect(find.byTooltip('显示密码'), findsOneWidget);
    expect(find.byTooltip('复制代理地址'), findsOneWidget);
    expect(find.byTooltip('复制临时密码'), findsOneWidget);
  });

  testWidgets('TLS runtime stopped mobile preview', (tester) async {
    await _pump(
      tester,
      size: const Size(430, 932),
      foundation: _preparedFoundation(),
      runtime: const TlsInspectionRuntimeState(),
    );
    await expectLater(
      find.byType(Scaffold),
      matchesCodePreview('../goldens/tls_runtime_stopped_preview.png'),
    );
  });

  testWidgets('TLS runtime running mobile preview', (tester) async {
    await _pump(
      tester,
      size: const Size(430, 932),
      foundation: _preparedFoundation(),
      runtime: _runningState(),
    );
    await expectLater(
      find.byType(Scaffold),
      matchesCodePreview('../goldens/tls_runtime_running_preview.png'),
    );
  });

  testWidgets('TLS runtime stop-unconfirmed mobile preview', (tester) async {
    await _pump(
      tester,
      size: const Size(430, 932),
      foundation: _preparedFoundation(),
      runtime: _stopUnconfirmedState(),
    );
    await expectLater(
      find.byType(Scaffold),
      matchesCodePreview('../goldens/tls_runtime_stop_unconfirmed_preview.png'),
    );
  });

  testWidgets('TLS runtime desktop preview', (tester) async {
    await _pump(
      tester,
      size: const Size(1280, 800),
      foundation: _preparedFoundation(),
      runtime: _runningState(),
    );
    await expectLater(
      find.byType(Scaffold),
      matchesCodePreview('../goldens/tls_runtime_desktop_preview.png'),
    );
  });
}
