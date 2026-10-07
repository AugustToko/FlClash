import 'package:certificate_trust/certificate_trust.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/app.dart';
import 'package:fl_clash/providers/tls_inspection.dart';
import 'package:fl_clash/providers/tls_inspection_runtime.dart';
import 'package:fl_clash/state.dart';
import 'package:fl_clash/views/tls_inspection.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';

import '../helpers/test_app.dart';
import '../helpers/code_preview.dart';

late TlsInspectionState _previewState;

class _PreviewTlsInspection extends TlsInspectionNotifier {
  @override
  TlsInspectionState build() => _previewState;

  @override
  Future<void> reload() async {}
}

class _PreviewTlsInspectionRuntime extends TlsInspectionRuntimeNotifier {
  @override
  TlsInspectionRuntimeState build() => const TlsInspectionRuntimeState();

  @override
  Future<void> reconcile() async {}
}

const _fingerprint =
    '8A:47:35:D9:0C:B1:5E:27:72:2F:99:18:C4:A2:70:11:'
    '84:FE:51:33:90:C8:6A:60:5B:D3:EA:79:B6:1F:42:CD';

const _generation = 'a1b2c3d4e5f607182736455463728190';
const _policyDigest =
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const _runtimeProof = 'fedcba9876543210fedcba9876543210';

TlsInspectionState _notReadyState() => const TlsInspectionState(
  authority: TlsInspectionAuthorityStatus(state: 'missing'),
);

TlsInspectionState _preparedState() => TlsInspectionState(
  rulesValidated: true,
  leafCache: TlsInspectionLeafCacheStatus(
    state: 'ready',
    ready: true,
    generation: _generation,
    authorityFingerprintSha256: _fingerprint,
    policyDigest: _policyDigest,
    entryCount: 12,
    capacity: tlsInspectionLeafCacheCapacity,
    leafValiditySeconds: tlsInspectionLeafMaxValidity.inSeconds,
    algorithm: 'ECDSA P-256 / SHA-256',
    keyStorage: 'app-data-file',
    keyPermissionsRestricted: true,
    privateKeysExported: false,
    runtimeAuthorizationPresent: true,
    runtimeProofId: _runtimeProof,
    updatedAt: DateTime.utc(2026, 9, 27, 1, 32),
    contractValid: true,
  ),
  platformTrust: const CertificateTrustStatus(
    platform: 'android',
    state: CertificateTrustState.trusted,
    store: CertificateTrustStore.user,
    installMode: CertificateInstallMode.settings,
    verificationSupported: true,
    fingerprintSha256: _fingerprint,
    platformVersion: 35,
    limitations: [
      'android-user-ca-opt-in',
      'certificate-pinning-may-block',
      'manual-settings-install-required',
    ],
  ),
  authority: TlsInspectionAuthorityStatus(
    state: 'ready',
    ready: true,
    generation: _generation,
    fingerprintSha256: _fingerprint,
    subject: 'CN=FlClash Local Inspection CA,O=FlClash',
    serialNumber: '79A4D1E27C13B002',
    notBefore: DateTime.utc(2026, 9, 27),
    notAfter: DateTime.utc(2029, 9, 26),
    createdAt: DateTime.utc(2026, 9, 27),
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
    manuallyTrustedAt: DateTime.utc(2026, 9, 27, 1, 30),
    updatedAt: DateTime.utc(2026, 9, 27, 1, 31),
    allowlist: const [
      TlsInspectionDomainRule(
        host: 'api.openai.com',
        scope: TlsInspectionRuleScope.exact,
      ),
      TlsInspectionDomainRule(
        host: 'example.com',
        scope: TlsInspectionRuleScope.subdomains,
      ),
    ],
    exclusions: const [
      TlsInspectionDomainRule(
        host: 'accounts.example.com',
        scope: TlsInspectionRuleScope.exact,
      ),
      TlsInspectionDomainRule(
        host: 'bank.example.com',
        scope: TlsInspectionRuleScope.subdomains,
      ),
    ],
  ),
);

TlsInspectionState _platformNotTrustedState() {
  final prepared = _preparedState();
  return prepared.copyWith(
    rulesValidated: false,
    leafCache: const TlsInspectionLeafCacheStatus(
      state: 'disabled',
      issue: 'policy-disabled',
    ),
    policy: prepared.policy.copyWith(prepared: false, clearManualTrust: true),
    platformTrust: const CertificateTrustStatus(
      platform: 'android',
      state: CertificateTrustState.notTrusted,
      store: CertificateTrustStore.none,
      installMode: CertificateInstallMode.settings,
      verificationSupported: true,
      fingerprintSha256: _fingerprint,
      platformVersion: 35,
      limitations: [
        'android-user-ca-opt-in',
        'certificate-pinning-may-block',
        'manual-settings-install-required',
      ],
    ),
  );
}

Future<void> _pumpPreview(
  WidgetTester tester, {
  required Size size,
  required TlsInspectionState state,
}) async {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
  _previewState = state;

  final container = ProviderContainer(
    overrides: [
      tlsInspectionProvider.overrideWith(_PreviewTlsInspection.new),
      tlsInspectionRuntimeProvider.overrideWith(
        _PreviewTlsInspectionRuntime.new,
      ),
      tlsInspectionPersistenceEnabledProvider.overrideWithValue(false),
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
        child: const TlsInspectionView(),
      ),
    ),
  );
  await tester.pumpAndSettle();
}

void main() {
  setUpAll(loadCodePreviewFonts);
  testWidgets(
    'TLS inspection foundation declares the non-decryption boundary',
    (tester) async {
      await _pumpPreview(
        tester,
        size: const Size(430, 932),
        state: _notReadyState(),
      );

      expect(find.text('本阶段只准备证书和策略控制，不会解密、拦截或改写 HTTPS 流量。'), findsOneWidget);
      expect(find.text('默认关闭'), findsOneWidget);
    },
  );

  testWidgets('TLS inspection not-ready mobile preview', (tester) async {
    await _pumpPreview(
      tester,
      size: const Size(430, 932),
      state: _notReadyState(),
    );

    await expectLater(
      find.byType(TlsInspectionView),
      matchesCodePreview('../goldens/tls_inspection_not_ready_preview.png'),
    );
  });

  testWidgets('TLS inspection Android trust setup preview', (tester) async {
    await _pumpPreview(
      tester,
      size: const Size(430, 932),
      state: _platformNotTrustedState(),
    );

    await tester.scrollUntilVisible(
      find.text('导出 CA 并打开设置'),
      420,
      scrollable: find.byType(Scrollable).first,
    );
    await tester.pumpAndSettle();

    expect(find.text('导出 CA 并打开设置'), findsOneWidget);
    expect(find.text('重新检查'), findsOneWidget);
    expect(find.textContaining('android-user-ca-opt-in'), findsNothing);
    expect(find.textContaining('应用必须显式选择信任用户安装的 CA。'), findsOneWidget);
    expect(find.textContaining('证书固定仍可能阻止检查。'), findsOneWidget);
    await expectLater(
      find.byType(TlsInspectionView),
      matchesCodePreview(
        '../goldens/tls_inspection_platform_trust_preview.png',
      ),
    );
  });

  testWidgets('TLS inspection prepared mobile preview', (tester) async {
    await _pumpPreview(
      tester,
      size: const Size(430, 932),
      state: _preparedState(),
    );

    await expectLater(
      find.byType(TlsInspectionView),
      matchesCodePreview('../goldens/tls_inspection_mobile_preview.png'),
    );
  });

  testWidgets('TLS inspection leaf certificate cache preview', (tester) async {
    await _pumpPreview(
      tester,
      size: const Size(430, 932),
      state: _preparedState(),
    );

    await tester.scrollUntilVisible(
      find.text('叶证书缓存'),
      460,
      scrollable: find.byType(Scrollable).first,
    );
    await tester.pumpAndSettle();

    expect(find.text('叶证书缓存'), findsOneWidget);
    expect(find.text('12 / 64'), findsOneWidget);
    expect(find.text('最长 24 小时'), findsOneWidget);
    await expectLater(
      find.byType(TlsInspectionView),
      matchesCodePreview('../goldens/tls_inspection_leaf_cache_preview.png'),
    );
  });

  testWidgets('TLS inspection domain policy preview', (tester) async {
    await _pumpPreview(
      tester,
      size: const Size(430, 932),
      state: _preparedState(),
    );

    await tester.scrollUntilVisible(
      find.text('检查白名单'),
      500,
      scrollable: find.byType(Scrollable).first,
    );
    await tester.pumpAndSettle();

    expect(find.text('api.openai.com'), findsOneWidget);
    expect(find.text('accounts.example.com'), findsOneWidget);
    await expectLater(
      find.byType(TlsInspectionView),
      matchesCodePreview('../goldens/tls_inspection_policy_preview.png'),
    );
  });

  testWidgets('self-test is reachable in the full safety workspace', (
    tester,
  ) async {
    await _pumpPreview(
      tester,
      size: const Size(360, 800),
      state: _preparedState(),
    );
    await tester.scrollUntilVisible(
      find.text('TLS 握手自检'),
      400,
      scrollable: find.byType(Scrollable).first,
    );
    await tester.pumpAndSettle();
    expect(find.text('TLS 握手自检').hitTestable(), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('TLS handshake integrated safety workspace preview', (
    tester,
  ) async {
    await _pumpPreview(
      tester,
      size: const Size(430, 932),
      state: _preparedState(),
    );
    await tester.scrollUntilVisible(
      find.text('TLS 握手自检'),
      400,
      scrollable: find.byType(Scrollable).first,
    );
    await tester.ensureVisible(find.byKey(const Key('tls-handshake-domain')));
    await tester.pumpAndSettle();
    expect(tester.takeException(), isNull);
    await expectLater(
      find.byType(TlsInspectionView),
      matchesCodePreview(
        '../goldens/tls_inspection_handshake_integrated_preview.png',
      ),
    );
  });

  testWidgets('TLS inspection desktop preview', (tester) async {
    await _pumpPreview(
      tester,
      size: const Size(1280, 800),
      state: _preparedState(),
    );

    await expectLater(
      find.byType(TlsInspectionView),
      matchesCodePreview('../goldens/tls_inspection_desktop_preview.png'),
    );
  });
}
