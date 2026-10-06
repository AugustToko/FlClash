import 'dart:async';

import 'package:certificate_trust/certificate_trust.dart';
import 'package:fl_clash/core/controller.dart';
import 'package:fl_clash/core/desktop/model.dart';
import 'package:fl_clash/core/interface.dart';
import 'package:fl_clash/core/method.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/app.dart';
import 'package:fl_clash/providers/core.dart';
import 'package:fl_clash/providers/logbook.dart';
import 'package:fl_clash/providers/tls_inspection.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:riverpod/riverpod.dart';

const _fingerprintA =
    'AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA';
const _fingerprintB =
    'BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB';
const _leafFingerprint =
    'CC:CC:CC:CC:CC:CC:CC:CC:CC:CC:CC:CC:CC:CC:CC:CC:CC:CC:CC:CC:CC:CC:CC:CC:CC:CC:CC:CC:CC:CC:CC:CC';
const _leafPolicyDigest =
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const _runtimeProof = 'fedcba9876543210fedcba9876543210';
const _runtimeProofB = '0123456789abcdef0123456789abcdef';

class _MemoryPolicyStore implements TlsInspectionPolicyStore {
  TlsInspectionPolicy value;
  int writes = 0;
  bool failWrites = false;
  Completer<void>? loadGate;

  _MemoryPolicyStore([this.value = const TlsInspectionPolicy()]);

  @override
  Future<TlsInspectionPolicy> load() async {
    final gate = loadGate;
    if (gate != null) {
      await gate.future;
    }
    return value;
  }

  @override
  Future<void> save(TlsInspectionPolicy value) async {
    if (failWrites) {
      throw const TlsInspectionPolicyException(
        'policy_store_unavailable',
        'simulated write failure',
      );
    }
    this.value = TlsInspectionPolicy.fromJson(value.toJson());
    writes++;
  }
}

class _FakeTrustClient implements CertificateTrustClient {
  CertificateTrustStatus status;
  @override
  final String platform = 'android';
  @override
  final bool verificationSupported;
  CertificateInstallResult installResult;
  int checks = 0;
  int installs = 0;
  int settingsOpened = 0;
  Exception? checkError;
  Uint8List? lastCertificate;
  String lastFingerprint = '';

  _FakeTrustClient({
    this.status = const CertificateTrustStatus(),
    bool? verificationSupported,
    this.installResult = const CertificateInstallResult(
      outcome: CertificateInstallOutcome.cancelled,
    ),
  }) : verificationSupported =
           verificationSupported ?? status.verificationSupported;

  @override
  Future<CertificateTrustStatus> checkCertificate({
    required Uint8List certificateDer,
    required String fingerprintSha256,
  }) async {
    checks++;
    final error = checkError;
    if (error != null) {
      throw error;
    }
    lastCertificate = Uint8List.fromList(certificateDer);
    lastFingerprint = fingerprintSha256;
    return status;
  }

  @override
  Future<CertificateInstallResult> requestInstall({
    required Uint8List certificateDer,
    required String fingerprintSha256,
    required String displayName,
  }) async {
    installs++;
    lastCertificate = Uint8List.fromList(certificateDer);
    lastFingerprint = fingerprintSha256;
    return installResult;
  }

  @override
  Future<bool> openTrustSettings() async {
    settingsOpened++;
    return true;
  }
}

class _FoundationCoreHandler extends CoreHandlerInterface {
  String fingerprint = _fingerprintA;
  String? exportedFingerprint;
  String exportedPem =
      '-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n';
  String notBefore = '2026-09-27T00:00:00Z';
  String notAfter = '2029-09-26T00:00:00Z';
  Completer<void>? authorityGate;
  bool leafEnabled = false;
  int leafEntries = 0;
  int leafConfigureCalls = 0;
  int leafPrepareCalls = 0;
  String runtimeProof = _runtimeProof;
  String? leafResultRuntimeProof;
  bool rotateRuntimeProofAfterPrepare = false;
  Exception? leafStatusReadError;
  Map<String, Object?>? lastLeafPolicyArguments;

  Map<String, Object?> get authority => {
    'state': 'ready',
    'ready': true,
    'generation': fingerprint == _fingerprintA
        ? 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        : 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    'fingerprintSha256': fingerprint,
    'subject': 'CN=FlClash Local Inspection CA',
    'serialNumber': '01',
    'notBefore': notBefore,
    'notAfter': notAfter,
    'algorithm': 'ECDSA P-256 / SHA-256',
    'keyStorage': 'app-data-file',
    'keyPermissionsRestricted': true,
    'trustState': 'unknown',
    'trustCapability': 'manual-only',
    'certificateFileName': 'flclash-local-inspection-ca.crt',
  };

  Map<String, Object?> get leafCacheStatus => {
    'state': leafEnabled ? 'ready' : 'disabled',
    'ready': leafEnabled,
    'generation': authority['generation'],
    'authorityFingerprintSha256': fingerprint,
    'policyDigest': leafEnabled ? _leafPolicyDigest : '',
    'entryCount': leafEntries,
    'capacity': tlsInspectionLeafCacheCapacity,
    'leafValiditySeconds': tlsInspectionLeafMaxValidity.inSeconds,
    'algorithm': 'ECDSA P-256 / SHA-256',
    'keyStorage': 'app-data-file',
    'keyPermissionsRestricted': true,
    'privateKeysExported': false,
    'runtimeAuthorizationPresent': leafEnabled,
    if (leafEnabled) 'runtimeProofId': runtimeProof,
    'updatedAt': DateTime.now().toUtc().toIso8601String(),
    'issue': leafEnabled ? '' : 'policy-disabled',
  };

  Map<String, Object?> _readLeafStatus() {
    final error = leafStatusReadError;
    if (error != null) {
      throw error;
    }
    return leafCacheStatus;
  }

  Map<String, Object?> _configureLeaf(Object? arguments) {
    final value = Map<String, Object?>.from(arguments! as Map);
    leafConfigureCalls++;
    lastLeafPolicyArguments = value;
    leafEnabled = value['enabled'] as bool? ?? false;
    if (!leafEnabled) {
      leafEntries = 0;
    }
    return leafCacheStatus;
  }

  Map<String, Object?> _prepareLeaf(Object? arguments) {
    final value = Map<String, Object?>.from(arguments! as Map);
    leafPrepareCalls++;
    leafEntries = 1;
    final now = DateTime.now().toUtc();
    final proof = leafResultRuntimeProof ?? runtimeProof;
    final result = <String, Object?>{
      'host': value['host'],
      'cacheHit': leafPrepareCalls > 1,
      'generation': authority['generation'],
      'authorityFingerprintSha256': fingerprint,
      'policyDigest': _leafPolicyDigest,
      'fingerprintSha256': _leafFingerprint,
      'serialNumber': '01',
      'notBefore': now.subtract(const Duration(minutes: 1)).toIso8601String(),
      'notAfter': now.add(const Duration(hours: 23)).toIso8601String(),
      'algorithm': 'ECDSA P-256 / SHA-256',
      'keyStorage': 'app-data-file',
      'privateKeyExported': false,
    };
    if (value['verifyHandshake'] == true) {
      result.addAll({
        'handshakeVerified': true,
        'handshakeVersions': ['TLS 1.2', 'TLS 1.3'],
        'handshakeScope': 'in-memory-only',
        'handshakeAlpn': 'http/1.1',
        'handshakeDurationMs': 5,
        'runtimeProofId': proof,
      });
    }
    if (rotateRuntimeProofAfterPrepare) {
      runtimeProof = _runtimeProofB;
    }
    return result;
  }

  @override
  Future<CoreLifecycleResult> start() async => const CoreLifecycleResult(
    revision: 1,
    outcome: CoreLifecycleOutcome.applied,
  );

  @override
  Future<CoreLifecycleResult> restart() => start();

  @override
  Future<CoreLifecycleResult> stop() => start();

  @override
  Future<CoreLifecycleResult> close() => start();

  @override
  Future<T?> invokeMethod<T>({
    required CoreMethod method,
    Object? arguments,
    Duration? timeout,
  }) async {
    final gate = authorityGate;
    if (method == CoreMethod.getTlsInspectionAuthorityStatus && gate != null) {
      await gate.future;
    }
    final value = switch (method) {
      CoreMethod.getTlsInspectionAuthorityStatus ||
      CoreMethod.ensureTlsInspectionAuthority => authority,
      CoreMethod.rotateTlsInspectionAuthority => () {
        fingerprint = _fingerprintB;
        return authority;
      }(),
      CoreMethod.deleteTlsInspectionAuthority => true,
      CoreMethod.exportTlsInspectionCertificate => {
        'fileName': 'flclash-local-inspection-ca.crt',
        'pem': exportedPem,
        'fingerprintSha256': exportedFingerprint ?? fingerprint,
      },
      CoreMethod.getTlsInspectionLeafCacheStatus => _readLeafStatus(),
      CoreMethod.configureTlsInspectionLeafPolicy => _configureLeaf(arguments),
      CoreMethod.prepareTlsInspectionLeafCertificate => _prepareLeaf(arguments),
      CoreMethod.analyzeDomain => _analyze(arguments),
      _ => throw StateError('unexpected method: $method'),
    };
    return value as T;
  }

  Map<String, Object?> _analyze(Object? arguments) {
    final raw = (arguments as Map)['host'].toString().trim().toLowerCase();
    final host = raw.replaceFirst(RegExp(r'\.+$'), '');
    final isIp = RegExp(r'^\d+\.\d+\.\d+\.\d+$').hasMatch(host);
    final labels = host.split('.');
    final isCoUk = host == 'co.uk';
    final underCoUk = host.endsWith('.co.uk') && labels.length >= 3;
    final publicSuffix = isIp
        ? ''
        : isCoUk || underCoUk
        ? 'co.uk'
        : labels.isEmpty
        ? ''
        : labels.last;
    final registrable = isIp || isCoUk
        ? ''
        : underCoUk
        ? labels.sublist(labels.length - 3).join('.')
        : labels.length >= 2
        ? labels.sublist(labels.length - 2).join('.')
        : '';
    return {
      'input': raw,
      'normalizedHost': host,
      'isIP': isIp,
      'publicSuffix': publicSuffix,
      'registrableDomain': registrable,
      'icannSuffix': !isIp && publicSuffix.isNotEmpty,
    };
  }
}

void main() {
  ProviderContainer container({
    required _MemoryPolicyStore store,
    required _FoundationCoreHandler core,
    CoreStatus status = CoreStatus.connected,
    CertificateTrustClient? trustClient,
  }) {
    final value = ProviderContainer(
      overrides: [
        coreHandlerProvider.overrideWithValue(CoreController.scoped(core)),
        coreStatusProvider.overrideWithBuild((_, _) => status),
        tlsInspectionPersistenceEnabledProvider.overrideWithValue(true),
        tlsInspectionPolicyStoreProvider.overrideWithValue(store),
        if (trustClient != null)
          certificateTrustClientProvider.overrideWithValue(trustClient),
        logbookPersistenceEnabledProvider.overrideWithValue(false),
      ],
    );
    addTearDown(value.dispose);
    return value;
  }

  test('safety requirements gate preparation and exclusion wins', () async {
    final store = _MemoryPolicyStore();
    final core = _FoundationCoreHandler();
    final scope = container(store: store, core: core);
    final notifier = scope.read(tlsInspectionProvider.notifier);

    await notifier.reload();
    expect(scope.read(tlsInspectionProvider).authority.ready, isTrue);
    await expectLater(
      notifier.setPrepared(true),
      throwsA(
        isA<TlsInspectionPolicyException>().having(
          (error) => error.code,
          'code',
          'safety_requirements_incomplete',
        ),
      ),
    );

    await notifier.addRule(
      exclusion: false,
      input: 'Example.COM.',
      scope: TlsInspectionRuleScope.subdomains,
    );
    await notifier.addRule(
      exclusion: true,
      input: 'accounts.example.com',
      scope: TlsInspectionRuleScope.exact,
    );
    await notifier.acknowledgeRisk();
    await notifier.confirmManualTrust();
    await notifier.setPrepared(true);

    final state = scope.read(tlsInspectionProvider);
    expect(state.prepared, isTrue);
    expect(state.isAllowed('api.example.com'), isTrue);
    expect(state.isAllowed('accounts.example.com'), isFalse);
    expect(state.policy.allowlist.single.host, 'example.com');
    expect(store.writes, greaterThanOrEqualTo(4));
  });

  test(
    'Android platform trust cannot be replaced by manual confirmation',
    () async {
      final trust = _FakeTrustClient(
        status: const CertificateTrustStatus(
          platform: 'android',
          state: CertificateTrustState.notTrusted,
          store: CertificateTrustStore.none,
          installMode: CertificateInstallMode.settings,
          verificationSupported: true,
          fingerprintSha256: _fingerprintA,
          platformVersion: 35,
        ),
      );
      final store = _MemoryPolicyStore(
        const TlsInspectionPolicy(
          acknowledgedRiskVersion: tlsInspectionRiskVersion,
          manuallyTrustedFingerprint: _fingerprintA,
          allowlist: [
            TlsInspectionDomainRule(
              host: 'example.com',
              scope: TlsInspectionRuleScope.exact,
            ),
          ],
        ),
      );
      final scope = container(
        store: store,
        core: _FoundationCoreHandler(),
        trustClient: trust,
      );
      final notifier = scope.read(tlsInspectionProvider.notifier);

      await notifier.reload();
      final initial = scope.read(tlsInspectionProvider);
      expect(initial.manuallyTrusted, isTrue);
      expect(initial.platformTrustRequired, isTrue);
      expect(initial.platformTrusted, isFalse);
      expect(initial.trustSatisfied, isFalse);
      expect(trust.checks, 1);
      expect(trust.lastFingerprint, _fingerprintA);

      await expectLater(
        notifier.confirmManualTrust(),
        throwsA(
          isA<TlsInspectionPolicyException>().having(
            (error) => error.code,
            'code',
            'platform_trust_required',
          ),
        ),
      );
      await expectLater(
        notifier.setPrepared(true),
        throwsA(
          isA<TlsInspectionPolicyException>().having(
            (error) => error.code,
            'code',
            'safety_requirements_incomplete',
          ),
        ),
      );

      trust.status = const CertificateTrustStatus(
        platform: 'android',
        state: CertificateTrustState.trusted,
        store: CertificateTrustStore.user,
        installMode: CertificateInstallMode.settings,
        verificationSupported: true,
        fingerprintSha256: _fingerprintA,
        platformVersion: 35,
      );
      await notifier.refreshPlatformTrust();
      await notifier.setPrepared(true);

      final prepared = scope.read(tlsInspectionProvider);
      expect(prepared.platformTrusted, isTrue);
      expect(prepared.trustSatisfied, isTrue);
      expect(prepared.prepared, isTrue);
    },
  );

  test(
    'supported platform capability stays fail-closed on an incomplete status',
    () async {
      final trust = _FakeTrustClient(
        verificationSupported: true,
        status: const CertificateTrustStatus(
          platform: 'android',
          state: CertificateTrustState.unavailable,
          verificationSupported: false,
          errorCode: 'empty-result',
        ),
      );
      final scope = container(
        store: _MemoryPolicyStore(
          const TlsInspectionPolicy(
            acknowledgedRiskVersion: tlsInspectionRiskVersion,
            manuallyTrustedFingerprint: _fingerprintA,
            allowlist: [
              TlsInspectionDomainRule(
                host: 'example.com',
                scope: TlsInspectionRuleScope.exact,
              ),
            ],
          ),
        ),
        core: _FoundationCoreHandler(),
        trustClient: trust,
      );
      final notifier = scope.read(tlsInspectionProvider.notifier);

      await notifier.reload();

      final state = scope.read(tlsInspectionProvider);
      expect(state.platformTrustRequired, isTrue);
      expect(state.manuallyTrusted, isTrue);
      expect(state.trustSatisfied, isFalse);
      await expectLater(
        notifier.confirmManualTrust(),
        throwsA(
          isA<TlsInspectionPolicyException>().having(
            (error) => error.code,
            'code',
            'platform_trust_required',
          ),
        ),
      );
      await expectLater(
        notifier.setPrepared(true),
        throwsA(
          isA<TlsInspectionPolicyException>().having(
            (error) => error.code,
            'code',
            'safety_requirements_incomplete',
          ),
        ),
      );
    },
  );

  test(
    'a trusted result without verification capability stays fail-closed',
    () async {
      final trust = _FakeTrustClient(
        verificationSupported: true,
        status: const CertificateTrustStatus(
          platform: 'android',
          state: CertificateTrustState.trusted,
          store: CertificateTrustStore.user,
          installMode: CertificateInstallMode.settings,
          verificationSupported: false,
          fingerprintSha256: _fingerprintA,
        ),
      );
      final scope = container(
        store: _MemoryPolicyStore(
          const TlsInspectionPolicy(
            acknowledgedRiskVersion: tlsInspectionRiskVersion,
            allowlist: [
              TlsInspectionDomainRule(
                host: 'example.com',
                scope: TlsInspectionRuleScope.exact,
              ),
            ],
          ),
        ),
        core: _FoundationCoreHandler(),
        trustClient: trust,
      );

      await scope.read(tlsInspectionProvider.notifier).reload();

      final state = scope.read(tlsInspectionProvider);
      expect(state.platformTrust.state, CertificateTrustState.unavailable);
      expect(state.platformTrust.errorCode, 'verification-not-supported');
      expect(state.platformTrusted, isFalse);
      expect(state.trustSatisfied, isFalse);
      expect(state.prepared, isFalse);
    },
  );

  test(
    'invalid public certificate export clears stale trusted state',
    () async {
      final trust = _FakeTrustClient(
        status: const CertificateTrustStatus(
          platform: 'android',
          state: CertificateTrustState.trusted,
          store: CertificateTrustStore.user,
          installMode: CertificateInstallMode.settings,
          verificationSupported: true,
          fingerprintSha256: _fingerprintA,
        ),
      );
      final core = _FoundationCoreHandler();
      final scope = container(
        store: _MemoryPolicyStore(),
        core: core,
        trustClient: trust,
      );
      final notifier = scope.read(tlsInspectionProvider.notifier);
      await notifier.reload();
      expect(scope.read(tlsInspectionProvider).platformTrusted, isTrue);

      core.exportedPem = 'not a public certificate';
      await expectLater(
        notifier.refreshPlatformTrust(),
        throwsA(
          isA<TlsInspectionPolicyException>().having(
            (error) => error.code,
            'code',
            'authority_export_invalid',
          ),
        ),
      );

      final state = scope.read(tlsInspectionProvider);
      expect(state.platformTrustRequired, isTrue);
      expect(state.platformTrusted, isFalse);
      expect(state.platformTrust.state, CertificateTrustState.unavailable);
      expect(state.platformTrust.errorCode, 'authority_export_invalid');
    },
  );

  test(
    'a trust-check failure still exposes the current authority and policy',
    () async {
      const policy = TlsInspectionPolicy(
        prepared: true,
        acknowledgedRiskVersion: tlsInspectionRiskVersion,
        allowlist: [
          TlsInspectionDomainRule(
            host: 'example.com',
            scope: TlsInspectionRuleScope.exact,
          ),
        ],
      );
      final store = _MemoryPolicyStore(policy);
      final trust = _FakeTrustClient(
        verificationSupported: true,
        status: const CertificateTrustStatus(
          platform: 'android',
          verificationSupported: true,
        ),
      )..checkError = PlatformException(code: 'trust-store-busy');
      final scope = container(
        store: store,
        core: _FoundationCoreHandler(),
        trustClient: trust,
      );

      await scope.read(tlsInspectionProvider.notifier).reload();

      final state = scope.read(tlsInspectionProvider);
      expect(state.authority.validNow, isTrue);
      expect(state.authority.fingerprintSha256, _fingerprintA);
      expect(state.policy.prepared, isTrue);
      expect(state.prepared, isFalse);
      expect(state.platformTrust.state, CertificateTrustState.unavailable);
      expect(state.platformTrust.errorCode, 'trust-store-busy');
      expect(state.errorCode, 'trust-store-busy');
      expect(store.writes, 0);
    },
  );

  test('preparing performs a fresh platform trust check', () async {
    final trust = _FakeTrustClient(
      status: const CertificateTrustStatus(
        platform: 'android',
        state: CertificateTrustState.trusted,
        store: CertificateTrustStore.user,
        installMode: CertificateInstallMode.settings,
        verificationSupported: true,
        fingerprintSha256: _fingerprintA,
      ),
    );
    final scope = container(
      store: _MemoryPolicyStore(
        const TlsInspectionPolicy(
          acknowledgedRiskVersion: tlsInspectionRiskVersion,
          allowlist: [
            TlsInspectionDomainRule(
              host: 'example.com',
              scope: TlsInspectionRuleScope.exact,
            ),
          ],
        ),
      ),
      core: _FoundationCoreHandler(),
      trustClient: trust,
    );
    final notifier = scope.read(tlsInspectionProvider.notifier);
    await notifier.reload();
    expect(trust.checks, 1);

    trust.status = const CertificateTrustStatus(
      platform: 'android',
      state: CertificateTrustState.notTrusted,
      store: CertificateTrustStore.none,
      installMode: CertificateInstallMode.settings,
      verificationSupported: true,
      fingerprintSha256: _fingerprintA,
    );
    await expectLater(
      notifier.setPrepared(true),
      throwsA(
        isA<TlsInspectionPolicyException>().having(
          (error) => error.code,
          'code',
          'safety_requirements_incomplete',
        ),
      ),
    );

    final state = scope.read(tlsInspectionProvider);
    expect(trust.checks, 2);
    expect(state.platformTrust.state, CertificateTrustState.notTrusted);
    expect(state.platformTrusted, isFalse);
    expect(state.prepared, isFalse);
  });

  test('platform trust cannot bypass an expired authority', () async {
    final core = _FoundationCoreHandler()..notAfter = '2026-09-26T00:00:00Z';
    final trust = _FakeTrustClient(
      status: const CertificateTrustStatus(
        platform: 'android',
        state: CertificateTrustState.trusted,
        store: CertificateTrustStore.user,
        installMode: CertificateInstallMode.settings,
        verificationSupported: true,
        fingerprintSha256: _fingerprintA,
      ),
    );
    final scope = container(
      store: _MemoryPolicyStore(
        const TlsInspectionPolicy(
          prepared: true,
          acknowledgedRiskVersion: tlsInspectionRiskVersion,
          allowlist: [
            TlsInspectionDomainRule(
              host: 'example.com',
              scope: TlsInspectionRuleScope.exact,
            ),
          ],
        ),
      ),
      core: core,
      trustClient: trust,
    );

    await scope.read(tlsInspectionProvider.notifier).reload();

    final state = scope.read(tlsInspectionProvider);
    expect(state.authority.validNow, isFalse);
    expect(state.platformTrusted, isFalse);
    expect(state.trustSatisfied, isFalse);
    expect(state.prepared, isFalse);
    expect(state.policy.prepared, isFalse);
    expect(trust.checks, 0);
  });

  test('platform trust is bound to the exact current fingerprint', () async {
    final trust = _FakeTrustClient(
      status: const CertificateTrustStatus(
        platform: 'android',
        state: CertificateTrustState.trusted,
        store: CertificateTrustStore.user,
        installMode: CertificateInstallMode.settings,
        verificationSupported: true,
        fingerprintSha256: _fingerprintB,
      ),
    );
    final scope = container(
      store: _MemoryPolicyStore(),
      core: _FoundationCoreHandler(),
      trustClient: trust,
    );

    await scope.read(tlsInspectionProvider.notifier).reload();

    final state = scope.read(tlsInspectionProvider);
    expect(state.platformTrust.state, CertificateTrustState.unavailable);
    expect(state.platformTrust.errorCode, 'fingerprint-mismatch');
    expect(state.platformTrusted, isFalse);
    expect(state.trustSatisfied, isFalse);
  });

  test(
    'transient platform trust failure does not erase prepared policy',
    () async {
      final policy = TlsInspectionPolicy(
        prepared: true,
        acknowledgedRiskVersion: tlsInspectionRiskVersion,
        manuallyTrustedFingerprint: _fingerprintA,
        manuallyTrustedAt: DateTime.utc(2026, 9, 27),
        allowlist: const [
          TlsInspectionDomainRule(
            host: 'example.com',
            scope: TlsInspectionRuleScope.exact,
          ),
        ],
      );
      final store = _MemoryPolicyStore(policy);
      final trust = _FakeTrustClient(
        status: const CertificateTrustStatus(
          platform: 'android',
          state: CertificateTrustState.unavailable,
          store: CertificateTrustStore.unknown,
          installMode: CertificateInstallMode.settings,
          verificationSupported: true,
          errorCode: 'store-busy',
        ),
      );
      final core = _FoundationCoreHandler();
      final scope = container(store: store, core: core, trustClient: trust);

      await scope.read(tlsInspectionProvider.notifier).reload();

      final state = scope.read(tlsInspectionProvider);
      expect(state.policy.prepared, isTrue);
      expect(state.prepared, isFalse);
      expect(state.platformTrust.state, CertificateTrustState.unavailable);
      expect(state.leafCache.ready, isFalse);
      expect(core.leafEnabled, isFalse);
      expect(core.lastLeafPolicyArguments?['enabled'], isFalse);
      expect(store.writes, 0);
    },
  );

  test('definitive platform trust loss revokes the prepared policy', () async {
    const policy = TlsInspectionPolicy(
      prepared: true,
      acknowledgedRiskVersion: tlsInspectionRiskVersion,
      allowlist: [
        TlsInspectionDomainRule(
          host: 'example.com',
          scope: TlsInspectionRuleScope.exact,
        ),
      ],
    );
    final store = _MemoryPolicyStore(policy);
    final trust = _FakeTrustClient(
      status: const CertificateTrustStatus(
        platform: 'android',
        state: CertificateTrustState.trusted,
        store: CertificateTrustStore.user,
        installMode: CertificateInstallMode.settings,
        verificationSupported: true,
        fingerprintSha256: _fingerprintA,
        platformVersion: 35,
      ),
    );
    final scope = container(
      store: store,
      core: _FoundationCoreHandler(),
      trustClient: trust,
    );
    final notifier = scope.read(tlsInspectionProvider.notifier);
    await notifier.reload();
    expect(scope.read(tlsInspectionProvider).prepared, isTrue);
    final writesBeforeLoss = store.writes;

    trust.status = const CertificateTrustStatus(
      platform: 'android',
      state: CertificateTrustState.notTrusted,
      store: CertificateTrustStore.none,
      installMode: CertificateInstallMode.settings,
      verificationSupported: true,
      fingerprintSha256: _fingerprintA,
      platformVersion: 35,
    );
    await notifier.refreshPlatformTrust();

    final state = scope.read(tlsInspectionProvider);
    expect(state.platformTrust.state, CertificateTrustState.notTrusted);
    expect(state.policy.prepared, isFalse);
    expect(state.rulesValidated, isFalse);
    expect(state.prepared, isFalse);
    expect(store.value.prepared, isFalse);
    expect(store.writes, writesBeforeLoss + 1);
  });

  test('platform install result refreshes the effective trust state', () async {
    const trusted = CertificateTrustStatus(
      platform: 'android',
      state: CertificateTrustState.trusted,
      store: CertificateTrustStore.user,
      installMode: CertificateInstallMode.settings,
      verificationSupported: true,
      fingerprintSha256: _fingerprintA,
      platformVersion: 35,
    );
    final trust = _FakeTrustClient(
      status: const CertificateTrustStatus(
        platform: 'android',
        state: CertificateTrustState.notTrusted,
        store: CertificateTrustStore.none,
        installMode: CertificateInstallMode.settings,
        verificationSupported: true,
        fingerprintSha256: _fingerprintA,
      ),
      installResult: const CertificateInstallResult(
        outcome: CertificateInstallOutcome.installed,
        trustStatus: trusted,
      ),
    );
    final scope = container(
      store: _MemoryPolicyStore(),
      core: _FoundationCoreHandler(),
      trustClient: trust,
    );
    final notifier = scope.read(tlsInspectionProvider.notifier);
    await notifier.reload();

    final result = await notifier.requestPlatformTrustInstall();

    expect(result.outcome, CertificateInstallOutcome.installed);
    expect(trust.installs, 1);
    expect(trust.lastFingerprint, _fingerprintA);
    expect(scope.read(tlsInspectionProvider).platformTrusted, isTrue);
  });

  test(
    'an installed outcome is rejected when the current CA is not verified',
    () async {
      final trust = _FakeTrustClient(
        status: const CertificateTrustStatus(
          platform: 'android',
          state: CertificateTrustState.notTrusted,
          store: CertificateTrustStore.none,
          installMode: CertificateInstallMode.settings,
          verificationSupported: true,
          fingerprintSha256: _fingerprintA,
        ),
        installResult: const CertificateInstallResult(
          outcome: CertificateInstallOutcome.installed,
          trustStatus: CertificateTrustStatus(
            platform: 'android',
            state: CertificateTrustState.trusted,
            store: CertificateTrustStore.user,
            installMode: CertificateInstallMode.settings,
            verificationSupported: true,
            fingerprintSha256: _fingerprintB,
          ),
        ),
      );
      final scope = container(
        store: _MemoryPolicyStore(),
        core: _FoundationCoreHandler(),
        trustClient: trust,
      );
      final notifier = scope.read(tlsInspectionProvider.notifier);
      await notifier.reload();

      final result = await notifier.requestPlatformTrustInstall();

      expect(result.outcome, CertificateInstallOutcome.failed);
      expect(result.errorCode, 'trust-not-confirmed');
      expect(result.trustStatus?.state, CertificateTrustState.unavailable);
      expect(result.trustStatus?.errorCode, 'fingerprint-mismatch');
      final state = scope.read(tlsInspectionProvider);
      expect(state.platformTrusted, isFalse);
      expect(state.errorCode, 'trust-not-confirmed');
    },
  );

  test(
    'settings install outcome is rechecked instead of being assumed trusted',
    () async {
      final trust = _FakeTrustClient(
        status: const CertificateTrustStatus(
          platform: 'android',
          state: CertificateTrustState.notTrusted,
          store: CertificateTrustStore.none,
          installMode: CertificateInstallMode.settings,
          verificationSupported: true,
          fingerprintSha256: _fingerprintA,
        ),
        installResult: const CertificateInstallResult(
          outcome: CertificateInstallOutcome.settingsOpened,
        ),
      );
      final scope = container(
        store: _MemoryPolicyStore(),
        core: _FoundationCoreHandler(),
        trustClient: trust,
      );
      final notifier = scope.read(tlsInspectionProvider.notifier);
      await notifier.reload();
      final checksBeforeInstall = trust.checks;

      final result = await notifier.requestPlatformTrustInstall();

      expect(result.outcome, CertificateInstallOutcome.settingsOpened);
      expect(trust.installs, 1);
      expect(trust.checks, checksBeforeInstall + 1);
      expect(scope.read(tlsInspectionProvider).platformTrusted, isFalse);
      expect(
        scope.read(tlsInspectionProvider).platformTrust.state,
        CertificateTrustState.notTrusted,
      );
    },
  );

  test(
    'concurrent rule mutations are serialized without lost updates',
    () async {
      final scope = container(
        store: _MemoryPolicyStore(),
        core: _FoundationCoreHandler(),
      );
      final notifier = scope.read(tlsInspectionProvider.notifier);
      await notifier.reload();

      await Future.wait([
        notifier.addRule(
          exclusion: false,
          input: 'api.example.com',
          scope: TlsInspectionRuleScope.exact,
        ),
        notifier.addRule(
          exclusion: false,
          input: 'cdn.example.com',
          scope: TlsInspectionRuleScope.exact,
        ),
      ]);

      expect(
        scope
            .read(tlsInspectionProvider)
            .policy
            .allowlist
            .map((rule) => rule.host),
        ['api.example.com', 'cdn.example.com'],
      );
    },
  );

  test(
    'a mutation queued during hydration runs after the loaded snapshot',
    () async {
      final store = _MemoryPolicyStore(
        const TlsInspectionPolicy(
          allowlist: [
            TlsInspectionDomainRule(
              host: 'existing.example.com',
              scope: TlsInspectionRuleScope.exact,
            ),
          ],
        ),
      )..loadGate = Completer<void>();
      final scope = container(store: store, core: _FoundationCoreHandler());
      final notifier = scope.read(tlsInspectionProvider.notifier);
      final reload = notifier.reload();
      await Future<void>.delayed(Duration.zero);
      final mutation = notifier.addRule(
        exclusion: false,
        input: 'new.example.com',
        scope: TlsInspectionRuleScope.exact,
      );

      store.loadGate!.complete();
      await Future.wait([reload, mutation]);

      expect(
        scope
            .read(tlsInspectionProvider)
            .policy
            .allowlist
            .map((rule) => rule.host),
        ['existing.example.com', 'new.example.com'],
      );
    },
  );

  test('rotation invalidates manual trust and prepared state', () async {
    final store = _MemoryPolicyStore(
      TlsInspectionPolicy(
        prepared: true,
        acknowledgedRiskVersion: tlsInspectionRiskVersion,
        manuallyTrustedFingerprint: _fingerprintA,
        manuallyTrustedAt: DateTime.utc(2026, 9, 27),
        allowlist: const [
          TlsInspectionDomainRule(
            host: 'example.com',
            scope: TlsInspectionRuleScope.exact,
          ),
        ],
      ),
    );
    final core = _FoundationCoreHandler();
    final scope = container(store: store, core: core);
    final notifier = scope.read(tlsInspectionProvider.notifier);

    await notifier.reload();
    expect(scope.read(tlsInspectionProvider).prepared, isTrue);
    await notifier.rotateAuthority();

    final state = scope.read(tlsInspectionProvider);
    expect(state.authority.fingerprintSha256, _fingerprintB);
    expect(state.policy.prepared, isFalse);
    expect(state.policy.manuallyTrustedFingerprint, isEmpty);
    expect(state.manuallyTrusted, isFalse);
  });

  test(
    'rotation remains fail-safe when clearing the persisted policy fails',
    () async {
      final store = _MemoryPolicyStore(
        TlsInspectionPolicy(
          prepared: true,
          acknowledgedRiskVersion: tlsInspectionRiskVersion,
          manuallyTrustedFingerprint: _fingerprintA,
          manuallyTrustedAt: DateTime.utc(2026, 9, 27),
          allowlist: const [
            TlsInspectionDomainRule(
              host: 'example.com',
              scope: TlsInspectionRuleScope.exact,
            ),
          ],
        ),
      );
      final core = _FoundationCoreHandler();
      final scope = container(store: store, core: core);
      final notifier = scope.read(tlsInspectionProvider.notifier);

      await notifier.reload();
      expect(scope.read(tlsInspectionProvider).prepared, isTrue);
      store.failWrites = true;

      await expectLater(
        notifier.rotateAuthority(),
        throwsA(
          isA<TlsInspectionPolicyException>().having(
            (error) => error.code,
            'code',
            'policy_store_unavailable',
          ),
        ),
      );

      final state = scope.read(tlsInspectionProvider);
      expect(state.busy, isFalse);
      expect(state.authority.fingerprintSha256, _fingerprintB);
      expect(state.policy.prepared, isFalse);
      expect(state.policy.manuallyTrustedFingerprint, isEmpty);
      expect(state.prepared, isFalse);
      expect(state.errorCode, 'policy_store_unavailable');
    },
  );

  test(
    'policy persists across notifier restarts without certificate material',
    () async {
      final store = _MemoryPolicyStore();
      final core = _FoundationCoreHandler();
      final first = container(store: store, core: core);
      final notifier = first.read(tlsInspectionProvider.notifier);

      await notifier.reload();
      await notifier.addRule(
        exclusion: false,
        input: 'api.example.com',
        scope: TlsInspectionRuleScope.exact,
      );
      await notifier.acknowledgeRisk();
      await notifier.confirmManualTrust();
      first.dispose();

      final second = container(store: store, core: core);
      await second.read(tlsInspectionProvider.notifier).reload();
      final restored = second.read(tlsInspectionProvider);

      expect(restored.policy.allowlist.single.host, 'api.example.com');
      expect(restored.policy.riskAcknowledged, isTrue);
      expect(restored.manuallyTrusted, isTrue);
      expect(store.value.toJson().toString(), isNot(contains('PRIVATE KEY')));
      expect(store.value.toJson().toString(), isNot(contains('CERTIFICATE')));
    },
  );

  test('reload downgrades a prepared policy with stale trust', () async {
    final store = _MemoryPolicyStore(
      const TlsInspectionPolicy(
        prepared: true,
        acknowledgedRiskVersion: tlsInspectionRiskVersion,
        manuallyTrustedFingerprint: 'OLD',
        allowlist: [
          TlsInspectionDomainRule(
            host: 'example.com',
            scope: TlsInspectionRuleScope.exact,
          ),
        ],
      ),
    );
    final scope = container(store: store, core: _FoundationCoreHandler());

    await scope.read(tlsInspectionProvider.notifier).reload();

    final state = scope.read(tlsInspectionProvider);
    expect(state.policy.prepared, isFalse);
    expect(state.policy.manuallyTrustedFingerprint, isEmpty);
    expect(state.prepared, isFalse);
    expect(store.value.prepared, isFalse);
    expect(store.value.manuallyTrustedFingerprint, isEmpty);
  });

  test(
    'reload disables a prepared policy containing a public suffix',
    () async {
      final store = _MemoryPolicyStore(
        const TlsInspectionPolicy(
          prepared: true,
          acknowledgedRiskVersion: tlsInspectionRiskVersion,
          manuallyTrustedFingerprint: _fingerprintA,
          allowlist: [
            TlsInspectionDomainRule(
              host: 'co.uk',
              scope: TlsInspectionRuleScope.subdomains,
            ),
          ],
        ),
      );
      final scope = container(store: store, core: _FoundationCoreHandler());

      await scope.read(tlsInspectionProvider.notifier).reload();

      final state = scope.read(tlsInspectionProvider);
      expect(state.policy.prepared, isFalse);
      expect(state.rulesValidated, isFalse);
      expect(state.prepared, isFalse);
      expect(state.errorCode, 'policy_rule_invalid');
      expect(store.value.prepared, isFalse);
    },
  );

  test(
    'preparation revalidates persisted rules against the public suffix list',
    () async {
      final store = _MemoryPolicyStore(
        const TlsInspectionPolicy(
          acknowledgedRiskVersion: tlsInspectionRiskVersion,
          manuallyTrustedFingerprint: _fingerprintA,
          allowlist: [
            TlsInspectionDomainRule(
              host: 'co.uk',
              scope: TlsInspectionRuleScope.subdomains,
            ),
          ],
        ),
      );
      final scope = container(store: store, core: _FoundationCoreHandler());
      final notifier = scope.read(tlsInspectionProvider.notifier);
      await notifier.reload();

      await expectLater(
        notifier.setPrepared(true),
        throwsA(
          isA<TlsInspectionPolicyException>().having(
            (error) => error.code,
            'code',
            'policy_rule_invalid',
          ),
        ),
      );
      expect(scope.read(tlsInspectionProvider).prepared, isFalse);
    },
  );

  test('a disconnect wins over an in-flight authority reload', () async {
    const policy = TlsInspectionPolicy(
      prepared: true,
      acknowledgedRiskVersion: tlsInspectionRiskVersion,
      manuallyTrustedFingerprint: _fingerprintA,
      allowlist: [
        TlsInspectionDomainRule(
          host: 'example.com',
          scope: TlsInspectionRuleScope.exact,
        ),
      ],
    );
    final core = _FoundationCoreHandler()..authorityGate = Completer<void>();
    final scope = container(store: _MemoryPolicyStore(policy), core: core);
    final reload = scope.read(tlsInspectionProvider.notifier).reload();
    await Future<void>.delayed(Duration.zero);

    scope.read(coreStatusProvider.notifier).value = CoreStatus.disconnected;
    core.authorityGate!.complete();
    await reload;

    final state = scope.read(tlsInspectionProvider);
    expect(state.authority.issue, 'core-disconnected');
    expect(state.rulesValidated, isFalse);
    expect(state.prepared, isFalse);
    expect(state.policy.prepared, isTrue);
  });

  test(
    'a Core disconnect immediately makes a prepared snapshot inactive',
    () async {
      final store = _MemoryPolicyStore(
        const TlsInspectionPolicy(
          prepared: true,
          acknowledgedRiskVersion: tlsInspectionRiskVersion,
          manuallyTrustedFingerprint: _fingerprintA,
          allowlist: [
            TlsInspectionDomainRule(
              host: 'example.com',
              scope: TlsInspectionRuleScope.exact,
            ),
          ],
        ),
      );
      final scope = container(store: store, core: _FoundationCoreHandler());
      final notifier = scope.read(tlsInspectionProvider.notifier);
      await notifier.reload();
      expect(scope.read(tlsInspectionProvider).prepared, isTrue);

      scope.read(coreStatusProvider.notifier).value = CoreStatus.disconnected;
      await Future<void>.delayed(Duration.zero);

      final disconnected = scope.read(tlsInspectionProvider);
      expect(disconnected.authority.issue, 'core-disconnected');
      expect(disconnected.rulesValidated, isFalse);
      expect(disconnected.leafCache.ready, isFalse);
      expect(disconnected.leafCache.issue, 'core-disconnected');
      expect(disconnected.prepared, isFalse);
      expect(disconnected.policy.prepared, isTrue);
      expect(store.value.prepared, isTrue);
    },
  );

  test('temporary Core disconnection does not erase prepared policy', () async {
    final policy = TlsInspectionPolicy(
      prepared: true,
      acknowledgedRiskVersion: tlsInspectionRiskVersion,
      manuallyTrustedFingerprint: _fingerprintA,
      manuallyTrustedAt: DateTime.utc(2026, 9, 27),
      allowlist: const [
        TlsInspectionDomainRule(
          host: 'example.com',
          scope: TlsInspectionRuleScope.exact,
        ),
      ],
    );
    final store = _MemoryPolicyStore(policy);
    final scope = container(
      store: store,
      core: _FoundationCoreHandler(),
      status: CoreStatus.disconnected,
    );

    await scope.read(tlsInspectionProvider.notifier).reload();

    final state = scope.read(tlsInspectionProvider);
    expect(state.authority.issue, 'core-disconnected');
    expect(state.policy.prepared, isTrue);
    expect(state.policy.manuallyTrustedFingerprint, _fingerprintA);
    expect(state.leafCache.ready, isFalse);
    expect(state.leafCache.issue, 'core-disconnected');
    expect(state.prepared, isFalse);
    expect(store.writes, 0);
  });

  test(
    'platform trust refresh revokes leaf authorization before a failed check',
    () async {
      const policy = TlsInspectionPolicy(
        prepared: true,
        acknowledgedRiskVersion: tlsInspectionRiskVersion,
        allowlist: [
          TlsInspectionDomainRule(
            host: 'example.com',
            scope: TlsInspectionRuleScope.subdomains,
          ),
        ],
      );
      final core = _FoundationCoreHandler();
      final trust = _FakeTrustClient(
        status: const CertificateTrustStatus(
          platform: 'android',
          state: CertificateTrustState.trusted,
          store: CertificateTrustStore.user,
          installMode: CertificateInstallMode.settings,
          verificationSupported: true,
          fingerprintSha256: _fingerprintA,
          platformVersion: 35,
        ),
      );
      final scope = container(
        store: _MemoryPolicyStore(policy),
        core: core,
        trustClient: trust,
      );
      final notifier = scope.read(tlsInspectionProvider.notifier);
      await notifier.reload();
      expect(scope.read(tlsInspectionProvider).prepared, isTrue);
      expect(core.leafEnabled, isTrue);

      trust.checkError = PlatformException(code: 'trust-store-busy');
      await expectLater(
        notifier.refreshPlatformTrust(),
        throwsA(
          isA<PlatformException>().having(
            (error) => error.code,
            'code',
            'trust-store-busy',
          ),
        ),
      );

      final state = scope.read(tlsInspectionProvider);
      expect(core.leafEnabled, isFalse);
      expect(core.lastLeafPolicyArguments?['enabled'], isFalse);
      expect(state.leafCache.ready, isFalse);
      expect(state.prepared, isFalse);
      expect(state.policy.prepared, isTrue);
      expect(state.platformTrust.state, CertificateTrustState.unavailable);
      expect(state.errorCode, 'trust-store-busy');
    },
  );

  test(
    'prepared policy provisions the Core leaf cache and issues metadata only',
    () async {
      final core = _FoundationCoreHandler();
      final trust = _FakeTrustClient(
        verificationSupported: false,
        status: const CertificateTrustStatus(
          platform: 'linux',
          state: CertificateTrustState.unsupported,
          verificationSupported: false,
        ),
      );
      final scope = container(
        store: _MemoryPolicyStore(),
        core: core,
        trustClient: trust,
      );
      final notifier = scope.read(tlsInspectionProvider.notifier);

      await notifier.reload();
      await notifier.addRule(
        exclusion: false,
        input: 'example.com',
        scope: TlsInspectionRuleScope.subdomains,
      );
      await notifier.acknowledgeRisk();
      await notifier.confirmManualTrust();
      await notifier.setPrepared(true);

      final prepared = scope.read(tlsInspectionProvider);
      expect(prepared.prepared, isTrue);
      expect(prepared.leafCache.matchesAuthority(prepared.authority), isTrue);
      expect(core.leafEnabled, isTrue);
      expect(core.lastLeafPolicyArguments?['enabled'], isTrue);
      expect(core.lastLeafPolicyArguments?['trustSatisfied'], isTrue);
      expect(core.lastLeafPolicyArguments?['allowlist'], [
        {'host': 'example.com', 'scope': 'subdomains'},
      ]);

      final leaf = await notifier.prepareLeafCertificate('api.example.com');
      expect(leaf.host, 'api.example.com');
      expect(leaf.privateKeyExported, isFalse);
      expect(leaf.policyDigest, _leafPolicyDigest);
      expect(core.leafPrepareCalls, 1);
      expect(scope.read(tlsInspectionProvider).leafCache.entryCount, 1);

      await expectLater(
        notifier.prepareLeafCertificate('outside.example.net'),
        throwsA(
          isA<TlsInspectionPolicyException>().having(
            (error) => error.code,
            'code',
            'domain_not_allowed',
          ),
        ),
      );
      expect(core.leafPrepareCalls, 1);
    },
  );

  test('handshake proof must match the ready Core runtime', () async {
    final core = _FoundationCoreHandler();
    final trust = _FakeTrustClient(
      verificationSupported: false,
      status: const CertificateTrustStatus(
        platform: 'linux',
        state: CertificateTrustState.unsupported,
        verificationSupported: false,
      ),
    );
    final scope = container(
      store: _MemoryPolicyStore(),
      core: core,
      trustClient: trust,
    );
    final notifier = scope.read(tlsInspectionProvider.notifier);
    await notifier.reload();
    await notifier.addRule(
      exclusion: false,
      input: 'example.com',
      scope: TlsInspectionRuleScope.subdomains,
    );
    await notifier.acknowledgeRisk();
    await notifier.confirmManualTrust();
    await notifier.setPrepared(true);

    final proof = await notifier.prepareLeafCertificate(
      'api.example.com',
      verifyHandshake: true,
    );
    expect(proof.handshakeContractValid, isTrue);
    expect(proof.runtimeProofId, _runtimeProof);
    expect(scope.read(tlsInspectionProvider).prepared, isTrue);
  });

  test(
    'a leaf proof from another Core runtime is rejected and revoked',
    () async {
      final core = _FoundationCoreHandler()
        ..leafResultRuntimeProof = _runtimeProofB;
      final trust = _FakeTrustClient(
        verificationSupported: false,
        status: const CertificateTrustStatus(
          platform: 'linux',
          state: CertificateTrustState.unsupported,
          verificationSupported: false,
        ),
      );
      final scope = container(
        store: _MemoryPolicyStore(),
        core: core,
        trustClient: trust,
      );
      final notifier = scope.read(tlsInspectionProvider.notifier);
      await notifier.reload();
      await notifier.addRule(
        exclusion: false,
        input: 'example.com',
        scope: TlsInspectionRuleScope.subdomains,
      );
      await notifier.acknowledgeRisk();
      await notifier.confirmManualTrust();
      await notifier.setPrepared(true);

      await expectLater(
        notifier.prepareLeafCertificate(
          'api.example.com',
          verifyHandshake: true,
        ),
        throwsA(
          isA<TlsInspectionPolicyException>().having(
            (error) => error.code,
            'code',
            'leaf_result_invalid',
          ),
        ),
      );
      expect(core.leafEnabled, isFalse);
      expect(scope.read(tlsInspectionProvider).prepared, isFalse);
    },
  );

  test(
    'a Core restart between handshake and status confirmation is rejected',
    () async {
      final core = _FoundationCoreHandler()
        ..rotateRuntimeProofAfterPrepare = true;
      final trust = _FakeTrustClient(
        verificationSupported: false,
        status: const CertificateTrustStatus(
          platform: 'linux',
          state: CertificateTrustState.unsupported,
          verificationSupported: false,
        ),
      );
      final scope = container(
        store: _MemoryPolicyStore(),
        core: core,
        trustClient: trust,
      );
      final notifier = scope.read(tlsInspectionProvider.notifier);
      await notifier.reload();
      await notifier.addRule(
        exclusion: false,
        input: 'example.com',
        scope: TlsInspectionRuleScope.subdomains,
      );
      await notifier.acknowledgeRisk();
      await notifier.confirmManualTrust();
      await notifier.setPrepared(true);

      await expectLater(
        notifier.prepareLeafCertificate(
          'api.example.com',
          verifyHandshake: true,
        ),
        throwsA(
          isA<TlsInspectionPolicyException>().having(
            (error) => error.code,
            'code',
            'leaf_cache_invalid',
          ),
        ),
      );
      expect(core.leafEnabled, isFalse);
      expect(scope.read(tlsInspectionProvider).prepared, isFalse);
    },
  );

  test(
    'leaf status confirmation failure revokes effective preparation',
    () async {
      final core = _FoundationCoreHandler();
      final trust = _FakeTrustClient(
        verificationSupported: false,
        status: const CertificateTrustStatus(
          platform: 'linux',
          state: CertificateTrustState.unsupported,
          verificationSupported: false,
        ),
      );
      final scope = container(
        store: _MemoryPolicyStore(),
        core: core,
        trustClient: trust,
      );
      final notifier = scope.read(tlsInspectionProvider.notifier);
      await notifier.reload();
      await notifier.addRule(
        exclusion: false,
        input: 'example.com',
        scope: TlsInspectionRuleScope.subdomains,
      );
      await notifier.acknowledgeRisk();
      await notifier.confirmManualTrust();
      await notifier.setPrepared(true);
      expect(scope.read(tlsInspectionProvider).prepared, isTrue);

      core.leafStatusReadError = PlatformException(code: 'leaf-status-busy');
      await expectLater(
        notifier.prepareLeafCertificate('api.example.com'),
        throwsA(
          isA<PlatformException>().having(
            (error) => error.code,
            'code',
            'leaf-status-busy',
          ),
        ),
      );

      final state = scope.read(tlsInspectionProvider);
      expect(core.leafEnabled, isFalse);
      expect(state.leafCache.ready, isFalse);
      expect(state.prepared, isFalse);
      expect(state.policy.prepared, isTrue);
      expect(state.errorCode, 'leaf-status-busy');
    },
  );

  test(
    'certificate export must match the current verified authority',
    () async {
      final core = _FoundationCoreHandler();
      final scope = container(store: _MemoryPolicyStore(), core: core);
      final notifier = scope.read(tlsInspectionProvider.notifier);
      await notifier.reload();

      final exported = await notifier.exportCertificate();
      expect(exported.valid, isTrue);
      expect(exported.fingerprintSha256, _fingerprintA);

      core.exportedFingerprint = _fingerprintB;
      await expectLater(
        notifier.exportCertificate(),
        throwsA(
          isA<TlsInspectionPolicyException>().having(
            (error) => error.code,
            'code',
            'authority_export_invalid',
          ),
        ),
      );

      core.exportedFingerprint = _fingerprintA;
      core.exportedPem =
          '-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----';
      await expectLater(
        notifier.exportCertificate(),
        throwsA(
          isA<TlsInspectionPolicyException>().having(
            (error) => error.code,
            'code',
            'authority_export_invalid',
          ),
        ),
      );
    },
  );

  test('IP and public suffix inputs are rejected', () async {
    final scope = container(
      store: _MemoryPolicyStore(),
      core: _FoundationCoreHandler(),
    );
    final notifier = scope.read(tlsInspectionProvider.notifier);

    await expectLater(
      notifier.normalizeRule(
        input: '192.0.2.1',
        scope: TlsInspectionRuleScope.exact,
      ),
      throwsA(
        isA<TlsInspectionPolicyException>().having(
          (error) => error.code,
          'code',
          'ip_not_supported',
        ),
      ),
    );
    await expectLater(
      notifier.normalizeRule(
        input: 'com',
        scope: TlsInspectionRuleScope.subdomains,
      ),
      throwsA(
        isA<TlsInspectionPolicyException>().having(
          (error) => error.code,
          'code',
          'domain_too_broad',
        ),
      ),
    );
  });
}
