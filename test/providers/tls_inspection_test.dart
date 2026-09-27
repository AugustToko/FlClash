import 'dart:async';

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
import 'package:flutter_test/flutter_test.dart';
import 'package:riverpod/riverpod.dart';

const _fingerprintA =
    'AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA';
const _fingerprintB =
    'BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB';

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

class _FoundationCoreHandler extends CoreHandlerInterface {
  String fingerprint = _fingerprintA;
  String? exportedFingerprint;
  String exportedPem =
      '-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n';
  Completer<void>? authorityGate;

  Map<String, Object?> get authority => {
    'state': 'ready',
    'ready': true,
    'generation': fingerprint == _fingerprintA
        ? 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        : 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    'fingerprintSha256': fingerprint,
    'subject': 'CN=FlClash Local Inspection CA',
    'serialNumber': '01',
    'notBefore': '2026-09-27T00:00:00Z',
    'notAfter': '2029-09-26T00:00:00Z',
    'algorithm': 'ECDSA P-256 / SHA-256',
    'keyStorage': 'app-data-file',
    'keyPermissionsRestricted': true,
    'trustState': 'unknown',
    'trustCapability': 'manual-only',
    'certificateFileName': 'flclash-local-inspection-ca.crt',
  };

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
  }) {
    final value = ProviderContainer(
      overrides: [
        coreHandlerProvider.overrideWithValue(CoreController.scoped(core)),
        coreStatusProvider.overrideWithBuild((_, _) => status),
        tlsInspectionPersistenceEnabledProvider.overrideWithValue(true),
        tlsInspectionPolicyStoreProvider.overrideWithValue(store),
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
    expect(state.prepared, isFalse);
    expect(store.writes, 0);
  });

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
