import 'package:fl_clash/core/controller.dart';
import 'package:fl_clash/core/desktop/model.dart';
import 'package:fl_clash/core/interface.dart';
import 'package:fl_clash/core/method.dart';
import 'package:fl_clash/models/models.dart';
import 'package:flutter_test/flutter_test.dart';

const _fingerprint =
    'AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:'
    'AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA';
const _leafFingerprint =
    'BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:'
    'BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB';
const _generation = '0123456789abcdef0123456789abcdef';
const _policyDigest =
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const _runtimeProof = 'fedcba9876543210fedcba9876543210';

class _TlsInspectionCoreHandler extends CoreHandlerInterface {
  final calls = <CoreMethodCall>[];

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
    calls.add(CoreMethodCall(method: method, arguments: arguments));
    final result = switch (method) {
      CoreMethod.getTlsInspectionAuthorityStatus ||
      CoreMethod.ensureTlsInspectionAuthority ||
      CoreMethod.rotateTlsInspectionAuthority => <String, Object?>{
        'state': 'ready',
        'ready': true,
        'generation': _generation,
        'fingerprintSha256': _fingerprint,
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
      },
      CoreMethod.deleteTlsInspectionAuthority => true,
      CoreMethod.exportTlsInspectionCertificate => <String, Object?>{
        'fileName': 'flclash-local-inspection-ca.crt',
        'pem': '-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n',
        'fingerprintSha256': _fingerprint,
      },
      CoreMethod.getTlsInspectionLeafCacheStatus ||
      CoreMethod.configureTlsInspectionLeafPolicy => <String, Object?>{
        'state': 'ready',
        'ready': true,
        'generation': _generation,
        'authorityFingerprintSha256': _fingerprint,
        'policyDigest': _policyDigest,
        'entryCount': 1,
        'capacity': 64,
        'leafValiditySeconds': 86400,
        'algorithm': 'ECDSA P-256 / SHA-256',
        'keyStorage': 'app-data-file',
        'keyPermissionsRestricted': true,
        'privateKeysExported': false,
        'runtimeAuthorizationPresent': true,
        'runtimeProofId': _runtimeProof,
        'updatedAt': '2026-09-28T00:00:00Z',
      },
      CoreMethod.prepareTlsInspectionLeafCertificate => <String, Object?>{
        'host': 'api.example.com',
        'cacheHit': false,
        'generation': _generation,
        'authorityFingerprintSha256': _fingerprint,
        'policyDigest': _policyDigest,
        'fingerprintSha256': _leafFingerprint,
        'serialNumber': '01',
        'notBefore': '2026-09-27T23:55:00Z',
        'notAfter': '2026-09-28T23:55:00Z',
        'algorithm': 'ECDSA P-256 / SHA-256',
        'keyStorage': 'app-data-file',
        'privateKeyExported': false,
      },
      _ => throw StateError('unexpected method: $method'),
    };
    return result as T;
  }
}

void main() {
  test(
    'controller exposes the authority and leaf certificate safety contracts',
    () async {
      final handler = _TlsInspectionCoreHandler();
      final controller = CoreController.scoped(handler);

      final status = await controller.getTlsInspectionAuthorityStatus();
      final ensured = await controller.ensureTlsInspectionAuthority();
      final rotated = await controller.rotateTlsInspectionAuthority();
      final exported = await controller.exportTlsInspectionCertificate();
      final leafStatus = await controller.getTlsInspectionLeafCacheStatus();
      final configured = await controller.configureTlsInspectionLeafPolicy(
        enabled: true,
        policy: const TlsInspectionPolicy(
          acknowledgedRiskVersion: tlsInspectionRiskVersion,
          allowlist: [
            TlsInspectionDomainRule(
              host: 'example.com',
              scope: TlsInspectionRuleScope.subdomains,
            ),
          ],
        ),
        authority: status,
        trustSatisfied: true,
      );
      final leaf = await controller.prepareTlsInspectionLeafCertificate(
        host: 'api.example.com',
        authority: status,
        policyDigest: configured.policyDigest,
      );
      final deleted = await controller.deleteTlsInspectionAuthority();

      expect(status.ready, isTrue);
      expect(ensured.fingerprintSha256, _fingerprint);
      expect(rotated.generation, hasLength(32));
      expect(exported.pem, contains('BEGIN CERTIFICATE'));
      expect(leafStatus.policyDigest, _policyDigest);
      expect(configured.entryCount, 1);
      expect(leaf.host, 'api.example.com');
      expect(leaf.privateKeyExported, isFalse);
      expect(deleted, isTrue);
      expect(handler.calls.map((call) => call.method), [
        CoreMethod.getTlsInspectionAuthorityStatus,
        CoreMethod.ensureTlsInspectionAuthority,
        CoreMethod.rotateTlsInspectionAuthority,
        CoreMethod.exportTlsInspectionCertificate,
        CoreMethod.getTlsInspectionLeafCacheStatus,
        CoreMethod.configureTlsInspectionLeafPolicy,
        CoreMethod.prepareTlsInspectionLeafCertificate,
        CoreMethod.deleteTlsInspectionAuthority,
      ]);
      expect(handler.calls[2].arguments, {'confirm': true});
      expect(handler.calls[5].arguments, {
        'enabled': true,
        'authorityGeneration': _generation,
        'authorityFingerprintSha256': _fingerprint,
        'riskVersion': tlsInspectionRiskVersion,
        'trustSatisfied': true,
        'allowlist': [
          {'host': 'example.com', 'scope': 'subdomains'},
        ],
        'exclusions': <Map<String, Object?>>[],
      });
      expect(handler.calls[6].arguments, {
        'host': 'api.example.com',
        'authorityGeneration': _generation,
        'authorityFingerprintSha256': _fingerprint,
        'policyDigest': _policyDigest,
      });
      expect(handler.calls[7].arguments, {'confirm': true});
    },
  );

  test('protocol method names round-trip', () {
    for (final method in const [
      CoreMethod.getTlsInspectionAuthorityStatus,
      CoreMethod.ensureTlsInspectionAuthority,
      CoreMethod.rotateTlsInspectionAuthority,
      CoreMethod.deleteTlsInspectionAuthority,
      CoreMethod.exportTlsInspectionCertificate,
      CoreMethod.getTlsInspectionLeafCacheStatus,
      CoreMethod.configureTlsInspectionLeafPolicy,
      CoreMethod.prepareTlsInspectionLeafCertificate,
    ]) {
      final call = CoreMethodCall(method: method);
      expect(CoreMethodCall.fromJson(call.toJson()).method, method);
    }
  });
}
