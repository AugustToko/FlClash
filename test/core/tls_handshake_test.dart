import 'package:fl_clash/core/controller.dart';
import 'package:fl_clash/core/desktop/model.dart';
import 'package:fl_clash/core/interface.dart';
import 'package:fl_clash/core/method.dart';
import 'package:fl_clash/models/models.dart';
import 'package:flutter_test/flutter_test.dart';

const _generation = '0123456789abcdef0123456789abcdef';
const _digest =
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const _runtimeProof = 'fedcba9876543210fedcba9876543210';
final _fingerprint = List.filled(32, 'AA').join(':');

Map<String, dynamic> _verifiedResult() => {
  'host': 'api.example.com',
  'cacheHit': false,
  'generation': _generation,
  'authorityFingerprintSha256': _fingerprint,
  'policyDigest': _digest,
  'fingerprintSha256': List.filled(32, 'BB').join(':'),
  'serialNumber': '01',
  'notBefore': DateTime.now()
      .toUtc()
      .subtract(const Duration(minutes: 5))
      .toIso8601String(),
  'notAfter': DateTime.now()
      .toUtc()
      .add(const Duration(hours: 23))
      .toIso8601String(),
  'algorithm': 'ECDSA P-256 / SHA-256',
  'keyStorage': 'app-data-file',
  'privateKeyExported': false,
  'handshakeVerified': true,
  'handshakeVersions': ['TLS 1.2', 'TLS 1.3'],
  'handshakeScope': 'in-memory-only',
  'handshakeAlpn': 'http/1.1',
  'handshakeDurationMs': 5,
  'runtimeProofId': _runtimeProof,
};

class _HandshakeCore extends CoreHandlerInterface {
  Map<String, dynamic>? result = _verifiedResult();
  CoreMethod? method;
  Object? arguments;

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
    this.method = method;
    this.arguments = arguments;
    return result as T?;
  }
}

void main() {
  late _HandshakeCore handler;
  late CoreController controller;

  Future<TlsInspectionLeafCertificateStatus> prepare({bool verify = true}) =>
      controller.prepareTlsInspectionLeafCertificate(
        host: 'api.example.com',
        authority: TlsInspectionAuthorityStatus(
          generation: _generation,
          fingerprintSha256: _fingerprint,
        ),
        policyDigest: _digest,
        verifyHandshake: verify,
      );

  setUp(() {
    handler = _HandshakeCore();
    controller = CoreController.scoped(handler);
  });

  test(
    'self-test explicitly requests real handshakes through leaf IPC',
    () async {
      final result = await prepare();
      expect(handler.method, CoreMethod.prepareTlsInspectionLeafCertificate);
      expect(handler.arguments, {
        'host': 'api.example.com',
        'authorityGeneration': _generation,
        'authorityFingerprintSha256': _fingerprint,
        'policyDigest': _digest,
        'verifyHandshake': true,
      });
      expect(result.contractValid, isTrue);
      expect(result.handshakeContractValid, isTrue);
      expect(result.runtimeProofId, _runtimeProof);
      expect(result.privateKeyExported, isFalse);
    },
  );

  test('ordinary issuance preserves the pre-self-test IPC contract', () async {
    handler.result!.removeWhere((key, _) => key.startsWith('handshake'));
    await prepare(verify: false);
    expect((handler.arguments! as Map).containsKey('verifyHandshake'), isFalse);
  });

  test('an older Core cannot silently satisfy the self-test request', () async {
    handler.result!.removeWhere((key, _) => key.startsWith('handshake'));
    await expectLater(
      prepare(),
      throwsA(
        isA<CoreMethodException>().having(
          (error) => error.code,
          'code',
          'leaf_handshake_unverified',
        ),
      ),
    );
  });

  final malformed = <String, Map<String, Object?>>{
    'false verification': {'handshakeVerified': false},
    'string verification': {'handshakeVerified': 'true'},
    'missing verification': {'handshakeVerified': null},
    'string versions': {'handshakeVersions': 'TLS 1.2,TLS 1.3'},
    'one version': {
      'handshakeVersions': ['TLS 1.3'],
    },
    'duplicate version': {
      'handshakeVersions': ['TLS 1.2', 'TLS 1.2'],
    },
    'unverified legacy protocol': {
      'handshakeVersions': ['TLS 1.0', 'TLS 1.3'],
    },
    'extra version': {
      'handshakeVersions': ['TLS 1.2', 'TLS 1.3', 'unknown'],
    },
    'wrong scope': {'handshakeScope': 'target-server'},
    'missing scope': {'handshakeScope': null},
    'wrong ALPN': {'handshakeAlpn': 'h2'},
    'missing ALPN': {'handshakeAlpn': null},
    'missing duration': {'handshakeDurationMs': null},
    'string duration': {'handshakeDurationMs': '5'},
    'unbounded duration': {'handshakeDurationMs': 5001},
    'missing runtime proof': {'runtimeProofId': null},
    'short runtime proof': {'runtimeProofId': 'abc'},
    'non-hex runtime proof': {
      'runtimeProofId': 'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz',
    },
  };
  for (final entry in malformed.entries) {
    test('self-test rejects ${entry.key}', () async {
      handler.result!.addAll(entry.value);
      await expectLater(
        prepare(),
        throwsA(
          isA<CoreMethodException>().having(
            (error) => error.code,
            'code',
            'leaf_handshake_unverified',
          ),
        ),
      );
    });
  }

  test('empty Core response is not successful verification', () async {
    handler.result = null;
    await expectLater(
      prepare(),
      throwsA(
        isA<CoreMethodException>().having(
          (error) => error.code,
          'code',
          'empty_result',
        ),
      ),
    );
  });
}
