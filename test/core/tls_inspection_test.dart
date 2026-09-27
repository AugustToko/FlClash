import 'package:fl_clash/core/controller.dart';
import 'package:fl_clash/core/desktop/model.dart';
import 'package:fl_clash/core/interface.dart';
import 'package:fl_clash/core/method.dart';
import 'package:flutter_test/flutter_test.dart';

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
        'generation': '0123456789abcdef0123456789abcdef',
        'fingerprintSha256': 'AA:BB',
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
        'fingerprintSha256': 'AA:BB',
      },
      _ => throw StateError('unexpected method: $method'),
    };
    return result as T;
  }
}

void main() {
  test(
    'controller exposes the complete authority lifecycle contract',
    () async {
      final handler = _TlsInspectionCoreHandler();
      final controller = CoreController.scoped(handler);

      final status = await controller.getTlsInspectionAuthorityStatus();
      final ensured = await controller.ensureTlsInspectionAuthority();
      final rotated = await controller.rotateTlsInspectionAuthority();
      final exported = await controller.exportTlsInspectionCertificate();
      final deleted = await controller.deleteTlsInspectionAuthority();

      expect(status.ready, isTrue);
      expect(ensured.fingerprintSha256, 'AA:BB');
      expect(rotated.generation, hasLength(32));
      expect(exported.pem, contains('BEGIN CERTIFICATE'));
      expect(deleted, isTrue);
      expect(handler.calls.map((call) => call.method), [
        CoreMethod.getTlsInspectionAuthorityStatus,
        CoreMethod.ensureTlsInspectionAuthority,
        CoreMethod.rotateTlsInspectionAuthority,
        CoreMethod.exportTlsInspectionCertificate,
        CoreMethod.deleteTlsInspectionAuthority,
      ]);
      expect(handler.calls[2].arguments, {'confirm': true});
      expect(handler.calls[4].arguments, {'confirm': true});
    },
  );

  test('protocol method names round-trip', () {
    for (final method in const [
      CoreMethod.getTlsInspectionAuthorityStatus,
      CoreMethod.ensureTlsInspectionAuthority,
      CoreMethod.rotateTlsInspectionAuthority,
      CoreMethod.deleteTlsInspectionAuthority,
      CoreMethod.exportTlsInspectionCertificate,
    ]) {
      final call = CoreMethodCall(method: method);
      expect(CoreMethodCall.fromJson(call.toJson()).method, method);
    }
  });
}
