import 'package:certificate_trust/certificate_trust.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

const _fingerprint =
    '8A:47:35:D9:0C:B1:5E:27:72:2F:99:18:C4:A2:70:11:'
    '84:FE:51:33:90:C8:6A:60:5B:D3:EA:79:B6:1F:42:CD';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('certificate_trust');

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  test('decodes a verified Android user-store result', () async {
    MethodCall? received;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          received = call;
          return {
            'platform': 'android',
            'state': 'trusted',
            'store': 'user',
            'installMode': 'settings',
            'verificationSupported': true,
            'fingerprintSha256': _fingerprint,
            'platformVersion': 35,
            'limitations': ['android-user-ca-opt-in'],
            'checkedAtEpochMs': 1,
          };
        });
    final manager = CertificateTrustManager(platformSupported: true);
    expect(manager.platform, 'android');
    expect(manager.verificationSupported, isTrue);

    final result = await manager.checkCertificate(
      certificateDer: Uint8List.fromList([1, 2, 3]),
      fingerprintSha256: _fingerprint,
    );

    expect(received?.method, 'checkTrust');
    expect(result.state, CertificateTrustState.trusted);
    expect(result.store, CertificateTrustStore.user);
    expect(result.installMode, CertificateInstallMode.settings);
    expect(result.matchesFingerprint(_fingerprint), isTrue);
    expect(
      result.checkedAt,
      DateTime.fromMillisecondsSinceEpoch(1, isUtc: true),
    );
  });

  test('missing native timestamps remain absent instead of becoming 1970', () {
    final result = CertificateTrustStatus.fromMap({
      'platform': 'android',
      'state': 'notTrusted',
      'verificationSupported': true,
    });

    expect(result.checkedAt, isNull);
  });

  test('bounds native timestamps and installation error codes', () {
    final status = CertificateTrustStatus.fromMap({
      'checkedAtEpochMs': 0x7fffffffffffffff,
    });
    final result = CertificateInstallResult.fromMap({
      'outcome': 'failed',
      'errorCode': 'x' * 512,
    });

    expect(status.checkedAt, isNotNull);
    expect(
      status.checkedAt!.millisecondsSinceEpoch,
      lessThanOrEqualTo(8640000000000000),
    );
    expect(result.errorCode, hasLength(128));
  });

  test('requestInstall preserves the native outcome and status', () async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          expect(call.method, 'requestInstall');
          return {
            'outcome': 'settingsOpened',
            'trustStatus': {
              'platform': 'android',
              'state': 'notTrusted',
              'store': 'none',
              'installMode': 'settings',
              'verificationSupported': true,
              'fingerprintSha256': _fingerprint,
            },
          };
        });
    final manager = CertificateTrustManager(platformSupported: true);

    final result = await manager.requestInstall(
      certificateDer: Uint8List.fromList([1]),
      fingerprintSha256: _fingerprint,
      displayName: 'FlClash Local Inspection CA',
    );

    expect(result.outcome, CertificateInstallOutcome.settingsOpened);
    expect(result.trustStatus?.state, CertificateTrustState.notTrusted);
  });

  test('unsupported platforms do not invoke the method channel', () async {
    var invoked = false;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (_) async {
          invoked = true;
          return null;
        });
    final manager = CertificateTrustManager(platformSupported: false);
    expect(manager.verificationSupported, isFalse);
    expect(manager.platform, isNotEmpty);

    final result = await manager.checkCertificate(
      certificateDer: Uint8List.fromList([1]),
      fingerprintSha256: _fingerprint,
    );

    expect(invoked, isFalse);
    expect(result.state, CertificateTrustState.unsupported);
    expect(result.verificationSupported, isFalse);
  });

  test('rejects oversized certificates and malformed fingerprints', () async {
    final manager = CertificateTrustManager(platformSupported: false);
    expect(
      () => manager.checkCertificate(
        certificateDer: Uint8List(64 * 1024 + 1),
        fingerprintSha256: _fingerprint,
      ),
      throwsArgumentError,
    );
    expect(
      () => manager.checkCertificate(
        certificateDer: Uint8List.fromList([1]),
        fingerprintSha256: 'bad',
      ),
      throwsArgumentError,
    );
  });
}
