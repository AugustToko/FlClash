import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

File _resolveSource(String relativePath) {
  final direct = File(relativePath);
  if (direct.existsSync()) {
    return direct;
  }
  final inPlugin = File('plugins/certificate_trust/$relativePath');
  return inPlugin.existsSync() ? inPlugin : direct;
}

void main() {
  late String source;

  setUpAll(() {
    source = _resolveSource(
      'android/src/main/kotlin/com/follow/clash/certificate_trust/CertificateTrustPlugin.kt',
    ).readAsStringSync();
  });

  test('Android trust checks run away from the platform thread', () {
    final runBackground = source.indexOf('private fun runBackground');
    expect(runBackground, isNonNegative);
    expect(source.substring(runBackground), contains('executor.execute {'));
    expect(source, contains('METHOD_CHECK -> runBackground(result)'));
  });

  test('successful legacy installation waits for trust-store propagation', () {
    final callback = source.indexOf('private val activityResultListener');
    final checker = source.indexOf('private fun awaitInstalledTrust');
    expect(callback, isNonNegative);
    expect(checker, greaterThan(callback));
    expect(
      source.substring(callback, checker),
      contains('awaitInstalledTrust(pending.input)'),
    );
    final block = source.substring(checker);
    expect(block, contains('INSTALL_TRUST_POLL_ATTEMPTS'));
    expect(block, contains('Thread.sleep(INSTALL_TRUST_POLL_DELAY_MS)'));
    expect(block, contains('Thread.currentThread().interrupt()'));
  });

  test(
    'Android 11+ settings flow does not scan the trust store synchronously',
    () {
      final start = source.indexOf(
        'if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)',
      );
      final end = source.indexOf('if (pendingInstall != null)', start);
      expect(start, isNonNegative);
      expect(end, greaterThan(start));
      final block = source.substring(start, end);
      expect(block, contains('openTrustSettings()'));
      expect(block, isNot(contains('checkTrust(input)')));
    },
  );

  test('native plugin never logs or persists certificate material', () {
    expect(source, isNot(contains('android.util.Log')));
    expect(source, isNot(contains('SharedPreferences')));
    expect(source, isNot(contains('FileOutputStream')));
    expect(source, isNot(contains('contentToString()')));
  });

  test('native input validation binds the exact CA fingerprint', () {
    expect(source, contains('CertificateFactory.getInstance("X.509")'));
    expect(source, contains('certificateStream.available() != 0'));
    expect(source, contains('if (actual != expected)'));
    expect(source, contains('certificate.checkValidity()'));
    expect(
      source,
      contains(
        'certificate.subjectX500Principal != certificate.issuerX500Principal',
      ),
    );
    expect(source, contains('certificate.verify(certificate.publicKey)'));
    expect(source, contains('certificate.basicConstraints != 0'));
    expect(source, contains('!keyUsage[5]'));
    expect(source, contains('KeyStore.getInstance("AndroidCAStore")'));
  });
}
