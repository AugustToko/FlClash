import 'dart:io';
import 'package:flutter/services.dart';

const _maximumDateTimeEpochMilliseconds = 8640000000000000;

enum CertificateTrustState {
  trusted,
  notTrusted,
  blocked,
  unsupported,
  unavailable,
}

enum CertificateTrustStore { none, user, system, both, unknown }

enum CertificateInstallMode { prompt, settings, unsupported }

enum CertificateInstallOutcome {
  installed,
  settingsOpened,
  cancelled,
  unsupported,
  failed,
}

class CertificateTrustStatus {
  final String platform;
  final CertificateTrustState state;
  final CertificateTrustStore store;
  final CertificateInstallMode installMode;
  final bool verificationSupported;
  final String fingerprintSha256;
  final int platformVersion;
  final List<String> limitations;
  final String errorCode;
  final DateTime? checkedAt;

  const CertificateTrustStatus({
    this.platform = 'unknown',
    this.state = CertificateTrustState.unsupported,
    this.store = CertificateTrustStore.none,
    this.installMode = CertificateInstallMode.unsupported,
    this.verificationSupported = false,
    this.fingerprintSha256 = '',
    this.platformVersion = 0,
    this.limitations = const [],
    this.errorCode = '',
    this.checkedAt,
  });

  factory CertificateTrustStatus.fromMap(Map<Object?, Object?> raw) {
    String text(String key, {int maximum = 256}) {
      final value = raw[key]?.toString() ?? '';
      return value.length <= maximum ? value : value.substring(0, maximum);
    }

    int integer(String key) => switch (raw[key]) {
      final int value => value,
      final num value => value.toInt(),
      _ => int.tryParse(raw[key]?.toString() ?? '') ?? 0,
    };

    T enumValue<T extends Enum>(List<T> values, String key, T fallback) {
      final name = text(key, maximum: 64);
      return values.where((value) => value.name == name).firstOrNull ??
          fallback;
    }

    final rawLimitations = raw['limitations'];
    final checkedAtEpochMs = integer('checkedAtEpochMs');
    return CertificateTrustStatus(
      platform: text('platform', maximum: 32),
      state: enumValue(
        CertificateTrustState.values,
        'state',
        CertificateTrustState.unavailable,
      ),
      store: enumValue(
        CertificateTrustStore.values,
        'store',
        CertificateTrustStore.unknown,
      ),
      installMode: enumValue(
        CertificateInstallMode.values,
        'installMode',
        CertificateInstallMode.unsupported,
      ),
      verificationSupported: raw['verificationSupported'] as bool? ?? false,
      fingerprintSha256: text('fingerprintSha256', maximum: 128).toUpperCase(),
      platformVersion: integer('platformVersion').clamp(0, 0x7fffffff),
      limitations: List.unmodifiable(
        (rawLimitations is List ? rawLimitations : const <Object?>[])
            .map((value) => value?.toString() ?? '')
            .where((value) => value.isNotEmpty)
            .take(16)
            .map(
              (value) => value.length <= 128 ? value : value.substring(0, 128),
            ),
      ),
      errorCode: text('errorCode', maximum: 128),
      checkedAt: checkedAtEpochMs <= 0
          ? null
          : DateTime.fromMillisecondsSinceEpoch(
              checkedAtEpochMs.clamp(0, _maximumDateTimeEpochMilliseconds),
              isUtc: true,
            ),
    );
  }

  bool matchesFingerprint(String fingerprint) =>
      state == CertificateTrustState.trusted &&
      fingerprintSha256.isNotEmpty &&
      fingerprintSha256 == fingerprint.toUpperCase();
}

class CertificateInstallResult {
  final CertificateInstallOutcome outcome;
  final CertificateTrustStatus? trustStatus;
  final String errorCode;

  const CertificateInstallResult({
    required this.outcome,
    this.trustStatus,
    this.errorCode = '',
  });

  factory CertificateInstallResult.fromMap(Map<Object?, Object?> raw) {
    String boundedText(Object? value, {int maximum = 128}) {
      final text = value?.toString() ?? '';
      return text.length <= maximum ? text : text.substring(0, maximum);
    }

    final rawOutcome = raw['outcome']?.toString() ?? '';
    final outcome = CertificateInstallOutcome.values
        .where((value) => value.name == rawOutcome)
        .firstOrNull;
    final status = raw['trustStatus'];
    return CertificateInstallResult(
      outcome: outcome ?? CertificateInstallOutcome.failed,
      trustStatus: status is Map
          ? CertificateTrustStatus.fromMap(Map<Object?, Object?>.from(status))
          : null,
      errorCode: boundedText(raw['errorCode']),
    );
  }
}

abstract interface class CertificateTrustClient {
  String get platform;

  bool get verificationSupported;

  Future<CertificateTrustStatus> checkCertificate({
    required Uint8List certificateDer,
    required String fingerprintSha256,
  });

  Future<CertificateInstallResult> requestInstall({
    required Uint8List certificateDer,
    required String fingerprintSha256,
    required String displayName,
  });

  Future<bool> openTrustSettings();
}

class CertificateTrustManager implements CertificateTrustClient {
  CertificateTrustManager({MethodChannel? channel, bool? platformSupported})
    : _channel = channel ?? const MethodChannel('certificate_trust'),
      _platformSupported = platformSupported ?? Platform.isAndroid;

  static final CertificateTrustManager instance = CertificateTrustManager();

  final MethodChannel _channel;
  final bool _platformSupported;

  @override
  String get platform =>
      _platformSupported ? 'android' : Platform.operatingSystem;

  @override
  bool get verificationSupported => _platformSupported;

  @override
  Future<CertificateTrustStatus> checkCertificate({
    required Uint8List certificateDer,
    required String fingerprintSha256,
  }) async {
    _validateCertificateInput(certificateDer, fingerprintSha256);
    if (!_platformSupported) {
      return CertificateTrustStatus(platform: platform);
    }
    try {
      final value = await _channel
          .invokeMapMethod<Object?, Object?>('checkTrust', {
            'certificateDer': certificateDer,
            'fingerprintSha256': fingerprintSha256.toUpperCase(),
          });
      return value == null
          ? CertificateTrustStatus(
              platform: platform,
              state: CertificateTrustState.unavailable,
              verificationSupported: true,
              errorCode: 'empty-result',
            )
          : CertificateTrustStatus.fromMap(value);
    } on MissingPluginException {
      return CertificateTrustStatus(
        platform: platform,
        state: CertificateTrustState.unavailable,
        verificationSupported: true,
        installMode: CertificateInstallMode.unsupported,
        errorCode: 'missing-plugin',
      );
    } on PlatformException catch (error) {
      return CertificateTrustStatus(
        platform: platform,
        state: CertificateTrustState.unavailable,
        verificationSupported: true,
        errorCode: error.code,
      );
    }
  }

  @override
  Future<CertificateInstallResult> requestInstall({
    required Uint8List certificateDer,
    required String fingerprintSha256,
    required String displayName,
  }) async {
    _validateCertificateInput(certificateDer, fingerprintSha256);
    if (!_platformSupported) {
      return const CertificateInstallResult(
        outcome: CertificateInstallOutcome.unsupported,
      );
    }
    try {
      final value = await _channel
          .invokeMapMethod<Object?, Object?>('requestInstall', {
            'certificateDer': certificateDer,
            'fingerprintSha256': fingerprintSha256.toUpperCase(),
            'displayName': displayName,
          });
      return value == null
          ? const CertificateInstallResult(
              outcome: CertificateInstallOutcome.failed,
              errorCode: 'empty-result',
            )
          : CertificateInstallResult.fromMap(value);
    } on MissingPluginException {
      return const CertificateInstallResult(
        outcome: CertificateInstallOutcome.failed,
        errorCode: 'missing-plugin',
      );
    } on PlatformException catch (error) {
      return CertificateInstallResult(
        outcome: CertificateInstallOutcome.failed,
        errorCode: error.code,
      );
    }
  }

  @override
  Future<bool> openTrustSettings() async {
    if (!_platformSupported) {
      return false;
    }
    try {
      return await _channel.invokeMethod<bool>('openTrustSettings') ?? false;
    } on MissingPluginException {
      return false;
    } on PlatformException {
      return false;
    }
  }

  void _validateCertificateInput(Uint8List certificateDer, String fingerprint) {
    if (certificateDer.isEmpty || certificateDer.length > 64 * 1024) {
      throw ArgumentError.value(
        certificateDer.length,
        'certificateDer',
        'Certificate DER must contain between 1 and 65536 bytes.',
      );
    }
    if (!RegExp(
      r'^(?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}$',
    ).hasMatch(fingerprint)) {
      throw ArgumentError.value(
        fingerprint,
        'fingerprintSha256',
        'Expected a colon-separated SHA-256 fingerprint.',
      );
    }
  }
}

extension _FirstOrNull<T> on Iterable<T> {
  T? get firstOrNull => isEmpty ? null : first;
}

final certificateTrustManager = CertificateTrustManager.instance;
