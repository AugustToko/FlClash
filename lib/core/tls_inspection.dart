part of 'controller.dart';

extension CoreControllerTlsInspectionExt on CoreController {
  Future<TlsInspectionAuthorityStatus> getTlsInspectionAuthorityStatus() async {
    final data = await _interface.invokeMethod<Map<String, dynamic>>(
      method: CoreMethod.getTlsInspectionAuthorityStatus,
      timeout: const Duration(seconds: 5),
    );
    if (data == null) {
      throw const CoreMethodException(
        code: 'empty_result',
        message: 'Core returned an empty authority status',
      );
    }
    return TlsInspectionAuthorityStatus.fromJson(data);
  }

  Future<TlsInspectionAuthorityStatus> ensureTlsInspectionAuthority() async {
    return _authorityMutation(CoreMethod.ensureTlsInspectionAuthority);
  }

  Future<TlsInspectionAuthorityStatus> rotateTlsInspectionAuthority() async {
    return _authorityMutation(
      CoreMethod.rotateTlsInspectionAuthority,
      arguments: const {'confirm': true},
    );
  }

  Future<bool> deleteTlsInspectionAuthority() async {
    return await _interface.invokeMethod<bool>(
          method: CoreMethod.deleteTlsInspectionAuthority,
          arguments: const {'confirm': true},
          timeout: const Duration(seconds: 10),
        ) ??
        false;
  }

  Future<TlsInspectionAuthorityExport> exportTlsInspectionCertificate() async {
    final data = await _interface.invokeMethod<Map<String, dynamic>>(
      method: CoreMethod.exportTlsInspectionCertificate,
      timeout: const Duration(seconds: 5),
    );
    if (data == null) {
      throw const CoreMethodException(
        code: 'empty_result',
        message: 'Core returned an empty certificate export',
      );
    }
    return TlsInspectionAuthorityExport.fromJson(data);
  }

  Future<TlsInspectionLeafCacheStatus> getTlsInspectionLeafCacheStatus() async {
    final data = await _interface.invokeMethod<Map<String, dynamic>>(
      method: CoreMethod.getTlsInspectionLeafCacheStatus,
      timeout: const Duration(seconds: 5),
    );
    if (data == null) {
      throw const CoreMethodException(
        code: 'empty_result',
        message: 'Core returned an empty leaf cache status',
      );
    }
    return TlsInspectionLeafCacheStatus.fromJson(data);
  }

  Future<TlsInspectionLeafCacheStatus> configureTlsInspectionLeafPolicy({
    required bool enabled,
    required TlsInspectionPolicy policy,
    required TlsInspectionAuthorityStatus authority,
    required bool trustSatisfied,
  }) async {
    final data = await _interface.invokeMethod<Map<String, dynamic>>(
      method: CoreMethod.configureTlsInspectionLeafPolicy,
      arguments: {
        'enabled': enabled,
        'authorityGeneration': authority.generation,
        'authorityFingerprintSha256': authority.fingerprintSha256,
        'riskVersion': tlsInspectionRiskVersion,
        'trustSatisfied': trustSatisfied,
        'allowlist': policy.allowlist.map((rule) => rule.toJson()).toList(),
        'exclusions': policy.exclusions.map((rule) => rule.toJson()).toList(),
      },
      timeout: const Duration(seconds: 15),
    );
    if (data == null) {
      throw const CoreMethodException(
        code: 'empty_result',
        message: 'Core returned an empty leaf policy result',
      );
    }
    return TlsInspectionLeafCacheStatus.fromJson(data);
  }

  Future<TlsInspectionLeafCertificateStatus>
  prepareTlsInspectionLeafCertificate({
    required String host,
    required TlsInspectionAuthorityStatus authority,
    required String policyDigest,
    bool verifyHandshake = false,
  }) async {
    final data = await _interface.invokeMethod<Map<String, dynamic>>(
      method: CoreMethod.prepareTlsInspectionLeafCertificate,
      arguments: {
        'host': host,
        'authorityGeneration': authority.generation,
        'authorityFingerprintSha256': authority.fingerprintSha256,
        'policyDigest': policyDigest,
        if (verifyHandshake) 'verifyHandshake': true,
      },
      timeout: const Duration(seconds: 15),
    );
    if (data == null) {
      throw const CoreMethodException(
        code: 'empty_result',
        message: 'Core returned an empty leaf certificate result',
      );
    }
    if (verifyHandshake &&
        (data['handshakeVerified'] != true ||
            data['handshakeScope'] != 'in-memory-only' ||
            data['handshakeAlpn'] != 'http/1.1' ||
            data['handshakeVersions'] is! List ||
            (data['handshakeVersions'] as List).length != 2 ||
            (data['handshakeVersions'] as List)[0] != 'TLS 1.2' ||
            (data['handshakeVersions'] as List)[1] != 'TLS 1.3')) {
      throw const CoreMethodException(
        code: 'leaf_handshake_unverified',
        message: 'Core did not confirm both local TLS handshake versions',
      );
    }
    return TlsInspectionLeafCertificateStatus.fromJson(data);
  }

  Future<TlsInspectionAuthorityStatus> _authorityMutation(
    CoreMethod method, {
    Object? arguments,
  }) async {
    final data = await _interface.invokeMethod<Map<String, dynamic>>(
      method: method,
      arguments: arguments,
      timeout: const Duration(seconds: 15),
    );
    if (data == null) {
      throw CoreMethodException(
        code: 'empty_result',
        message: 'Core returned an empty result for ${method.name}',
      );
    }
    return TlsInspectionAuthorityStatus.fromJson(data);
  }
}
