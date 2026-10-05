part of 'controller.dart';

extension CoreControllerTlsRuntimeExt on CoreController {
  Future<TlsInspectionRuntimeStatus> getTlsInspectionRuntimeStatus() async {
    final data = await _interface.invokeMethod<Map<String, dynamic>>(
      method: CoreMethod.getTlsInspectionRuntimeStatus,
      timeout: const Duration(seconds: 5),
    );
    if (data == null) {
      throw const CoreMethodException(
        code: 'runtime_status_unavailable',
        message: 'Runtime status is unavailable',
      );
    }
    return TlsInspectionRuntimeStatus.fromJson(data);
  }

  Future<TlsInspectionRuntimeStart> startTlsInspectionRuntime({
    required String id,
    required bool confirmed,
    required TlsInspectionAuthorityStatus authority,
    required TlsInspectionLeafCacheStatus cache,
  }) async {
    if (!confirmed ||
        !RegExp(r'^[0-9a-f]{32}$').hasMatch(id) ||
        !cache.matchesAuthority(authority)) {
      throw const CoreMethodException(
        code: 'runtime_not_authorized',
        message:
            'Runtime requires explicit confirmation and current preparation',
      );
    }
    try {
      final data = await _interface.invokeMethod<Map<String, dynamic>>(
        method: CoreMethod.startTlsInspectionRuntime,
        arguments: {
          'id': id,
          'confirm': true,
          'authorityGeneration': authority.generation,
          'authorityFingerprintSha256': authority.fingerprintSha256,
          'policyDigest': cache.policyDigest,
        },
        timeout: const Duration(seconds: 15),
      );
      if (data == null) {
        throw const FormatException('Missing runtime start result');
      }
      final result = TlsInspectionRuntimeStart.fromJson(data);
      if (!result.status.matches(authority, cache, id)) {
        throw const FormatException(
          'Runtime result does not match authorization',
        );
      }
      return result;
    } catch (error) {
      if (error is CoreMethodException &&
          error.code == 'runtime_already_running') {
        rethrow;
      }
      try {
        await stopTlsInspectionRuntime(id);
      } catch (_) {
        // The identity-bound stop can be retried without stopping a newer run.
      }
      throw const CoreMethodException(
        code: 'runtime_start_unconfirmed',
        message:
            'Runtime start could not be verified; stop the requested runtime before retrying',
      );
    }
  }

  Future<bool> stopTlsInspectionRuntime(String id) async {
    if (!RegExp(r'^[0-9a-f]{32}$').hasMatch(id)) {
      throw const CoreMethodException(
        code: 'runtime_identity_required',
        message: 'Stopping requires the requested runtime identity',
      );
    }
    return await _interface.invokeMethod<bool>(
          method: CoreMethod.stopTlsInspectionRuntime,
          arguments: {'id': id},
          timeout: const Duration(seconds: 5),
        ) ==
        true;
  }
}
