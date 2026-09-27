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
