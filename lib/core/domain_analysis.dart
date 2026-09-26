part of 'controller.dart';

class CoreDomainAnalysis {
  final String input;
  final String normalizedHost;
  final bool isIP;
  final String publicSuffix;
  final String registrableDomain;
  final bool icannSuffix;

  const CoreDomainAnalysis({
    required this.input,
    required this.normalizedHost,
    required this.isIP,
    required this.publicSuffix,
    required this.registrableDomain,
    required this.icannSuffix,
  });

  factory CoreDomainAnalysis.fromJson(Map<String, dynamic> json) {
    return CoreDomainAnalysis(
      input: json['input'] as String? ?? '',
      normalizedHost: json['normalizedHost'] as String? ?? '',
      isIP: json['isIP'] as bool? ?? false,
      publicSuffix: json['publicSuffix'] as String? ?? '',
      registrableDomain: json['registrableDomain'] as String? ?? '',
      icannSuffix: json['icannSuffix'] as bool? ?? false,
    );
  }

  bool get hasRegistrableDomain =>
      !isIP && normalizedHost.isNotEmpty && registrableDomain.isNotEmpty;
}

extension CoreControllerDomainAnalysisExt on CoreController {
  Future<CoreDomainAnalysis> analyzeDomain(String host) async {
    final data = await _interface.invokeMethod<Map<String, dynamic>>(
      method: CoreMethod.analyzeDomain,
      arguments: {'host': host},
      timeout: const Duration(seconds: 5),
    );
    if (data == null) {
      throw const CoreMethodException(
        code: 'empty_result',
        message: 'Core returned an empty domain analysis result',
      );
    }
    return CoreDomainAnalysis.fromJson(data);
  }
}
