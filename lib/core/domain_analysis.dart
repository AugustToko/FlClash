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

  factory CoreDomainAnalysis.fromJson(Map<String, Object?> json) {
    return CoreDomainAnalysis(
      input: json['input'] as String? ?? '',
      normalizedHost: json['normalizedHost'] as String? ?? '',
      isIP: json['isIP'] as bool? ?? false,
      publicSuffix: json['publicSuffix'] as String? ?? '',
      registrableDomain: json['registrableDomain'] as String? ?? '',
      icannSuffix: json['icannSuffix'] as bool? ?? false,
    );
  }

  bool get hasRegistrableDomain => registrableDomain.isNotEmpty;

  Map<String, Object?> toJson() {
    return {
      'input': input,
      'normalizedHost': normalizedHost,
      'isIP': isIP,
      'publicSuffix': publicSuffix,
      'registrableDomain': registrableDomain,
      'icannSuffix': icannSuffix,
    };
  }
}
