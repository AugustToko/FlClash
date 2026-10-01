const tlsInspectionRiskVersion = 1;
const tlsInspectionPolicyFormatVersion = 1;
const tlsInspectionMaxRulesPerList = 200;
const tlsInspectionLeafCacheCapacity = 64;
const tlsInspectionLeafMaxValidity = Duration(hours: 24);
const tlsInspectionLeafRenewBefore = Duration(minutes: 10);

enum TlsInspectionRuleScope { exact, subdomains }

class TlsInspectionDomainRule {
  final String host;
  final TlsInspectionRuleScope scope;

  const TlsInspectionDomainRule({required this.host, required this.scope});

  factory TlsInspectionDomainRule.fromJson(Map<String, Object?> json) {
    final rawHost = json['host']?.toString() ?? '';
    final rawScope = json['scope']?.toString() ?? '';
    final normalizedHost = normalizeTlsInspectionHost(rawHost);
    return TlsInspectionDomainRule(
      host: _isValidTlsInspectionHost(normalizedHost) ? normalizedHost : '',
      scope:
          TlsInspectionRuleScope.values
              .where((value) => value.name == rawScope)
              .firstOrNull ??
          TlsInspectionRuleScope.exact,
    );
  }

  Map<String, Object?> toJson() => {'host': host, 'scope': scope.name};

  bool matches(String value) {
    final normalized = normalizeTlsInspectionHost(value);
    if (normalized.isEmpty || host.isEmpty) {
      return false;
    }
    return switch (scope) {
      TlsInspectionRuleScope.exact => normalized == host,
      TlsInspectionRuleScope.subdomains =>
        normalized == host || normalized.endsWith('.$host'),
    };
  }

  String get identity => '${scope.name}:$host';

  @override
  bool operator ==(Object other) =>
      other is TlsInspectionDomainRule &&
      other.host == host &&
      other.scope == scope;

  @override
  int get hashCode => Object.hash(host, scope);
}

class TlsInspectionPolicy {
  final int formatVersion;
  final bool prepared;
  final int acknowledgedRiskVersion;
  final List<TlsInspectionDomainRule> allowlist;
  final List<TlsInspectionDomainRule> exclusions;
  final String manuallyTrustedFingerprint;
  final DateTime? manuallyTrustedAt;
  final DateTime? updatedAt;

  const TlsInspectionPolicy({
    this.formatVersion = tlsInspectionPolicyFormatVersion,
    this.prepared = false,
    this.acknowledgedRiskVersion = 0,
    this.allowlist = const [],
    this.exclusions = const [],
    this.manuallyTrustedFingerprint = '',
    this.manuallyTrustedAt,
    this.updatedAt,
  });

  factory TlsInspectionPolicy.fromJson(Map<String, Object?> json) {
    List<TlsInspectionDomainRule> rules(Object? raw) {
      final values = raw is List ? raw : const <Object?>[];
      final byIdentity = <String, TlsInspectionDomainRule>{};
      for (final item in values.whereType<Map>().take(
        tlsInspectionMaxRulesPerList,
      )) {
        final rule = TlsInspectionDomainRule.fromJson(
          Map<String, Object?>.from(item),
        );
        if (rule.host.isNotEmpty) {
          byIdentity[rule.identity] = rule;
        }
      }
      return List.unmodifiable(byIdentity.values);
    }

    final rawFormatVersion = _boundedTlsInspectionInt(
      json['formatVersion'],
      min: 0,
      max: 0x7fffffff,
      fallback: tlsInspectionPolicyFormatVersion,
    );
    final supportedFormat =
        rawFormatVersion == tlsInspectionPolicyFormatVersion;
    final updatedAt = DateTime.tryParse(json['updatedAt']?.toString() ?? '');
    return TlsInspectionPolicy(
      formatVersion: tlsInspectionPolicyFormatVersion,
      prepared: supportedFormat && (json['prepared'] as bool? ?? false),
      acknowledgedRiskVersion: supportedFormat
          ? _boundedTlsInspectionInt(
              json['acknowledgedRiskVersion'],
              min: 0,
              max: tlsInspectionRiskVersion,
            )
          : 0,
      allowlist: rules(json['allowlist']),
      exclusions: rules(json['exclusions']),
      manuallyTrustedFingerprint: supportedFormat
          ? _boundedTlsInspectionString(
              json['manuallyTrustedFingerprint'],
              maxLength: 128,
            )
          : '',
      manuallyTrustedAt: supportedFormat
          ? DateTime.tryParse(
              json['manuallyTrustedAt']?.toString() ?? '',
            )?.toUtc()
          : null,
      updatedAt: updatedAt?.toUtc(),
    );
  }

  TlsInspectionPolicy copyWith({
    bool? prepared,
    int? acknowledgedRiskVersion,
    List<TlsInspectionDomainRule>? allowlist,
    List<TlsInspectionDomainRule>? exclusions,
    String? manuallyTrustedFingerprint,
    DateTime? manuallyTrustedAt,
    bool clearManualTrust = false,
    DateTime? updatedAt,
  }) {
    return TlsInspectionPolicy(
      formatVersion: tlsInspectionPolicyFormatVersion,
      prepared: prepared ?? this.prepared,
      acknowledgedRiskVersion:
          acknowledgedRiskVersion ?? this.acknowledgedRiskVersion,
      allowlist: List.unmodifiable(allowlist ?? this.allowlist),
      exclusions: List.unmodifiable(exclusions ?? this.exclusions),
      manuallyTrustedFingerprint: clearManualTrust
          ? ''
          : manuallyTrustedFingerprint ?? this.manuallyTrustedFingerprint,
      manuallyTrustedAt: clearManualTrust
          ? null
          : manuallyTrustedAt ?? this.manuallyTrustedAt,
      updatedAt: updatedAt ?? this.updatedAt,
    );
  }

  Map<String, Object?> toJson() => {
    'formatVersion': tlsInspectionPolicyFormatVersion,
    'prepared': prepared,
    'acknowledgedRiskVersion': acknowledgedRiskVersion,
    'allowlist': allowlist.map((rule) => rule.toJson()).toList(),
    'exclusions': exclusions.map((rule) => rule.toJson()).toList(),
    if (manuallyTrustedFingerprint.isNotEmpty)
      'manuallyTrustedFingerprint': manuallyTrustedFingerprint,
    if (manuallyTrustedAt != null)
      'manuallyTrustedAt': manuallyTrustedAt!.toUtc().toIso8601String(),
    if (updatedAt != null) 'updatedAt': updatedAt!.toUtc().toIso8601String(),
  };

  bool get riskAcknowledged =>
      acknowledgedRiskVersion >= tlsInspectionRiskVersion;

  bool manuallyTrusts(TlsInspectionAuthorityStatus authority) =>
      authority.validNow &&
      manuallyTrustedFingerprint.isNotEmpty &&
      manuallyTrustedFingerprint == authority.fingerprintSha256;

  bool canPrepareWith(
    TlsInspectionAuthorityStatus authority, {
    bool? trustSatisfied,
  }) =>
      authority.validNow &&
      allowlist.isNotEmpty &&
      riskAcknowledged &&
      (trustSatisfied ?? manuallyTrusts(authority));

  bool isExcluded(String host) => exclusions.any((rule) => rule.matches(host));

  bool matchesAllowlist(String host) =>
      !isExcluded(host) && allowlist.any((rule) => rule.matches(host));
}

class TlsInspectionAuthorityStatus {
  final String state;
  final bool ready;
  final String generation;
  final String fingerprintSha256;
  final String subject;
  final String serialNumber;
  final DateTime? notBefore;
  final DateTime? notAfter;
  final DateTime? createdAt;
  final String algorithm;
  final String keyStorage;
  final bool keyPermissionsRestricted;
  final String trustState;
  final String trustCapability;
  final String certificateFileName;
  final String issue;

  const TlsInspectionAuthorityStatus({
    this.state = 'unavailable',
    this.ready = false,
    this.generation = '',
    this.fingerprintSha256 = '',
    this.subject = '',
    this.serialNumber = '',
    this.notBefore,
    this.notAfter,
    this.createdAt,
    this.algorithm = '',
    this.keyStorage = 'app-data-file',
    this.keyPermissionsRestricted = false,
    this.trustState = 'unknown',
    this.trustCapability = 'manual-only',
    this.certificateFileName = 'flclash-local-inspection-ca.crt',
    this.issue = '',
  });

  factory TlsInspectionAuthorityStatus.fromJson(Map<String, Object?> json) {
    DateTime? date(Object? value) {
      final parsed = DateTime.tryParse(value?.toString() ?? '');
      if (parsed == null || parsed.year <= 1) {
        return null;
      }
      return parsed.toUtc();
    }

    String string(Object? value, {int maxLength = 512}) {
      final text = value?.toString() ?? '';
      return text.length <= maxLength ? text : text.substring(0, maxLength);
    }

    return TlsInspectionAuthorityStatus(
      state: string(json['state'], maxLength: 64),
      ready: json['ready'] is bool ? json['ready'] as bool : false,
      generation: string(json['generation'], maxLength: 64),
      fingerprintSha256: string(json['fingerprintSha256'], maxLength: 128),
      subject: string(json['subject']),
      serialNumber: string(json['serialNumber'], maxLength: 128),
      notBefore: date(json['notBefore']),
      notAfter: date(json['notAfter']),
      createdAt: date(json['createdAt']),
      algorithm: string(json['algorithm'], maxLength: 128),
      keyStorage: string(json['keyStorage'], maxLength: 64),
      keyPermissionsRestricted:
          json['keyPermissionsRestricted'] as bool? ?? false,
      trustState: string(json['trustState'], maxLength: 64),
      trustCapability: string(json['trustCapability'], maxLength: 64),
      certificateFileName: string(json['certificateFileName'], maxLength: 128),
      issue: string(json['issue'], maxLength: 128),
    );
  }

  bool get exists => state != 'missing' && state != 'unavailable';

  bool get validNow {
    final start = notBefore;
    final expiry = notAfter;
    if (!ready ||
        state != 'ready' ||
        !keyPermissionsRestricted ||
        keyStorage != 'app-data-file' ||
        algorithm != 'ECDSA P-256 / SHA-256' ||
        trustState != 'unknown' ||
        trustCapability != 'manual-only' ||
        certificateFileName != 'flclash-local-inspection-ca.crt' ||
        issue.isNotEmpty ||
        !subject.contains('CN=FlClash Local Inspection CA') ||
        serialNumber.isEmpty ||
        !_tlsInspectionGenerationPattern.hasMatch(generation) ||
        !_tlsInspectionFingerprintPattern.hasMatch(fingerprintSha256) ||
        start == null ||
        expiry == null) {
      return false;
    }
    final now = DateTime.now().toUtc();
    return !now.isBefore(start) && now.isBefore(expiry);
  }

  bool get expiresSoon {
    final expiry = notAfter;
    return validNow &&
        expiry != null &&
        expiry.difference(DateTime.now().toUtc()) < const Duration(days: 30);
  }
}

class TlsInspectionAuthorityExport {
  final String fileName;
  final String pem;
  final String fingerprintSha256;

  const TlsInspectionAuthorityExport({
    required this.fileName,
    required this.pem,
    required this.fingerprintSha256,
  });

  factory TlsInspectionAuthorityExport.fromJson(Map<String, Object?> json) {
    final rawFileName = json['fileName']?.toString() ?? '';
    final safeFileName =
        RegExp(r'^[A-Za-z0-9._-]{1,128}$').hasMatch(rawFileName)
        ? rawFileName
        : 'flclash-local-inspection-ca.crt';
    final rawPem = json['pem']?.toString() ?? '';
    final boundedPem = rawPem.length <= 64 * 1024 ? rawPem : '';
    final fingerprint = (json['fingerprintSha256']?.toString() ?? '')
        .toUpperCase();
    return TlsInspectionAuthorityExport(
      fileName: safeFileName,
      pem: _isPublicCertificatePem(boundedPem) ? boundedPem : '',
      fingerprintSha256: fingerprint.length <= 128
          ? fingerprint
          : fingerprint.substring(0, 128),
    );
  }

  bool get valid =>
      pem.isNotEmpty &&
      _tlsInspectionFingerprintPattern.hasMatch(fingerprintSha256);
}

class TlsInspectionLeafCacheStatus {
  final String state;
  final bool ready;
  final String generation;
  final String authorityFingerprintSha256;
  final String policyDigest;
  final int entryCount;
  final int capacity;
  final int leafValiditySeconds;
  final String algorithm;
  final String keyStorage;
  final bool keyPermissionsRestricted;
  final bool privateKeysExported;
  final bool runtimeAuthorizationPresent;
  final DateTime? updatedAt;
  final String issue;
  final bool contractValid;

  const TlsInspectionLeafCacheStatus({
    this.state = 'disabled',
    this.ready = false,
    this.generation = '',
    this.authorityFingerprintSha256 = '',
    this.policyDigest = '',
    this.entryCount = 0,
    this.capacity = tlsInspectionLeafCacheCapacity,
    this.leafValiditySeconds = 0,
    this.algorithm = '',
    this.keyStorage = 'app-data-file',
    this.keyPermissionsRestricted = false,
    this.privateKeysExported = false,
    this.runtimeAuthorizationPresent = false,
    this.updatedAt,
    this.issue = '',
    this.contractValid = false,
  });

  factory TlsInspectionLeafCacheStatus.fromJson(Map<String, Object?> json) {
    final rawUpdatedAtValue = json['updatedAt'];
    final rawUpdatedAt = rawUpdatedAtValue is String
        ? DateTime.tryParse(rawUpdatedAtValue)
        : null;
    final rawState = _strictTlsInspectionString(json['state'], maxLength: 64);
    final rawGeneration = _strictTlsInspectionString(
      json['generation'],
      maxLength: 64,
    );
    final rawAuthorityFingerprint = _strictTlsInspectionString(
      json['authorityFingerprintSha256'],
      maxLength: 128,
    ).toUpperCase();
    final rawPolicyDigest = _strictTlsInspectionString(
      json['policyDigest'],
      maxLength: 64,
    ).toLowerCase();
    final rawAlgorithm = _strictTlsInspectionString(
      json['algorithm'],
      maxLength: 128,
    );
    final rawKeyStorage = _strictTlsInspectionString(
      json['keyStorage'],
      maxLength: 64,
    );
    final rawIssue = json['issue'] == null
        ? ''
        : _strictTlsInspectionString(json['issue'], maxLength: 128);
    final contractValid =
        rawState.isNotEmpty &&
        json['ready'] is bool &&
        _tlsInspectionGenerationPattern.hasMatch(rawGeneration) &&
        _tlsInspectionFingerprintPattern.hasMatch(rawAuthorityFingerprint) &&
        _tlsInspectionPolicyDigestPattern.hasMatch(rawPolicyDigest) &&
        _isBoundedTlsInspectionInt(
          json['entryCount'],
          min: 0,
          max: tlsInspectionLeafCacheCapacity,
        ) &&
        _isBoundedTlsInspectionInt(
          json['capacity'],
          min: 0,
          max: tlsInspectionLeafCacheCapacity,
        ) &&
        _isBoundedTlsInspectionInt(
          json['leafValiditySeconds'],
          min: 0,
          max: tlsInspectionLeafMaxValidity.inSeconds,
        ) &&
        rawAlgorithm == 'ECDSA P-256 / SHA-256' &&
        rawKeyStorage == 'app-data-file' &&
        json['keyPermissionsRestricted'] is bool &&
        json['privateKeysExported'] is bool &&
        json['runtimeAuthorizationPresent'] is bool &&
        rawUpdatedAt != null &&
        (json['issue'] == null ||
            (json['issue'] is String &&
                (json['issue'] as String).length <= 128));
    return TlsInspectionLeafCacheStatus(
      state: rawState,
      ready: json['ready'] as bool? ?? false,
      generation: rawGeneration,
      authorityFingerprintSha256: rawAuthorityFingerprint,
      policyDigest: rawPolicyDigest,
      entryCount: _boundedTlsInspectionInt(
        json['entryCount'],
        min: 0,
        max: tlsInspectionLeafCacheCapacity,
      ),
      capacity: _boundedTlsInspectionInt(
        json['capacity'],
        min: 0,
        max: tlsInspectionLeafCacheCapacity,
      ),
      leafValiditySeconds: _boundedTlsInspectionInt(
        json['leafValiditySeconds'],
        min: 0,
        max: tlsInspectionLeafMaxValidity.inSeconds,
      ),
      algorithm: rawAlgorithm,
      keyStorage: rawKeyStorage,
      keyPermissionsRestricted: json['keyPermissionsRestricted'] is bool
          ? json['keyPermissionsRestricted'] as bool
          : false,
      privateKeysExported: json['privateKeysExported'] is bool
          ? json['privateKeysExported'] as bool
          : true,
      runtimeAuthorizationPresent: json['runtimeAuthorizationPresent'] is bool
          ? json['runtimeAuthorizationPresent'] as bool
          : false,
      updatedAt: rawUpdatedAt?.toUtc(),
      issue: rawIssue,
      contractValid: contractValid,
    );
  }

  bool matchesAuthority(TlsInspectionAuthorityStatus authority) =>
      contractValid &&
      ready &&
      state == 'ready' &&
      authority.validNow &&
      generation == authority.generation &&
      authorityFingerprintSha256 == authority.fingerprintSha256 &&
      _tlsInspectionPolicyDigestPattern.hasMatch(policyDigest) &&
      capacity > 0 &&
      capacity <= tlsInspectionLeafCacheCapacity &&
      entryCount >= 0 &&
      entryCount <= capacity &&
      leafValiditySeconds > 0 &&
      leafValiditySeconds <= tlsInspectionLeafMaxValidity.inSeconds &&
      algorithm == 'ECDSA P-256 / SHA-256' &&
      keyStorage == 'app-data-file' &&
      keyPermissionsRestricted &&
      !privateKeysExported &&
      runtimeAuthorizationPresent &&
      updatedAt != null &&
      issue.isEmpty;
}

class TlsInspectionLeafCertificateStatus {
  final String host;
  final bool cacheHit;
  final String generation;
  final String authorityFingerprintSha256;
  final String policyDigest;
  final String fingerprintSha256;
  final String serialNumber;
  final DateTime? notBefore;
  final DateTime? notAfter;
  final String algorithm;
  final String keyStorage;
  final bool privateKeyExported;
  final bool contractValid;

  const TlsInspectionLeafCertificateStatus({
    this.host = '',
    this.cacheHit = false,
    this.generation = '',
    this.authorityFingerprintSha256 = '',
    this.policyDigest = '',
    this.fingerprintSha256 = '',
    this.serialNumber = '',
    this.notBefore,
    this.notAfter,
    this.algorithm = '',
    this.keyStorage = 'app-data-file',
    this.privateKeyExported = false,
    this.contractValid = false,
  });

  factory TlsInspectionLeafCertificateStatus.fromJson(
    Map<String, Object?> json,
  ) {
    DateTime? date(String key) {
      final value = json[key];
      return value is String ? DateTime.tryParse(value)?.toUtc() : null;
    }

    final rawHost = _strictTlsInspectionString(json['host'], maxLength: 253);
    final normalizedHost = normalizeTlsInspectionHost(rawHost);
    final rawGeneration = _strictTlsInspectionString(
      json['generation'],
      maxLength: 64,
    );
    final rawAuthorityFingerprint = _strictTlsInspectionString(
      json['authorityFingerprintSha256'],
      maxLength: 128,
    ).toUpperCase();
    final rawPolicyDigest = _strictTlsInspectionString(
      json['policyDigest'],
      maxLength: 64,
    ).toLowerCase();
    final rawFingerprint = _strictTlsInspectionString(
      json['fingerprintSha256'],
      maxLength: 128,
    ).toUpperCase();
    final rawSerial = _strictTlsInspectionString(
      json['serialNumber'],
      maxLength: 128,
    );
    final rawAlgorithm = _strictTlsInspectionString(
      json['algorithm'],
      maxLength: 128,
    );
    final rawKeyStorage = _strictTlsInspectionString(
      json['keyStorage'],
      maxLength: 64,
    );
    final contractValid =
        rawHost.isNotEmpty &&
        _isValidTlsInspectionHost(normalizedHost) &&
        json['cacheHit'] is bool &&
        _tlsInspectionGenerationPattern.hasMatch(rawGeneration) &&
        _tlsInspectionFingerprintPattern.hasMatch(rawAuthorityFingerprint) &&
        _tlsInspectionPolicyDigestPattern.hasMatch(rawPolicyDigest) &&
        _tlsInspectionFingerprintPattern.hasMatch(rawFingerprint) &&
        _tlsInspectionLeafSerialPattern.hasMatch(rawSerial) &&
        date('notBefore') != null &&
        date('notAfter') != null &&
        rawAlgorithm == 'ECDSA P-256 / SHA-256' &&
        rawKeyStorage == 'app-data-file' &&
        json['privateKeyExported'] is bool;
    return TlsInspectionLeafCertificateStatus(
      host: normalizedHost,
      cacheHit: json['cacheHit'] is bool ? json['cacheHit'] as bool : false,
      generation: rawGeneration,
      authorityFingerprintSha256: rawAuthorityFingerprint,
      policyDigest: rawPolicyDigest,
      fingerprintSha256: rawFingerprint,
      serialNumber: rawSerial,
      notBefore: date('notBefore'),
      notAfter: date('notAfter'),
      algorithm: rawAlgorithm,
      keyStorage: rawKeyStorage,
      privateKeyExported: json['privateKeyExported'] is bool
          ? json['privateKeyExported'] as bool
          : true,
      contractValid: contractValid,
    );
  }

  bool validFor(
    TlsInspectionAuthorityStatus authority,
    String expectedPolicyDigest, {
    required String expectedHost,
  }) {
    final start = notBefore;
    final expiry = notAfter;
    final authorityStart = authority.notBefore;
    final authorityExpiry = authority.notAfter;
    final normalizedExpectedHost = normalizeTlsInspectionHost(expectedHost);
    if (!_isValidTlsInspectionHost(host) ||
        host != normalizedExpectedHost ||
        !authority.validNow ||
        generation != authority.generation ||
        authorityFingerprintSha256 != authority.fingerprintSha256 ||
        policyDigest != expectedPolicyDigest ||
        !_tlsInspectionPolicyDigestPattern.hasMatch(policyDigest) ||
        !_tlsInspectionFingerprintPattern.hasMatch(fingerprintSha256) ||
        serialNumber.isEmpty ||
        start == null ||
        expiry == null ||
        authorityStart == null ||
        authorityExpiry == null ||
        !expiry.isAfter(start) ||
        start.isBefore(authorityStart) ||
        expiry.isAfter(authorityExpiry) ||
        expiry.difference(start) > tlsInspectionLeafMaxValidity ||
        !_tlsInspectionLeafSerialPattern.hasMatch(serialNumber) ||
        algorithm != 'ECDSA P-256 / SHA-256' ||
        keyStorage != 'app-data-file' ||
        privateKeyExported) {
      return false;
    }
    final now = DateTime.now().toUtc();
    return !now.isBefore(start) &&
        expiry.isAfter(now.add(tlsInspectionLeafRenewBefore));
  }
}

final _tlsInspectionLeafSerialPattern = RegExp(r'^[0-9A-Fa-f]{1,32}$');
final _tlsInspectionPolicyDigestPattern = RegExp(r'^[0-9a-f]{64}$');

bool _isPublicCertificatePem(String value) {
  final normalized = value.trim();
  const begin = '-----BEGIN CERTIFICATE-----';
  const end = '-----END CERTIFICATE-----';
  return normalized.startsWith('$begin\n') &&
      normalized.endsWith(end) &&
      normalized.indexOf(begin, begin.length) == -1 &&
      !normalized.contains('PRIVATE KEY');
}

final _tlsInspectionGenerationPattern = RegExp(r'^[0-9a-fA-F]{32}$');
final _tlsInspectionFingerprintPattern = RegExp(
  r'^(?:[0-9a-fA-F]{2}:){31}[0-9a-fA-F]{2}$',
);

String normalizeTlsInspectionHost(String value) =>
    value.trim().toLowerCase().replaceFirst(RegExp(r'\.+$'), '');

bool _isValidTlsInspectionHost(String value) {
  if (value.length > 253 || !value.contains('.')) {
    return false;
  }
  final labels = value.split('.');
  for (final label in labels) {
    if (label.isEmpty || label.length > 63) {
      return false;
    }
    if (!RegExp(r'^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$').hasMatch(label)) {
      return false;
    }
  }
  return true;
}

String _strictTlsInspectionString(Object? value, {required int maxLength}) =>
    value is String && value.length <= maxLength ? value : '';

bool _isBoundedTlsInspectionInt(
  Object? value, {
  required int min,
  required int max,
}) {
  final int? parsed = switch (value) {
    final int number => number,
    final num number when number.isFinite && number == number.truncate() =>
      number.toInt(),
    _ => null,
  };
  return parsed != null && parsed >= min && parsed <= max;
}

String _boundedTlsInspectionString(Object? value, {required int maxLength}) {
  final text = value?.toString() ?? '';
  return text.length <= maxLength ? text : text.substring(0, maxLength);
}

int _boundedTlsInspectionInt(
  Object? value, {
  required int min,
  required int max,
  int fallback = 0,
}) {
  final parsed = switch (value) {
    final int number => number,
    final num number => number.toInt(),
    _ => int.tryParse(value?.toString() ?? '') ?? fallback,
  };
  return parsed.clamp(min, max);
}

extension _TlsInspectionFirstOrNull<T> on Iterable<T> {
  T? get firstOrNull => isEmpty ? null : first;
}
