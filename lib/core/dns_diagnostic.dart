part of 'controller.dart';

enum DnsDiagnosticQueryType {
  a('A'),
  aaaa('AAAA'),
  cname('CNAME'),
  mx('MX'),
  txt('TXT'),
  ns('NS'),
  soa('SOA'),
  srv('SRV'),
  ptr('PTR'),
  https('HTTPS'),
  svcb('SVCB');

  final String wireName;

  const DnsDiagnosticQueryType(this.wireName);

  static DnsDiagnosticQueryType fromWireName(String value) {
    final normalized = value.trim().toUpperCase();
    return values.firstWhere(
      (item) => item.wireName == normalized,
      orElse: () => DnsDiagnosticQueryType.a,
    );
  }
}

enum DnsDiagnosticResolver {
  defaultResolver('default'),
  system('system'),
  proxy('proxy'),
  direct('direct');

  final String wireName;

  const DnsDiagnosticResolver(this.wireName);

  static DnsDiagnosticResolver fromWireName(String value) {
    final normalized = value.trim().toLowerCase();
    return values.firstWhere(
      (item) => item.wireName == normalized,
      orElse: () => DnsDiagnosticResolver.defaultResolver,
    );
  }
}

class CoreDnsRecord {
  final String section;
  final String name;
  final String type;
  final String recordClass;
  final int ttl;
  final String data;

  const CoreDnsRecord({
    required this.section,
    required this.name,
    required this.type,
    required this.recordClass,
    required this.ttl,
    required this.data,
  });

  factory CoreDnsRecord.fromJson(Map<String, dynamic> json) {
    return CoreDnsRecord(
      section: json['section'] as String? ?? '',
      name: json['name'] as String? ?? '',
      type: json['type'] as String? ?? '',
      recordClass: json['class'] as String? ?? '',
      ttl: (json['ttl'] as num?)?.toInt() ?? 0,
      data: json['data'] as String? ?? '',
    );
  }

  Map<String, Object?> toJson() {
    return {
      'section': section,
      'name': name,
      'type': type,
      'class': recordClass,
      'ttl': ttl,
      'data': data,
    };
  }
}

class CoreDnsQueryResult {
  final String input;
  final String name;
  final String questionName;
  final DnsDiagnosticQueryType queryType;
  final DnsDiagnosticResolver requestedResolver;
  final DnsDiagnosticResolver resolver;
  final int durationMs;
  final int rcode;
  final String status;
  final bool authoritative;
  final bool truncated;
  final bool recursionAvailable;
  final bool authenticatedData;
  final bool checkingDisabled;
  final bool complete;
  final List<CoreDnsRecord> answers;
  final List<CoreDnsRecord> authority;
  final List<CoreDnsRecord> additional;
  final List<String> warnings;

  const CoreDnsQueryResult({
    required this.input,
    required this.name,
    required this.questionName,
    required this.queryType,
    required this.requestedResolver,
    required this.resolver,
    required this.durationMs,
    required this.rcode,
    required this.status,
    required this.authoritative,
    required this.truncated,
    required this.recursionAvailable,
    required this.authenticatedData,
    required this.checkingDisabled,
    required this.complete,
    required this.answers,
    required this.authority,
    required this.additional,
    required this.warnings,
  });

  factory CoreDnsQueryResult.fromJson(Map<String, dynamic> json) {
    return CoreDnsQueryResult(
      input: json['input'] as String? ?? '',
      name: json['name'] as String? ?? '',
      questionName: json['questionName'] as String? ?? '',
      queryType: DnsDiagnosticQueryType.fromWireName(
        json['queryType'] as String? ?? '',
      ),
      requestedResolver: DnsDiagnosticResolver.fromWireName(
        json['requestedResolver'] as String? ?? '',
      ),
      resolver: DnsDiagnosticResolver.fromWireName(
        json['resolver'] as String? ?? '',
      ),
      durationMs: (json['durationMs'] as num?)?.toInt() ?? 0,
      rcode: (json['rcode'] as num?)?.toInt() ?? 0,
      status: json['status'] as String? ?? '',
      authoritative: json['authoritative'] as bool? ?? false,
      truncated: json['truncated'] as bool? ?? false,
      recursionAvailable: json['recursionAvailable'] as bool? ?? false,
      authenticatedData: json['authenticatedData'] as bool? ?? false,
      checkingDisabled: json['checkingDisabled'] as bool? ?? false,
      complete: json['complete'] as bool? ?? false,
      answers: _dnsRecordsFromJson(json['answers']),
      authority: _dnsRecordsFromJson(json['authority']),
      additional: _dnsRecordsFromJson(json['additional']),
      warnings: _dnsStringsFromJson(json['warnings']),
    );
  }

  int get recordCount => answers.length + authority.length + additional.length;

  bool get hasRecords => recordCount > 0;

  Map<String, Object?> toJson() {
    return {
      'input': input,
      'name': name,
      'questionName': questionName,
      'queryType': queryType.wireName,
      'requestedResolver': requestedResolver.wireName,
      'resolver': resolver.wireName,
      'durationMs': durationMs,
      'rcode': rcode,
      'status': status,
      'authoritative': authoritative,
      'truncated': truncated,
      'recursionAvailable': recursionAvailable,
      'authenticatedData': authenticatedData,
      'checkingDisabled': checkingDisabled,
      'complete': complete,
      'answers': answers.map((item) => item.toJson()).toList(growable: false),
      'authority': authority
          .map((item) => item.toJson())
          .toList(growable: false),
      'additional': additional
          .map((item) => item.toJson())
          .toList(growable: false),
      'warnings': warnings,
    };
  }
}

List<CoreDnsRecord> _dnsRecordsFromJson(Object? value) {
  if (value is! List) {
    return const [];
  }
  return List.unmodifiable(
    value.whereType<Map>().map(
      (item) => CoreDnsRecord.fromJson(Map<String, dynamic>.from(item)),
    ),
  );
}

List<String> _dnsStringsFromJson(Object? value) {
  if (value is! List) {
    return const [];
  }
  return List.unmodifiable(value.whereType<String>());
}

extension CoreControllerDnsDiagnosticExt on CoreController {
  Future<CoreDnsQueryResult> queryDns({
    required String name,
    DnsDiagnosticQueryType queryType = DnsDiagnosticQueryType.a,
    DnsDiagnosticResolver resolver = DnsDiagnosticResolver.defaultResolver,
    Duration timeout = const Duration(seconds: 5),
  }) async {
    final data = await _interface.invokeMethod<Map<String, dynamic>>(
      method: CoreMethod.queryDns,
      arguments: {
        'name': name,
        'queryType': queryType.wireName,
        'resolver': resolver.wireName,
        'timeoutMs': timeout.inMilliseconds,
      },
      timeout: timeout + const Duration(seconds: 2),
    );
    if (data == null) {
      throw const CoreMethodException(
        code: 'empty_result',
        message: 'Core returned an empty DNS diagnostic result',
      );
    }
    return CoreDnsQueryResult.fromJson(data);
  }
}
