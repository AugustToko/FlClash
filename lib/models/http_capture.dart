import 'dart:convert';

import 'common.dart';

enum HttpCaptureProtocol {
  http,
  tls,
  quic,
  unknown;

  static HttpCaptureProtocol fromName(Object? value) {
    final name = value?.toString().toLowerCase() ?? '';
    return HttpCaptureProtocol.values.firstWhere(
      (item) => item.name == name,
      orElse: () => HttpCaptureProtocol.unknown,
    );
  }

  String get scheme => switch (this) {
    HttpCaptureProtocol.http => 'http',
    HttpCaptureProtocol.tls || HttpCaptureProtocol.quic => 'https',
    HttpCaptureProtocol.unknown => '',
  };
}

class HttpCaptureEntry {
  static const formatVersion = 2;

  final int id;
  final String connectionId;
  final String sessionId;
  final int? profileId;
  final DateTime startedAt;
  final DateTime observedAt;
  final HttpCaptureProtocol protocol;
  final String evidence;
  final String network;
  final String host;
  final String destinationIP;
  final int destinationPort;
  final String sourceIP;
  final int sourcePort;
  final String process;
  final String processPath;
  final int uid;
  final String rule;
  final String rulePayload;
  final List<String> chains;
  final int upload;
  final int download;
  final String remoteDestination;
  final ProtocolObservation? observation;

  const HttpCaptureEntry({
    required this.id,
    required this.connectionId,
    required this.sessionId,
    required this.profileId,
    required this.startedAt,
    required this.observedAt,
    required this.protocol,
    required this.evidence,
    required this.network,
    required this.host,
    required this.destinationIP,
    required this.destinationPort,
    required this.sourceIP,
    required this.sourcePort,
    required this.process,
    required this.processPath,
    required this.uid,
    required this.rule,
    required this.rulePayload,
    required this.chains,
    required this.upload,
    required this.download,
    required this.remoteDestination,
    this.observation,
  });

  factory HttpCaptureEntry.fromTracker({
    required int id,
    required TrackerInfo tracker,
    required String sessionId,
    required int? profileId,
    DateTime? observedAt,
  }) {
    final metadata = tracker.metadata;
    final destinationPort = int.tryParse(metadata.destinationPort) ?? 0;
    final sourcePort = int.tryParse(metadata.sourcePort) ?? 0;
    final observation = tracker.observation;
    final classification = classifyHttpObservation(
      network: metadata.network,
      port: destinationPort,
      host: metadata.host,
      remoteDestination: metadata.remoteDestination,
      observation: observation,
    );
    final observedHost = switch (observation) {
      ProtocolObservation(http: final http?) when http.host.isNotEmpty =>
        http.host,
      ProtocolObservation(tls: final tls?) when tls.serverName.isNotEmpty =>
        tls.serverName,
      _ => metadata.host,
    };
    return HttpCaptureEntry(
      id: id,
      connectionId: tracker.id,
      sessionId: sessionId,
      profileId: profileId,
      startedAt: tracker.start,
      observedAt: observedAt ?? DateTime.now(),
      protocol: classification.protocol,
      evidence: classification.evidence,
      network: metadata.network.toLowerCase(),
      host: observedHost.trim().toLowerCase(),
      destinationIP: metadata.destinationIP.trim(),
      destinationPort: destinationPort,
      sourceIP: metadata.sourceIP.trim(),
      sourcePort: sourcePort,
      process: metadata.process.trim(),
      processPath: metadata.processPath.trim(),
      uid: metadata.uid,
      rule: tracker.rule,
      rulePayload: tracker.rulePayload,
      chains: List.unmodifiable(tracker.chains),
      upload: tracker.upload,
      download: tracker.download,
      remoteDestination: metadata.remoteDestination.trim(),
      observation: observation,
    );
  }

  factory HttpCaptureEntry.fromJson(Map<String, Object?> json) {
    List<String> strings(Object? value) => value is List
        ? List.unmodifiable(value.whereType<String>())
        : const <String>[];
    DateTime date(Object? value) =>
        DateTime.tryParse(value?.toString() ?? '') ??
        DateTime.fromMillisecondsSinceEpoch(0, isUtc: true);
    int integer(Object? value) => switch (value) {
      final int number => number,
      final num number => number.toInt(),
      _ => int.tryParse(value?.toString() ?? '') ?? 0,
    };
    final rawObservation = json['observation'];

    return HttpCaptureEntry(
      id: integer(json['id']),
      connectionId: json['connectionId'] as String? ?? '',
      sessionId: json['sessionId'] as String? ?? '',
      profileId: json['profileId'] == null ? null : integer(json['profileId']),
      startedAt: date(json['startedAt']),
      observedAt: date(json['observedAt']),
      protocol: HttpCaptureProtocol.fromName(json['protocol']),
      evidence: json['evidence'] as String? ?? 'unknown',
      network: json['network'] as String? ?? '',
      host: json['host'] as String? ?? '',
      destinationIP: json['destinationIP'] as String? ?? '',
      destinationPort: integer(json['destinationPort']),
      sourceIP: json['sourceIP'] as String? ?? '',
      sourcePort: integer(json['sourcePort']),
      process: json['process'] as String? ?? '',
      processPath: json['processPath'] as String? ?? '',
      uid: integer(json['uid']),
      rule: json['rule'] as String? ?? '',
      rulePayload: json['rulePayload'] as String? ?? '',
      chains: strings(json['chains']),
      upload: integer(json['upload']),
      download: integer(json['download']),
      remoteDestination: json['remoteDestination'] as String? ?? '',
      observation: rawObservation is Map
          ? ProtocolObservation.fromJson(
              Map<String, Object?>.from(rawObservation),
            )
          : null,
    );
  }

  Map<String, Object?> toJson() => {
    'version': formatVersion,
    'id': id,
    'connectionId': connectionId,
    'sessionId': sessionId,
    'profileId': profileId,
    'startedAt': startedAt.toUtc().toIso8601String(),
    'observedAt': observedAt.toUtc().toIso8601String(),
    'protocol': protocol.name,
    'evidence': evidence,
    'network': network,
    'host': host,
    'destinationIP': destinationIP,
    'destinationPort': destinationPort,
    'sourceIP': sourceIP,
    'sourcePort': sourcePort,
    'process': process,
    'processPath': processPath,
    'uid': uid,
    'rule': rule,
    'rulePayload': rulePayload,
    'chains': chains,
    'upload': upload,
    'download': download,
    'remoteDestination': remoteDestination,
    if (observation != null) 'observation': observation!.toJson(),
  };

  String encodePayload() => jsonEncode(toJson());

  static HttpCaptureEntry decodePayload(String payload) {
    final decoded = jsonDecode(payload);
    if (decoded is! Map) {
      throw const FormatException('HTTP capture payload is not an object');
    }
    return HttpCaptureEntry.fromJson(Map<String, Object?>.from(decoded));
  }

  HttpCaptureEntry copyWith({
    int? id,
    String? connectionId,
    String? sessionId,
    int? profileId,
    bool clearProfileId = false,
    DateTime? startedAt,
    DateTime? observedAt,
    HttpCaptureProtocol? protocol,
    String? evidence,
    String? network,
    String? host,
    String? destinationIP,
    int? destinationPort,
    String? sourceIP,
    int? sourcePort,
    String? process,
    String? processPath,
    int? uid,
    String? rule,
    String? rulePayload,
    List<String>? chains,
    int? upload,
    int? download,
    String? remoteDestination,
    ProtocolObservation? observation,
    bool clearObservation = false,
  }) {
    return HttpCaptureEntry(
      id: id ?? this.id,
      connectionId: connectionId ?? this.connectionId,
      sessionId: sessionId ?? this.sessionId,
      profileId: clearProfileId ? null : profileId ?? this.profileId,
      startedAt: startedAt ?? this.startedAt,
      observedAt: observedAt ?? this.observedAt,
      protocol: protocol ?? this.protocol,
      evidence: evidence ?? this.evidence,
      network: network ?? this.network,
      host: host ?? this.host,
      destinationIP: destinationIP ?? this.destinationIP,
      destinationPort: destinationPort ?? this.destinationPort,
      sourceIP: sourceIP ?? this.sourceIP,
      sourcePort: sourcePort ?? this.sourcePort,
      process: process ?? this.process,
      processPath: processPath ?? this.processPath,
      uid: uid ?? this.uid,
      rule: rule ?? this.rule,
      rulePayload: rulePayload ?? this.rulePayload,
      chains: List.unmodifiable(chains ?? this.chains),
      upload: upload ?? this.upload,
      download: download ?? this.download,
      remoteDestination: remoteDestination ?? this.remoteDestination,
      observation: clearObservation ? null : observation ?? this.observation,
    );
  }

  String get scopeKey => profileId == null ? 'global' : 'profile:$profileId';

  String get endpointHost => host.isNotEmpty ? host : destinationIP;

  bool get isHttpCandidate =>
      observation != null ||
      protocol != HttpCaptureProtocol.unknown ||
      (network == 'tcp' && host.isNotEmpty);

  bool get harObservationOnly => true;

  bool get isCoreObserved => observation != null;

  HttpProtocolObservation? get httpObservation => observation?.http;

  TlsClientHelloObservation? get tlsObservation => observation?.tls;

  int get observationDelayMs {
    final value = observedAt.difference(startedAt).inMilliseconds;
    return value < 0 ? 0 : value;
  }

  String get authority {
    final value = endpointHost;
    if (value.isEmpty) {
      return '';
    }
    final formatted = value.contains(':') && !value.startsWith('[')
        ? '[$value]'
        : value;
    if (destinationPort <= 0) {
      return formatted;
    }
    final defaultPort = switch (protocol.scheme) {
      'http' => 80,
      'https' => 443,
      _ => -1,
    };
    return destinationPort == defaultPort
        ? formatted
        : '$formatted:$destinationPort';
  }

  String get origin {
    final value = authority;
    if (value.isEmpty) {
      return '';
    }
    final scheme = protocol.scheme;
    if (scheme.isNotEmpty) {
      return '$scheme://$value';
    }
    final transport = network.isEmpty ? 'tcp' : network;
    return '$transport://$value';
  }

  String get requestUrl {
    final base = origin;
    final http = httpObservation;
    if (base.isEmpty) {
      return http?.target.isNotEmpty == true ? http!.target : 'unknown://';
    }
    final target = http?.target ?? '';
    if (target.isEmpty) {
      return '$base/';
    }
    if (http?.method == 'CONNECT') {
      return 'https://$target/';
    }
    if (target == '*') {
      return '$base/*';
    }
    return target.startsWith('/') ? '$base$target' : '$base/$target';
  }

  String get ruleText {
    if (rule.isEmpty) {
      return '';
    }
    return rulePayload.isEmpty ? rule : '$rule($rulePayload)';
  }

  String get searchText {
    final http = httpObservation;
    final tls = tlsObservation;
    return [
      sessionId,
      protocol.name,
      evidence,
      network,
      host,
      destinationIP,
      destinationPort,
      sourceIP,
      sourcePort,
      process,
      processPath,
      uid,
      rule,
      rulePayload,
      chains.join(' '),
      remoteDestination,
      origin,
      observation?.kind ?? '',
      observation?.observedBytes ?? 0,
      http?.method ?? '',
      http?.target ?? '',
      http?.version ?? '',
      http?.host ?? '',
      http?.headerNames.join(' ') ?? '',
      tls?.serverName ?? '',
      tls?.alpn.join(' ') ?? '',
      tls?.legacyVersion ?? '',
      tls?.supportedVersions.join(' ') ?? '',
      if (tls?.encryptedClientHello == true) 'ech',
    ].join('\n').toLowerCase();
  }

  TrackerInfo toTrackerInfo() {
    return TrackerInfo(
      id: connectionId,
      upload: upload,
      download: download,
      start: startedAt,
      metadata: Metadata(
        uid: uid,
        network: network,
        sourceIP: sourceIP,
        sourcePort: sourcePort == 0 ? '' : '$sourcePort',
        destinationIP: destinationIP,
        destinationPort: destinationPort == 0 ? '' : '$destinationPort',
        host: host,
        process: process,
        processPath: processPath,
        remoteDestination: remoteDestination,
      ),
      chains: chains,
      rule: rule,
      rulePayload: rulePayload,
      observation: observation,
    );
  }
}

({HttpCaptureProtocol protocol, String evidence}) classifyHttpObservation({
  required String network,
  required int port,
  required String host,
  required String remoteDestination,
  ProtocolObservation? observation,
}) {
  if (observation?.kind == 'http1' && observation?.http != null) {
    return (protocol: HttpCaptureProtocol.http, evidence: 'core-http1');
  }
  if (observation?.kind == 'tls-client-hello' && observation?.tls != null) {
    return (
      protocol: HttpCaptureProtocol.tls,
      evidence: 'core-tls-client-hello',
    );
  }

  final remote = Uri.tryParse(remoteDestination.trim());
  if (remote?.scheme == 'http') {
    return (protocol: HttpCaptureProtocol.http, evidence: 'remote-scheme');
  }
  if (remote?.scheme == 'https') {
    return (protocol: HttpCaptureProtocol.tls, evidence: 'remote-scheme');
  }

  final normalizedNetwork = network.toLowerCase();
  if (normalizedNetwork == 'udp' &&
      const {443, 784, 8443, 8853}.contains(port)) {
    return (protocol: HttpCaptureProtocol.quic, evidence: 'known-quic-port');
  }
  if (normalizedNetwork == 'tcp' &&
      const {80, 3000, 5000, 8000, 8080, 8888}.contains(port)) {
    return (protocol: HttpCaptureProtocol.http, evidence: 'known-http-port');
  }
  if (normalizedNetwork == 'tcp' &&
      const {443, 4443, 8443, 9443, 10443}.contains(port)) {
    return (protocol: HttpCaptureProtocol.tls, evidence: 'known-tls-port');
  }
  if (normalizedNetwork == 'tcp' && host.trim().isNotEmpty) {
    return (protocol: HttpCaptureProtocol.unknown, evidence: 'host-observed');
  }
  return (protocol: HttpCaptureProtocol.unknown, evidence: 'transport-only');
}

bool shouldCaptureHttpObservation(TrackerInfo tracker) {
  if (tracker.observation != null) {
    return true;
  }
  final metadata = tracker.metadata;
  final network = metadata.network.toLowerCase();
  final port = int.tryParse(metadata.destinationPort) ?? 0;
  final classified = classifyHttpObservation(
    network: network,
    port: port,
    host: metadata.host,
    remoteDestination: metadata.remoteDestination,
  );
  if (classified.protocol != HttpCaptureProtocol.unknown) {
    return true;
  }
  return network == 'tcp' && metadata.host.trim().isNotEmpty;
}

Map<String, Object?> buildHttpCaptureHar({
  required Iterable<HttpCaptureEntry> entries,
  DateTime? exportedAt,
  String creatorVersion = 'passive-2',
}) {
  final ordered = entries.toList(growable: false)
    ..sort((a, b) {
      final time = a.startedAt.compareTo(b.startedAt);
      return time != 0 ? time : a.id.compareTo(b.id);
    });
  final timestamp = (exportedAt ?? DateTime.now()).toUtc();
  return {
    'log': {
      'version': '1.2',
      'creator': {'name': 'FlClash', 'version': creatorVersion},
      'pages': const <Object?>[],
      'entries': [for (final entry in ordered) _httpCaptureHarEntry(entry)],
      '_flclash': {
        'format': 'flclash-passive-http-observation',
        'version': 2,
        'observationOnly': true,
        'exportedAt': timestamp.toIso8601String(),
        'limitations': const [
          'initial-client-prefix-only',
          'later-keep-alive-requests-not-captured',
          'request-method-only-for-observed-http1',
          'request-target-query-and-fragment-removed',
          'header-values-not-captured',
          'response-status-not-captured',
          'response-headers-not-captured',
          'body-not-captured',
          'timings-not-captured',
          'tls-not-decrypted',
        ],
      },
    },
  };
}

String encodeHttpCaptureHar({
  required Iterable<HttpCaptureEntry> entries,
  DateTime? exportedAt,
  String creatorVersion = 'passive-2',
}) {
  return const JsonEncoder.withIndent('  ').convert(
    buildHttpCaptureHar(
      entries: entries,
      exportedAt: exportedAt,
      creatorVersion: creatorVersion,
    ),
  );
}

Map<String, Object?> _httpCaptureHarEntry(HttpCaptureEntry entry) {
  final http = entry.httpObservation;
  return {
    'startedDateTime': entry.startedAt.toUtc().toIso8601String(),
    'time': 0,
    'request': {
      'method': http?.method.isNotEmpty == true ? http!.method : 'UNKNOWN',
      'url': entry.requestUrl,
      'httpVersion': http?.version ?? '',
      'cookies': const <Object?>[],
      // Header values are deliberately not retained. Names are kept only in
      // the FlClash extension below so an empty value is never fabricated.
      'headers': const <Object?>[],
      'queryString': const <Object?>[],
      'headersSize': -1,
      'bodySize': -1,
    },
    'response': {
      'status': 0,
      'statusText': 'Not captured',
      'httpVersion': '',
      'cookies': const <Object?>[],
      'headers': const <Object?>[],
      'content': {'size': -1, 'mimeType': ''},
      'redirectURL': '',
      'headersSize': -1,
      'bodySize': -1,
    },
    'cache': const <String, Object?>{},
    'timings': const {
      'blocked': -1,
      'dns': -1,
      'connect': -1,
      'ssl': -1,
      'send': -1,
      'wait': -1,
      'receive': -1,
    },
    'serverIPAddress': entry.destinationIP,
    'connection': entry.connectionId,
    '_flclash': {
      'observationOnly': true,
      'sessionId': entry.sessionId,
      'protocol': entry.protocol.name,
      'evidence': entry.evidence,
      'network': entry.network,
      'observationDelayMs': entry.observationDelayMs,
      'process': entry.process,
      'uid': entry.uid,
      'rule': entry.ruleText,
      'policyChain': entry.chains,
      'uploadAtObservation': entry.upload,
      'downloadAtObservation': entry.download,
      if (entry.observation != null)
        'coreObservation': entry.observation!.toJson(),
      if (http != null) ...{
        'headerNames': http.headerNames,
        'headersComplete': http.headersComplete,
        'headerNamesTruncated': http.headerNamesTruncated,
      },
    },
  };
}
