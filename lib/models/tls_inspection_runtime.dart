import 'common.dart';
import 'tls_inspection.dart';

class TlsInspectionRuntimeStatus {
  final String id;
  final String state;
  final String address;
  final String generation;
  final String authorityFingerprint;
  final String policyDigest;
  final String runtimeProofId;
  final DateTime? expiresAt;
  final int active;
  final int accepted;
  final int completed;
  final int failed;
  final int uploaded;
  final int downloaded;

  const TlsInspectionRuntimeStatus({
    required this.id,
    required this.state,
    required this.address,
    required this.generation,
    required this.authorityFingerprint,
    required this.policyDigest,
    required this.runtimeProofId,
    required this.expiresAt,
    required this.active,
    required this.accepted,
    required this.completed,
    required this.failed,
    required this.uploaded,
    required this.downloaded,
  });

  factory TlsInspectionRuntimeStatus.fromJson(Map<String, Object?> json) {
    final raw = json['runtime'];
    if (raw is! Map<String, dynamic> ||
        json['mode'] != 'loopback-connect-http1' ||
        _integer(json['capacity'], 16) != 16 ||
        _integer(json['connectionLifetimeSeconds'], 120) != 120 ||
        json['capturesPayload'] != false ||
        json['changesSystemProxy'] != false) {
      throw const FormatException('Invalid runtime boundary');
    }
    final state = _string(raw['state'], 16);
    if (state != 'running' && state != 'stopped') {
      throw const FormatException('Invalid runtime state');
    }
    final id = _string(raw['id'], 32);
    final address = _string(raw['address'], 21);
    final generation = _string(json['generation'], 32);
    final fingerprint = _string(json['authorityFingerprintSha256'], 95);
    final digest = _string(json['policyDigest'], 64);
    final runtimeProofId = json['runtimeProofId'] == null
        ? ''
        : _string(json['runtimeProofId'], 32);
    final date = _string(raw['expiresAt'], 64);
    final expiry = DateTime.tryParse(date)?.toUtc();
    if (state == 'running') {
      final endpoint = RegExp(
        r'^127\.0\.0\.1:([1-9][0-9]{0,4})$',
      ).firstMatch(address);
      if (!_id.hasMatch(id) ||
          !_id.hasMatch(generation) ||
          !_fingerprint.hasMatch(fingerprint) ||
          !_digest.hasMatch(digest) ||
          !_id.hasMatch(runtimeProofId) ||
          endpoint == null ||
          int.parse(endpoint.group(1)!) > 65535 ||
          expiry == null ||
          expiry.isAfter(
            DateTime.now().toUtc().add(const Duration(minutes: 11)),
          )) {
        throw const FormatException('Invalid runtime identity');
      }
    } else if ((id.isNotEmpty && !_id.hasMatch(id)) ||
        (runtimeProofId.isNotEmpty && !_id.hasMatch(runtimeProofId))) {
      throw const FormatException('Invalid stopped runtime identity');
    }
    final active = _integer(raw['active'], 16);
    final accepted = _integer(raw['accepted'], 0x1fffffffffffff);
    final completed = _integer(raw['completed'], accepted);
    final failed = _integer(raw['failed'], accepted);
    if (completed + failed + active != accepted) {
      throw const FormatException('Inconsistent runtime counters');
    }
    return TlsInspectionRuntimeStatus(
      id: id,
      state: state,
      address: address,
      generation: generation,
      authorityFingerprint: fingerprint,
      policyDigest: digest,
      runtimeProofId: runtimeProofId,
      expiresAt: expiry,
      active: active,
      accepted: accepted,
      completed: completed,
      failed: failed,
      uploaded: _integer(raw['uploaded'], 0x1fffffffffffff),
      downloaded: _integer(raw['downloaded'], 0x1fffffffffffff),
    );
  }

  bool get running =>
      state == 'running' &&
      expiresAt != null &&
      expiresAt!.isAfter(DateTime.now().toUtc());

  bool matches(
    TlsInspectionAuthorityStatus authority,
    TlsInspectionLeafCacheStatus cache,
    String expectedId,
  ) =>
      running &&
      id == expectedId &&
      cache.matchesAuthority(authority) &&
      generation == authority.generation &&
      authorityFingerprint == authority.fingerprintSha256 &&
      policyDigest == cache.policyDigest &&
      runtimeProofId == cache.runtimeProofId;

  static final _id = RegExp(r'^[0-9a-f]{32}$');
  static final _fingerprint = RegExp(r'^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$');
  static final _digest = RegExp(r'^[0-9a-f]{64}$');

  static String _string(Object? value, int maximum) {
    if (value is! String || value.length > maximum) {
      throw const FormatException('Invalid runtime string');
    }
    return value;
  }

  static int _integer(Object? value, int maximum) {
    if (value is! int || value < 0 || value > maximum) {
      throw const FormatException('Invalid runtime integer');
    }
    return value;
  }
}

class TlsInspectionRuntimeStart {
  final TlsInspectionRuntimeStatus status;
  final String username;
  final String password;

  const TlsInspectionRuntimeStart({
    required this.status,
    required this.username,
    required this.password,
  });

  factory TlsInspectionRuntimeStart.fromJson(Map<String, Object?> json) {
    final status = json['status'];
    final password = json['password'];
    if (status is! Map<String, dynamic> ||
        json['username'] != 'flclash' ||
        password is! String ||
        !RegExp(r'^[0-9a-f]{64}$').hasMatch(password)) {
      throw const FormatException('Invalid runtime start result');
    }
    return TlsInspectionRuntimeStart(
      status: TlsInspectionRuntimeStatus.fromJson(status),
      username: 'flclash',
      password: password,
    );
  }

  @override
  String toString() => 'TlsInspectionRuntimeStart(credentials redacted)';
}

class TlsInspectionRuntimeObservation {
  final String sessionId;
  final String connectionId;
  final String runtimeId;
  final String host;
  final String state;
  final DateTime startedAt;
  final DateTime? completedAt;
  final String downstreamTlsVersion;
  final String upstreamTlsVersion;
  final String alpn;
  final int uploaded;
  final int downloaded;
  final String failureKind;
  final HttpProtocolObservation? httpRequest;
  final HttpResponseProtocolObservation? httpResponse;

  const TlsInspectionRuntimeObservation({
    required this.sessionId,
    required this.connectionId,
    required this.runtimeId,
    required this.host,
    required this.state,
    required this.startedAt,
    required this.completedAt,
    required this.downstreamTlsVersion,
    required this.upstreamTlsVersion,
    required this.alpn,
    required this.uploaded,
    required this.downloaded,
    required this.failureKind,
    this.httpRequest,
    this.httpResponse,
  });

  factory TlsInspectionRuntimeObservation.fromJson(Map<String, Object?> json) {
    String requiredString(String key, int maximum) {
      final value = json[key];
      if (value is! String || value.isEmpty || value.length > maximum) {
        throw FormatException('Invalid runtime observation $key');
      }
      return value;
    }

    String optionalString(String key, int maximum) {
      final value = json[key];
      if (value == null) {
        return '';
      }
      if (value is! String || value.length > maximum) {
        throw FormatException('Invalid runtime observation $key');
      }
      return value;
    }

    int integer(String key) {
      final value = json[key];
      if (value is! int || value < 0 || value > 0x1fffffffffffff) {
        throw FormatException('Invalid runtime observation $key');
      }
      return value;
    }

    final sessionId = requiredString('sessionId', 128);
    final connectionId = requiredString('connectionId', 32);
    final runtimeId = requiredString('runtimeId', 32);
    final rawHost = requiredString('host', 253);
    final host = normalizeTlsInspectionHost(rawHost);
    final state = requiredString('state', 16);
    final startedAt = DateTime.tryParse(
      requiredString('startedAt', 64),
    )?.toUtc();
    final rawCompletedAt = json['completedAt'];
    final completedAt = rawCompletedAt == null
        ? null
        : DateTime.tryParse(requiredString('completedAt', 64))?.toUtc();
    final downstream = optionalString('downstreamTlsVersion', 16);
    final upstream = optionalString('upstreamTlsVersion', 16);
    final alpn = optionalString('alpn', 16);
    final failure = optionalString('failureKind', 32);
    final httpRequest = _runtimeHttpRequest(json['httpRequest']);
    final httpResponse = _runtimeHttpResponse(json['httpResponse']);
    final hasHttpMetadata = httpRequest != null || httpResponse != null;
    final validHost = rawHost == host && _validRuntimeHttpHost(host);
    const versions = {'', 'TLS 1.2', 'TLS 1.3'};
    const failures = {
      '',
      'upstream-dial',
      'upstream-tls',
      'leaf',
      'downstream-tls',
      'authorization-revoked',
      'relay',
      'capture-stopped',
      'capture-interrupted',
    };
    if (!sessionId.startsWith('http-capture:') ||
        !TlsInspectionRuntimeStatus._id.hasMatch(connectionId) ||
        !TlsInspectionRuntimeStatus._id.hasMatch(runtimeId) ||
        !validHost ||
        !const {
          'running',
          'completed',
          'failed',
          'interrupted',
        }.contains(state) ||
        startedAt == null ||
        (state == 'running' && completedAt != null) ||
        (state != 'running' &&
            (completedAt == null || completedAt.isBefore(startedAt))) ||
        !versions.contains(downstream) ||
        !versions.contains(upstream) ||
        (alpn.isNotEmpty && alpn != 'http/1.1') ||
        (httpResponse != null && httpRequest == null) ||
        (hasHttpMetadata && (downstream.isEmpty || upstream.isEmpty)) ||
        !failures.contains(failure) ||
        ((state == 'failed' || state == 'interrupted') != failure.isNotEmpty)) {
      throw const FormatException('Invalid runtime observation contract');
    }
    return TlsInspectionRuntimeObservation(
      sessionId: sessionId,
      connectionId: connectionId,
      runtimeId: runtimeId,
      host: host,
      state: state,
      startedAt: startedAt,
      completedAt: completedAt,
      downstreamTlsVersion: downstream,
      upstreamTlsVersion: upstream,
      alpn: alpn,
      uploaded: integer('uploaded'),
      downloaded: integer('downloaded'),
      failureKind: failure,
      httpRequest: httpRequest,
      httpResponse: httpResponse,
    );
  }

  Map<String, Object?> toJson() => {
    'sessionId': sessionId,
    'connectionId': connectionId,
    'runtimeId': runtimeId,
    'host': host,
    'state': state,
    'startedAt': startedAt.toUtc().toIso8601String(),
    if (completedAt != null)
      'completedAt': completedAt!.toUtc().toIso8601String(),
    if (downstreamTlsVersion.isNotEmpty)
      'downstreamTlsVersion': downstreamTlsVersion,
    if (upstreamTlsVersion.isNotEmpty) 'upstreamTlsVersion': upstreamTlsVersion,
    if (alpn.isNotEmpty) 'alpn': alpn,
    'uploaded': uploaded,
    'downloaded': downloaded,
    if (failureKind.isNotEmpty) 'failureKind': failureKind,
    if (httpRequest != null) 'httpRequest': httpRequest!.toJson(),
    if (httpResponse != null) 'httpResponse': httpResponse!.toJson(),
  };

  bool get completed =>
      state == 'completed' || state == 'failed' || state == 'interrupted';

  int get metadataRank =>
      (httpRequest == null ? 0 : 1) + (httpResponse == null ? 0 : 2);

  TlsInspectionRuntimeObservation merge(TlsInspectionRuntimeObservation other) {
    if (sessionId != other.sessionId ||
        connectionId != other.connectionId ||
        runtimeId != other.runtimeId ||
        host != other.host) {
      return this;
    }
    int stateRank(String value) => switch (value) {
      'completed' || 'failed' => 2,
      'interrupted' => 1,
      'running' => 0,
      _ => -1,
    };
    final preferred = stateRank(other.state) > stateRank(state) ? other : this;
    final alternate = identical(preferred, this) ? other : this;
    String richer(String primary, String fallback) =>
        primary.isNotEmpty ? primary : fallback;
    return TlsInspectionRuntimeObservation(
      sessionId: sessionId,
      connectionId: connectionId,
      runtimeId: runtimeId,
      host: host,
      state: preferred.state,
      startedAt: startedAt.isBefore(other.startedAt)
          ? startedAt
          : other.startedAt,
      completedAt: preferred.completedAt ?? alternate.completedAt,
      downstreamTlsVersion: richer(
        preferred.downstreamTlsVersion,
        alternate.downstreamTlsVersion,
      ),
      upstreamTlsVersion: richer(
        preferred.upstreamTlsVersion,
        alternate.upstreamTlsVersion,
      ),
      alpn: richer(preferred.alpn, alternate.alpn),
      uploaded: uploaded > other.uploaded ? uploaded : other.uploaded,
      downloaded: downloaded > other.downloaded ? downloaded : other.downloaded,
      failureKind:
          preferred.state == 'failed' || preferred.state == 'interrupted'
          ? preferred.failureKind
          : '',
      httpRequest: httpRequest ?? other.httpRequest,
      httpResponse: httpResponse ?? other.httpResponse,
    );
  }

  TlsInspectionRuntimeObservation interrupt({
    required DateTime completedAt,
    required String failureKind,
  }) {
    if (state != 'running' ||
        !const {
          'capture-stopped',
          'capture-interrupted',
        }.contains(failureKind)) {
      return this;
    }
    return TlsInspectionRuntimeObservation(
      sessionId: sessionId,
      connectionId: connectionId,
      runtimeId: runtimeId,
      host: host,
      state: 'interrupted',
      startedAt: startedAt,
      completedAt: completedAt.toUtc(),
      downstreamTlsVersion: downstreamTlsVersion,
      upstreamTlsVersion: upstreamTlsVersion,
      alpn: alpn,
      uploaded: uploaded,
      downloaded: downloaded,
      failureKind: failureKind,
      httpRequest: httpRequest,
      httpResponse: httpResponse,
    );
  }
}

final _runtimeHttpToken = RegExp(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$");

HttpProtocolObservation? _runtimeHttpRequest(Object? raw) {
  if (raw == null) {
    return null;
  }
  if (raw is! Map) {
    throw const FormatException('Invalid runtime HTTP request');
  }
  final json = Map<String, Object?>.from(raw);
  final method = json['method'];
  final target = json['target'];
  final version = json['version'];
  final host = json['host'] ?? '';
  final headersComplete = json['headersComplete'];
  final targetTruncated = json['targetTruncated'] ?? false;
  final hostTruncated = json['hostTruncated'] ?? false;
  final headerNamesTruncated = json['headerNamesTruncated'] ?? false;
  if (method is! String ||
      method.isEmpty ||
      method.length > 16 ||
      !_runtimeHttpToken.hasMatch(method) ||
      target is! String ||
      target.isEmpty ||
      target.length > 512 ||
      target.contains('?') ||
      target.contains('#') ||
      target.codeUnits.any((value) => value < 0x20 || value == 0x7f) ||
      version is! String ||
      !const {'HTTP/1.0', 'HTTP/1.1'}.contains(version) ||
      host is! String ||
      host.length > 255 ||
      (host.isNotEmpty && !_validRuntimeHttpHost(host)) ||
      headersComplete is! bool ||
      targetTruncated is! bool ||
      hostTruncated is! bool ||
      headerNamesTruncated is! bool ||
      (method != 'CONNECT' && target != '*' && !target.startsWith('/'))) {
    throw const FormatException('Invalid runtime HTTP request contract');
  }
  return HttpProtocolObservation(
    method: method,
    target: target,
    version: version,
    host: host,
    headerNames: _runtimeHttpHeaderNames(json['headerNames']),
    headersComplete: headersComplete,
    targetTruncated: targetTruncated,
    hostTruncated: hostTruncated,
    headerNamesTruncated: headerNamesTruncated,
  );
}

HttpResponseProtocolObservation? _runtimeHttpResponse(Object? raw) {
  if (raw == null) {
    return null;
  }
  if (raw is! Map) {
    throw const FormatException('Invalid runtime HTTP response');
  }
  final json = Map<String, Object?>.from(raw);
  final version = json['version'] ?? '';
  final statusCode = json['statusCode'] ?? 0;
  final headersComplete = json['headersComplete'];
  final observedBytes = json['observedBytes'];
  final observedAfter = json['observedAfterMilliseconds'] ?? 0;
  final truncated = json['truncated'] ?? false;
  final headerNamesTruncated = json['headerNamesTruncated'] ?? false;
  final informationalTruncated =
      json['informationalStatusCodesTruncated'] ?? false;
  final informational = _runtimeInformationalStatusCodes(
    json['informationalStatusCodes'],
  );
  final validStatus =
      statusCode is int &&
      (statusCode == 0 ||
          statusCode == 101 ||
          (statusCode >= 200 && statusCode <= 599));
  if (version is! String ||
      !const {'', 'HTTP/1.0', 'HTTP/1.1'}.contains(version) ||
      !validStatus ||
      headersComplete is! bool ||
      observedBytes is! int ||
      observedBytes <= 0 ||
      observedBytes > 32 * 1024 ||
      observedAfter is! int ||
      observedAfter < 0 ||
      observedAfter > 0x7fffffff ||
      truncated is! bool ||
      headerNamesTruncated is! bool ||
      informationalTruncated is! bool ||
      (statusCode != 0 && version.isEmpty) ||
      (headersComplete && statusCode == 0)) {
    throw const FormatException('Invalid runtime HTTP response contract');
  }
  final headerNames = _runtimeHttpHeaderNames(json['headerNames']);
  if (statusCode == 0 &&
      (version.isNotEmpty ||
          headerNames.isNotEmpty ||
          informational.isEmpty ||
          !truncated)) {
    throw const FormatException('Invalid runtime HTTP response contract');
  }
  return HttpResponseProtocolObservation(
    version: version,
    statusCode: statusCode,
    informationalStatusCodes: informational,
    headerNames: headerNames,
    headersComplete: headersComplete,
    observedBytes: observedBytes,
    observedAfterMilliseconds: observedAfter,
    truncated: truncated,
    headerNamesTruncated: headerNamesTruncated,
    informationalStatusCodesTruncated: informationalTruncated,
  );
}

List<String> _runtimeHttpHeaderNames(Object? raw) {
  if (raw == null) {
    return const [];
  }
  if (raw is! List || raw.length > 64) {
    throw const FormatException('Invalid runtime HTTP header names');
  }
  final result = <String>[];
  final seen = <String>{};
  for (final value in raw) {
    if (value is! String ||
        value.isEmpty ||
        value.length > 128 ||
        value != value.toLowerCase() ||
        !_runtimeHttpToken.hasMatch(value) ||
        !seen.add(value)) {
      throw const FormatException('Invalid runtime HTTP header name');
    }
    result.add(value);
  }
  return List.unmodifiable(result);
}

List<int> _runtimeInformationalStatusCodes(Object? raw) {
  if (raw == null) {
    return const [];
  }
  if (raw is! List || raw.length > 8) {
    throw const FormatException('Invalid runtime informational statuses');
  }
  final result = <int>[];
  for (final value in raw) {
    if (value is! int || value < 100 || value >= 200 || value == 101) {
      throw const FormatException('Invalid runtime informational status');
    }
    result.add(value);
  }
  return List.unmodifiable(result);
}

bool _validRuntimeHttpHost(String value) {
  if (value.isEmpty ||
      value.length > 253 ||
      value != value.toLowerCase() ||
      !value.contains('.') ||
      value.endsWith('.')) {
    return false;
  }
  return value
      .split('.')
      .every(
        (label) =>
            label.isNotEmpty &&
            label.length <= 63 &&
            RegExp(r'^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$').hasMatch(label),
      );
}
