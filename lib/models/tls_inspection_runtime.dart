import 'tls_inspection.dart';

class TlsInspectionRuntimeStatus {
  final String id;
  final String state;
  final String address;
  final String generation;
  final String authorityFingerprint;
  final String policyDigest;
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
          endpoint == null ||
          int.parse(endpoint.group(1)!) > 65535 ||
          expiry == null ||
          expiry.isAfter(
            DateTime.now().toUtc().add(const Duration(minutes: 11)),
          )) {
        throw const FormatException('Invalid runtime identity');
      }
    } else if (id.isNotEmpty && !_id.hasMatch(id)) {
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
      policyDigest == cache.policyDigest;

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
