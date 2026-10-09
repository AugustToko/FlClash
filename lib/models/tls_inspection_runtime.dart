import 'common.dart';
import 'http_inspection.dart';
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
  final String mode;
  final TlsInspectionCapturePolicy capturePolicy;

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
    this.mode = 'loopback-connect-http1',
    this.capturePolicy = TlsInspectionCapturePolicy.metadataOnly,
  });

  factory TlsInspectionRuntimeStatus.fromJson(Map<String, Object?> json) {
    final raw = json['runtime'];
    if (raw is! Map) {
      throw const FormatException('Invalid runtime boundary');
    }
    final runtime = Map<String, Object?>.from(raw);
    final mode = _string(json['mode'], 64);
    if (!const {
          'loopback-connect-http1',
          'loopback-connect-http1-h2',
        }.contains(mode) ||
        _integer(json['capacity'], 16) != 16 ||
        _integer(json['connectionLifetimeSeconds'], 120) != 120 ||
        json['changesSystemProxy'] != false) {
      throw const FormatException('Invalid runtime boundary');
    }
    final rawPolicy = json['capturePolicy'];
    if (rawPolicy != null && rawPolicy is! Map) {
      throw const FormatException('Invalid runtime capture policy');
    }
    final capturePolicy = rawPolicy == null
        ? TlsInspectionCapturePolicy.metadataOnly
        : TlsInspectionCapturePolicy.fromJson(
            Map<String, dynamic>.from(rawPolicy as Map),
          );
    final capturesPayload = json['capturesPayload'];
    if (capturesPayload is! bool ||
        capturesPayload != capturePolicy.capturesBodies) {
      throw const FormatException('Invalid runtime payload boundary');
    }
    final state = _string(runtime['state'], 16);
    if (state != 'running' && state != 'stopped') {
      throw const FormatException('Invalid runtime state');
    }
    final id = _string(runtime['id'], 32);
    final address = _string(runtime['address'], 21);
    final generation = _string(json['generation'], 32);
    final fingerprint = _string(json['authorityFingerprintSha256'], 95);
    final digest = _string(json['policyDigest'], 64);
    final runtimeProofId = json['runtimeProofId'] == null
        ? ''
        : _string(json['runtimeProofId'], 32);
    final date = _string(runtime['expiresAt'], 64);
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
    final active = _integer(runtime['active'], 16);
    final accepted = _integer(runtime['accepted'], 0x1fffffffffffff);
    final completed = _integer(runtime['completed'], accepted);
    final failed = _integer(runtime['failed'], accepted);
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
      uploaded: _integer(runtime['uploaded'], 0x1fffffffffffff),
      downloaded: _integer(runtime['downloaded'], 0x1fffffffffffff),
      mode: mode,
      capturePolicy: capturePolicy,
    );
  }

  bool get running =>
      state == 'running' &&
      expiresAt != null &&
      expiresAt!.isAfter(DateTime.now().toUtc());

  bool get supportsHttp2 => mode == 'loopback-connect-http1-h2';

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
    if (status is! Map ||
        json['username'] != 'flclash' ||
        password is! String ||
        !RegExp(r'^[0-9a-f]{64}$').hasMatch(password)) {
      throw const FormatException('Invalid runtime start result');
    }
    return TlsInspectionRuntimeStart(
      status: TlsInspectionRuntimeStatus.fromJson(
        Map<String, Object?>.from(status),
      ),
      username: 'flclash',
      password: password,
    );
  }

  @override
  String toString() => 'TlsInspectionRuntimeStart(credentials redacted)';
}

class TlsInspectionRuntimeHttpTransaction {
  static const maximumCount = 32;

  final int sequence;
  final int requestObservedAfterMilliseconds;
  final int requestCompletedAfterMilliseconds;
  final int responseCompletedAfterMilliseconds;
  final HttpProtocolObservation request;
  final TlsInspectionRuntimeHttpBody? requestBody;
  final HttpResponseProtocolObservation? response;
  final TlsInspectionRuntimeHttpBody? responseBody;

  const TlsInspectionRuntimeHttpTransaction({
    required this.sequence,
    required this.requestObservedAfterMilliseconds,
    this.requestCompletedAfterMilliseconds = 0,
    this.responseCompletedAfterMilliseconds = 0,
    required this.request,
    this.requestBody,
    required this.response,
    this.responseBody,
  });

  factory TlsInspectionRuntimeHttpTransaction.fromJson(
    Map<String, Object?> json, {
    required String runtimeHost,
    bool legacy = false,
  }) {
    final sequence = _runtimeInteger(
      json['sequence'],
      maximumCount,
      minimum: 1,
    );
    final requestObservedAfter = _runtimeInteger(
      json['requestObservedAfterMilliseconds'] ?? 0,
      0x7fffffff,
    );
    final requestCompletedAfter = _runtimeInteger(
      json['requestCompletedAfterMilliseconds'] ?? 0,
      0x7fffffff,
    );
    final responseCompletedAfter = _runtimeInteger(
      json['responseCompletedAfterMilliseconds'] ?? 0,
      0x7fffffff,
    );
    final request = _runtimeHttpRequest(json['request']);
    final response = _runtimeHttpResponse(json['response']);
    final requestBody = _runtimeHttpBody(json['requestBody']);
    final responseBody = _runtimeHttpBody(json['responseBody']);
    if (request == null ||
        !_validRuntimeTransactionHost(
          request,
          runtimeHost,
          allowLegacyMissingHost: legacy,
        ) ||
        (requestCompletedAfter != 0 &&
            requestCompletedAfter < requestObservedAfter) ||
        (response != null &&
            response.observedAfterMilliseconds < requestObservedAfter) ||
        (responseCompletedAfter != 0 &&
            (response == null ||
                responseCompletedAfter < response.observedAfterMilliseconds)) ||
        (responseBody != null && response == null)) {
      throw const FormatException('Invalid runtime HTTP transaction contract');
    }
    return TlsInspectionRuntimeHttpTransaction(
      sequence: sequence,
      requestObservedAfterMilliseconds: requestObservedAfter,
      requestCompletedAfterMilliseconds: requestCompletedAfter,
      responseCompletedAfterMilliseconds: responseCompletedAfter,
      request: request,
      requestBody: requestBody,
      response: response,
      responseBody: responseBody,
    );
  }

  Map<String, Object?> toJson() => {
    'sequence': sequence,
    'requestObservedAfterMilliseconds': requestObservedAfterMilliseconds,
    if (requestCompletedAfterMilliseconds != 0)
      'requestCompletedAfterMilliseconds': requestCompletedAfterMilliseconds,
    if (responseCompletedAfterMilliseconds != 0)
      'responseCompletedAfterMilliseconds': responseCompletedAfterMilliseconds,
    'request': request.toJson(),
    if (requestBody != null) 'requestBody': requestBody!.toJson(),
    if (response != null) 'response': response!.toJson(),
    if (responseBody != null) 'responseBody': responseBody!.toJson(),
  };

  int get metadataRank => 1 + (response == null ? 0 : 2);

  TlsInspectionRuntimeHttpTransaction merge(
    TlsInspectionRuntimeHttpTransaction other,
  ) {
    if (sequence != other.sequence ||
        !_sameRuntimeHttpRequest(request, other.request)) {
      return this;
    }
    return TlsInspectionRuntimeHttpTransaction(
      sequence: sequence,
      requestObservedAfterMilliseconds: _earlierNonNegative(
        requestObservedAfterMilliseconds,
        other.requestObservedAfterMilliseconds,
      ),
      requestCompletedAfterMilliseconds: _later(
        requestCompletedAfterMilliseconds,
        other.requestCompletedAfterMilliseconds,
      ),
      responseCompletedAfterMilliseconds: _later(
        responseCompletedAfterMilliseconds,
        other.responseCompletedAfterMilliseconds,
      ),
      request: _richerRuntimeHttpRequest(request, other.request),
      requestBody: _richerRuntimeHttpBody(requestBody, other.requestBody),
      response: _richerRuntimeHttpResponse(response, other.response),
      responseBody: _richerRuntimeHttpBody(responseBody, other.responseBody),
    );
  }
}

class TlsInspectionRuntimeHttp2Stream {
  final int sequence;
  final int streamId;
  final String state;
  final int requestObservedAfterMilliseconds;
  final int requestCompletedAfterMilliseconds;
  final int responseCompletedAfterMilliseconds;
  final int resetCode;
  final HttpProtocolObservation request;
  final TlsInspectionRuntimeHttpBody? requestBody;
  final HttpResponseProtocolObservation? response;
  final TlsInspectionRuntimeHttpBody? responseBody;

  const TlsInspectionRuntimeHttp2Stream({
    required this.sequence,
    required this.streamId,
    required this.state,
    required this.requestObservedAfterMilliseconds,
    this.requestCompletedAfterMilliseconds = 0,
    this.responseCompletedAfterMilliseconds = 0,
    this.resetCode = 0,
    required this.request,
    this.requestBody,
    this.response,
    this.responseBody,
  });

  factory TlsInspectionRuntimeHttp2Stream.fromJson(
    Map<String, Object?> json, {
    required String runtimeHost,
  }) {
    final sequence = _runtimeInteger(
      json['sequence'],
      TlsInspectionRuntimeHttpTransaction.maximumCount,
      minimum: 1,
    );
    final streamId = _runtimeInteger(json['streamId'], 0x7fffffff, minimum: 1);
    final state = json['state'];
    final requestObservedAfter = _runtimeInteger(
      json['requestObservedAfterMilliseconds'] ?? 0,
      0x7fffffff,
    );
    final requestCompletedAfter = _runtimeInteger(
      json['requestCompletedAfterMilliseconds'] ?? 0,
      0x7fffffff,
    );
    final responseCompletedAfter = _runtimeInteger(
      json['responseCompletedAfterMilliseconds'] ?? 0,
      0x7fffffff,
    );
    final resetCode = _runtimeInteger(json['resetCode'] ?? 0, 0xffffffff);
    final request = _runtimeHttpRequest(json['request']);
    final response = _runtimeHttpResponse(json['response']);
    final requestBody = _runtimeHttpBody(json['requestBody']);
    final responseBody = _runtimeHttpBody(json['responseBody']);
    if (streamId.isEven ||
        state is! String ||
        !const {
          'open',
          'request-ended',
          'response-ended',
          'closed',
          'reset',
        }.contains(state) ||
        request == null ||
        request.version != 'HTTP/2' ||
        !_validRuntimeTransactionHost(
          request,
          runtimeHost,
          allowLegacyMissingHost: false,
        ) ||
        (requestCompletedAfter != 0 &&
            requestCompletedAfter < requestObservedAfter) ||
        (response != null &&
            (response.version != 'HTTP/2' ||
                response.observedAfterMilliseconds < requestObservedAfter)) ||
        (responseCompletedAfter != 0 &&
            (response == null ||
                responseCompletedAfter < response.observedAfterMilliseconds)) ||
        (responseBody != null && response == null) ||
        (state != 'reset' && resetCode != 0)) {
      throw const FormatException('Invalid runtime HTTP/2 stream contract');
    }
    return TlsInspectionRuntimeHttp2Stream(
      sequence: sequence,
      streamId: streamId,
      state: state,
      requestObservedAfterMilliseconds: requestObservedAfter,
      requestCompletedAfterMilliseconds: requestCompletedAfter,
      responseCompletedAfterMilliseconds: responseCompletedAfter,
      resetCode: resetCode,
      request: request,
      requestBody: requestBody,
      response: response,
      responseBody: responseBody,
    );
  }

  Map<String, Object?> toJson() => {
    'sequence': sequence,
    'streamId': streamId,
    'state': state,
    'requestObservedAfterMilliseconds': requestObservedAfterMilliseconds,
    if (requestCompletedAfterMilliseconds != 0)
      'requestCompletedAfterMilliseconds': requestCompletedAfterMilliseconds,
    if (responseCompletedAfterMilliseconds != 0)
      'responseCompletedAfterMilliseconds': responseCompletedAfterMilliseconds,
    if (resetCode != 0) 'resetCode': resetCode,
    'request': request.toJson(),
    if (requestBody != null) 'requestBody': requestBody!.toJson(),
    if (response != null) 'response': response!.toJson(),
    if (responseBody != null) 'responseBody': responseBody!.toJson(),
  };

  int get metadataRank => 1 + (response == null ? 0 : 2);

  TlsInspectionRuntimeHttp2Stream merge(TlsInspectionRuntimeHttp2Stream other) {
    if (sequence != other.sequence ||
        streamId != other.streamId ||
        !_sameRuntimeHttpRequest(request, other.request)) {
      return this;
    }
    int stateRank(String value) => switch (value) {
      'reset' || 'closed' => 3,
      'response-ended' || 'request-ended' => 2,
      'open' => 1,
      _ => 0,
    };
    final preferred = stateRank(other.state) > stateRank(state) ? other : this;
    return TlsInspectionRuntimeHttp2Stream(
      sequence: sequence,
      streamId: streamId,
      state: preferred.state,
      requestObservedAfterMilliseconds: _earlierNonNegative(
        requestObservedAfterMilliseconds,
        other.requestObservedAfterMilliseconds,
      ),
      requestCompletedAfterMilliseconds: _later(
        requestCompletedAfterMilliseconds,
        other.requestCompletedAfterMilliseconds,
      ),
      responseCompletedAfterMilliseconds: _later(
        responseCompletedAfterMilliseconds,
        other.responseCompletedAfterMilliseconds,
      ),
      resetCode: preferred.resetCode,
      request: _richerRuntimeHttpRequest(request, other.request),
      requestBody: _richerRuntimeHttpBody(requestBody, other.requestBody),
      response: _richerRuntimeHttpResponse(response, other.response),
      responseBody: _richerRuntimeHttpBody(responseBody, other.responseBody),
    );
  }
}

class TlsInspectionRuntimeHttp2GoAway {
  final int lastStreamId;
  final int errorCode;
  final int observedAfterMilliseconds;

  const TlsInspectionRuntimeHttp2GoAway({
    required this.lastStreamId,
    required this.errorCode,
    required this.observedAfterMilliseconds,
  });

  factory TlsInspectionRuntimeHttp2GoAway.fromJson(Map<String, Object?> json) {
    return TlsInspectionRuntimeHttp2GoAway(
      lastStreamId: _runtimeInteger(json['lastStreamId'], 0x7fffffff),
      errorCode: _runtimeInteger(json['errorCode'], 0xffffffff),
      observedAfterMilliseconds: _runtimeInteger(
        json['observedAfterMilliseconds'],
        0x7fffffff,
      ),
    );
  }

  Map<String, Object?> toJson() => {
    'lastStreamId': lastStreamId,
    'errorCode': errorCode,
    'observedAfterMilliseconds': observedAfterMilliseconds,
  };
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
  final int downstreamTlsCompletedAfterMilliseconds;
  final int upstreamDialCompletedAfterMilliseconds;
  final int upstreamTlsCompletedAfterMilliseconds;
  final TlsInspectionCapturePolicy capturePolicy;
  final List<TlsInspectionRuntimeHttpTransaction> httpTransactions;
  final bool httpTransactionsTruncated;
  final List<TlsInspectionRuntimeHttp2Stream> http2Streams;
  final bool http2StreamsTruncated;
  final TlsInspectionRuntimeHttp2GoAway? http2GoAway;

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
    this.downstreamTlsCompletedAfterMilliseconds = 0,
    this.upstreamDialCompletedAfterMilliseconds = 0,
    this.upstreamTlsCompletedAfterMilliseconds = 0,
    this.capturePolicy = TlsInspectionCapturePolicy.metadataOnly,
    this.httpTransactions = const [],
    this.httpTransactionsTruncated = false,
    this.http2Streams = const [],
    this.http2StreamsTruncated = false,
    this.http2GoAway,
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

    int optionalElapsed(String key) =>
        _runtimeInteger(json[key] ?? 0, 0x7fffffff);

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
    final rawPolicy = json['capturePolicy'];
    if (rawPolicy != null && rawPolicy is! Map) {
      throw const FormatException('Invalid runtime capture policy');
    }
    final capturePolicy = rawPolicy == null
        ? TlsInspectionCapturePolicy.metadataOnly
        : TlsInspectionCapturePolicy.fromJson(
            Map<String, dynamic>.from(rawPolicy as Map),
          );
    final rawTransactions = json['httpTransactions'];
    final rawStreams = json['http2Streams'];
    final timelineTruncated = json['httpTransactionsTruncated'] ?? false;
    final streamsTruncated = json['http2StreamsTruncated'] ?? false;
    if (timelineTruncated is! bool || streamsTruncated is! bool) {
      throw const FormatException('Invalid runtime HTTP timeline state');
    }
    if (rawTransactions != null && rawTransactions is! List ||
        rawStreams != null && rawStreams is! List) {
      throw const FormatException('Invalid runtime HTTP timeline list');
    }
    if (rawTransactions is List &&
            rawTransactions.length >
                TlsInspectionRuntimeHttpTransaction.maximumCount ||
        rawStreams is List &&
            rawStreams.length >
                TlsInspectionRuntimeHttpTransaction.maximumCount) {
      throw const FormatException('Runtime HTTP timeline exceeds cap');
    }
    if (rawTransactions != null && rawStreams != null) {
      throw const FormatException('Mixed HTTP timeline contracts');
    }
    final transactions = <TlsInspectionRuntimeHttpTransaction>[];
    if (rawTransactions is List) {
      if (json.containsKey('httpRequest') || json.containsKey('httpResponse')) {
        throw const FormatException('Invalid runtime HTTP transaction list');
      }
      for (final raw in rawTransactions) {
        if (raw is! Map) {
          throw const FormatException('Invalid runtime HTTP transaction');
        }
        transactions.add(
          TlsInspectionRuntimeHttpTransaction.fromJson(
            Map<String, Object?>.from(raw),
            runtimeHost: host,
          ),
        );
      }
    }
    final streams = <TlsInspectionRuntimeHttp2Stream>[];
    if (rawStreams is List) {
      if (json.containsKey('httpRequest') || json.containsKey('httpResponse')) {
        throw const FormatException('Invalid runtime HTTP/2 stream list');
      }
      for (final raw in rawStreams) {
        if (raw is! Map) {
          throw const FormatException('Invalid runtime HTTP/2 stream');
        }
        streams.add(
          TlsInspectionRuntimeHttp2Stream.fromJson(
            Map<String, Object?>.from(raw),
            runtimeHost: host,
          ),
        );
      }
    }
    if (rawTransactions == null && rawStreams == null) {
      final legacyRequest = _runtimeHttpRequest(json['httpRequest']);
      final legacyResponse = _runtimeHttpResponse(json['httpResponse']);
      if (legacyResponse != null && legacyRequest == null) {
        throw const FormatException('Invalid legacy runtime HTTP contract');
      }
      if (legacyRequest != null) {
        transactions.add(
          TlsInspectionRuntimeHttpTransaction.fromJson(
            {
              'sequence': 1,
              'requestObservedAfterMilliseconds': 0,
              'request': legacyRequest.toJson(),
              if (legacyResponse != null) 'response': legacyResponse.toJson(),
            },
            runtimeHost: host,
            legacy: true,
          ),
        );
      }
    }
    if (transactions.length ==
                TlsInspectionRuntimeHttpTransaction.maximumCount &&
            !timelineTruncated ||
        streams.length == TlsInspectionRuntimeHttpTransaction.maximumCount &&
            !streamsTruncated) {
      throw const FormatException('Invalid complete runtime HTTP timeline cap');
    }
    _validateHTTP1Timeline(transactions);
    _validateHTTP2Timeline(streams);
    for (final transaction in transactions) {
      _validateCapturePolicy(
        request: transaction.request,
        requestBody: transaction.requestBody,
        response: transaction.response,
        responseBody: transaction.responseBody,
        policy: capturePolicy,
      );
    }
    for (final stream in streams) {
      _validateCapturePolicy(
        request: stream.request,
        requestBody: stream.requestBody,
        response: stream.response,
        responseBody: stream.responseBody,
        policy: capturePolicy,
      );
    }
    final rawGoAway = json['http2GoAway'];
    if (rawGoAway != null && rawGoAway is! Map) {
      throw const FormatException('Invalid runtime HTTP/2 GOAWAY');
    }
    final goAway = rawGoAway == null
        ? null
        : TlsInspectionRuntimeHttp2GoAway.fromJson(
            Map<String, Object?>.from(rawGoAway as Map),
          );
    final completedDelay = startedAt == null || completedAt == null
        ? null
        : completedAt.difference(startedAt).inMilliseconds;
    if (completedDelay != null &&
        (_timelineAfter(transactions, completedDelay) ||
            _streamTimelineAfter(streams, completedDelay) ||
            (goAway?.observedAfterMilliseconds ?? 0) > completedDelay)) {
      throw const FormatException('Invalid runtime HTTP transaction timing');
    }
    final downstreamTlsCompleted = optionalElapsed(
      'downstreamTlsCompletedAfterMilliseconds',
    );
    final upstreamDialCompleted = optionalElapsed(
      'upstreamDialCompletedAfterMilliseconds',
    );
    final upstreamTlsCompleted = optionalElapsed(
      'upstreamTlsCompletedAfterMilliseconds',
    );
    if (upstreamDialCompleted != 0 &&
            upstreamTlsCompleted != 0 &&
            upstreamDialCompleted > upstreamTlsCompleted ||
        completedDelay != null &&
            <int>[
              downstreamTlsCompleted,
              upstreamDialCompleted,
              upstreamTlsCompleted,
            ].any((value) => value > completedDelay)) {
      throw const FormatException('Invalid runtime connection timing');
    }
    final hasHttpMetadata =
        transactions.isNotEmpty ||
        streams.isNotEmpty ||
        timelineTruncated ||
        streamsTruncated ||
        goAway != null;
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
        (alpn.isNotEmpty && alpn != 'http/1.1' && alpn != 'h2') ||
        (streams.isNotEmpty && alpn != 'h2') ||
        (transactions.isNotEmpty && alpn == 'h2') ||
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
      downstreamTlsCompletedAfterMilliseconds: downstreamTlsCompleted,
      upstreamDialCompletedAfterMilliseconds: upstreamDialCompleted,
      upstreamTlsCompletedAfterMilliseconds: upstreamTlsCompleted,
      capturePolicy: capturePolicy,
      httpTransactions: List.unmodifiable(transactions),
      httpTransactionsTruncated: timelineTruncated,
      http2Streams: List.unmodifiable(streams),
      http2StreamsTruncated: streamsTruncated,
      http2GoAway: goAway,
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
    if (downstreamTlsCompletedAfterMilliseconds != 0)
      'downstreamTlsCompletedAfterMilliseconds':
          downstreamTlsCompletedAfterMilliseconds,
    if (upstreamDialCompletedAfterMilliseconds != 0)
      'upstreamDialCompletedAfterMilliseconds':
          upstreamDialCompletedAfterMilliseconds,
    if (upstreamTlsCompletedAfterMilliseconds != 0)
      'upstreamTlsCompletedAfterMilliseconds':
          upstreamTlsCompletedAfterMilliseconds,
    'capturePolicy': capturePolicy.toJson(),
    if (httpTransactions.isNotEmpty)
      'httpTransactions': [
        for (final transaction in httpTransactions) transaction.toJson(),
      ],
    if (httpTransactionsTruncated) 'httpTransactionsTruncated': true,
    if (http2Streams.isNotEmpty)
      'http2Streams': [for (final stream in http2Streams) stream.toJson()],
    if (http2StreamsTruncated) 'http2StreamsTruncated': true,
    if (http2GoAway != null) 'http2GoAway': http2GoAway!.toJson(),
  };

  bool get completed =>
      state == 'completed' || state == 'failed' || state == 'interrupted';

  HttpProtocolObservation? get httpRequest {
    if (httpTransactions.isNotEmpty) {
      return httpTransactions.first.request;
    }
    return http2Streams.isEmpty ? null : http2Streams.first.request;
  }

  HttpResponseProtocolObservation? get httpResponse {
    if (httpTransactions.isNotEmpty) {
      return httpTransactions.first.response;
    }
    return http2Streams.isEmpty ? null : http2Streams.first.response;
  }

  int get metadataRank {
    final timelineRank = httpTransactions.fold<int>(
      httpTransactionsTruncated ? 1 : 0,
      (rank, transaction) => rank + transaction.metadataRank,
    );
    return http2Streams.fold<int>(
      timelineRank + (http2StreamsTruncated ? 1 : 0),
      (rank, stream) => rank + stream.metadataRank,
    );
  }

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

    final sameStart = startedAt == other.startedAt;
    final samePolicy = capturePolicy == other.capturePolicy;
    final compatibleHTTP1 =
        sameStart &&
        samePolicy &&
        http2Streams.isEmpty &&
        other.http2Streams.isEmpty &&
        _compatibleTransactions(httpTransactions, other.httpTransactions);
    final compatibleHTTP2 =
        sameStart &&
        samePolicy &&
        httpTransactions.isEmpty &&
        other.httpTransactions.isEmpty &&
        _compatibleStreams(http2Streams, other.http2Streams);

    final transactions = compatibleHTTP1
        ? _mergeTransactions(httpTransactions, other.httpTransactions)
        : List<TlsInspectionRuntimeHttpTransaction>.from(
            preferred.httpTransactions,
          );
    final streams = compatibleHTTP2
        ? _mergeStreams(http2Streams, other.http2Streams)
        : List<TlsInspectionRuntimeHttp2Stream>.from(preferred.http2Streams);
    final hadHTTP1 =
        httpTransactions.isNotEmpty ||
        other.httpTransactions.isNotEmpty ||
        httpTransactionsTruncated ||
        other.httpTransactionsTruncated;
    final hadHTTP2 =
        http2Streams.isNotEmpty ||
        other.http2Streams.isNotEmpty ||
        http2StreamsTruncated ||
        other.http2StreamsTruncated;
    var transactionsTruncated =
        httpTransactionsTruncated ||
        other.httpTransactionsTruncated ||
        (!compatibleHTTP1 && hadHTTP1);
    var streamsTruncated =
        http2StreamsTruncated ||
        other.http2StreamsTruncated ||
        (!compatibleHTTP2 && hadHTTP2);
    final mergedStartedAt = sameStart ? startedAt : preferred.startedAt;
    final mergedCompletedAt = preferred.completedAt;
    if (mergedCompletedAt != null) {
      final completedDelay = mergedCompletedAt
          .difference(mergedStartedAt)
          .inMilliseconds;
      final firstLateTransaction = transactions.indexWhere(
        (transaction) => _transactionAfter(transaction, completedDelay),
      );
      if (firstLateTransaction >= 0) {
        transactions.removeRange(firstLateTransaction, transactions.length);
        transactionsTruncated = true;
      }
      final firstLateStream = streams.indexWhere(
        (stream) => _streamAfter(stream, completedDelay),
      );
      if (firstLateStream >= 0) {
        streams.removeRange(firstLateStream, streams.length);
        streamsTruncated = true;
      }
    }

    final preserveTerminalCounters = preferred.completed;
    return TlsInspectionRuntimeObservation(
      sessionId: sessionId,
      connectionId: connectionId,
      runtimeId: runtimeId,
      host: host,
      state: preferred.state,
      startedAt: mergedStartedAt,
      completedAt: mergedCompletedAt,
      downstreamTlsVersion: richer(
        preferred.downstreamTlsVersion,
        alternate.downstreamTlsVersion,
      ),
      upstreamTlsVersion: richer(
        preferred.upstreamTlsVersion,
        alternate.upstreamTlsVersion,
      ),
      alpn: richer(preferred.alpn, alternate.alpn),
      uploaded: preserveTerminalCounters
          ? preferred.uploaded
          : _later(uploaded, other.uploaded),
      downloaded: preserveTerminalCounters
          ? preferred.downloaded
          : _later(downloaded, other.downloaded),
      failureKind:
          preferred.state == 'failed' || preferred.state == 'interrupted'
          ? preferred.failureKind
          : '',
      downstreamTlsCompletedAfterMilliseconds: _later(
        downstreamTlsCompletedAfterMilliseconds,
        other.downstreamTlsCompletedAfterMilliseconds,
      ),
      upstreamDialCompletedAfterMilliseconds: _later(
        upstreamDialCompletedAfterMilliseconds,
        other.upstreamDialCompletedAfterMilliseconds,
      ),
      upstreamTlsCompletedAfterMilliseconds: _later(
        upstreamTlsCompletedAfterMilliseconds,
        other.upstreamTlsCompletedAfterMilliseconds,
      ),
      capturePolicy: preferred.capturePolicy,
      httpTransactions: List.unmodifiable(transactions),
      httpTransactionsTruncated: transactionsTruncated,
      http2Streams: List.unmodifiable(streams),
      http2StreamsTruncated: streamsTruncated,
      http2GoAway: _richerGoAway(http2GoAway, other.http2GoAway),
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
    final completed = completedAt.toUtc().isBefore(startedAt)
        ? startedAt
        : completedAt.toUtc();
    return TlsInspectionRuntimeObservation(
      sessionId: sessionId,
      connectionId: connectionId,
      runtimeId: runtimeId,
      host: host,
      state: 'interrupted',
      startedAt: startedAt,
      completedAt: completed,
      downstreamTlsVersion: downstreamTlsVersion,
      upstreamTlsVersion: upstreamTlsVersion,
      alpn: alpn,
      uploaded: uploaded,
      downloaded: downloaded,
      failureKind: failureKind,
      downstreamTlsCompletedAfterMilliseconds:
          downstreamTlsCompletedAfterMilliseconds,
      upstreamDialCompletedAfterMilliseconds:
          upstreamDialCompletedAfterMilliseconds,
      upstreamTlsCompletedAfterMilliseconds:
          upstreamTlsCompletedAfterMilliseconds,
      capturePolicy: capturePolicy,
      httpTransactions: httpTransactions,
      httpTransactionsTruncated: httpTransactionsTruncated,
      http2Streams: http2Streams,
      http2StreamsTruncated: http2StreamsTruncated,
      http2GoAway: http2GoAway,
    );
  }
}

void _validateHTTP1Timeline(
  List<TlsInspectionRuntimeHttpTransaction> transactions,
) {
  var previousRequestDelay = -1;
  var previousResponseDelay = -1;
  var responseGapSeen = false;
  for (var index = 0; index < transactions.length; index++) {
    final transaction = transactions[index];
    final response = transaction.response;
    if (transaction.sequence != index + 1 ||
        transaction.requestObservedAfterMilliseconds < previousRequestDelay ||
        (response != null && responseGapSeen) ||
        (response != null &&
            response.observedAfterMilliseconds < previousResponseDelay)) {
      throw const FormatException('Invalid runtime HTTP transaction order');
    }
    previousRequestDelay = transaction.requestObservedAfterMilliseconds;
    if (response == null) {
      responseGapSeen = true;
    } else {
      previousResponseDelay = response.observedAfterMilliseconds;
    }
  }
}

void _validateHTTP2Timeline(List<TlsInspectionRuntimeHttp2Stream> streams) {
  var previousRequestDelay = -1;
  final streamIds = <int>{};
  for (var index = 0; index < streams.length; index++) {
    final stream = streams[index];
    if (stream.sequence != index + 1 ||
        stream.requestObservedAfterMilliseconds < previousRequestDelay ||
        !streamIds.add(stream.streamId)) {
      throw const FormatException('Invalid runtime HTTP/2 stream order');
    }
    previousRequestDelay = stream.requestObservedAfterMilliseconds;
  }
}

void _validateCapturePolicy({
  required HttpProtocolObservation request,
  required TlsInspectionRuntimeHttpBody? requestBody,
  required HttpResponseProtocolObservation? response,
  required TlsInspectionRuntimeHttpBody? responseBody,
  required TlsInspectionCapturePolicy policy,
}) {
  if (!policy.headerValues &&
      (request.headers.isNotEmpty || response?.headers.isNotEmpty == true)) {
    throw const FormatException('Header values captured without authorization');
  }
  for (final header in <HttpHeaderObservation>[
    ...request.headers,
    ...?response?.headers,
  ]) {
    final customRedacted = policy.redactedHeaderNames.contains(header.name);
    if ((header.sensitive && !policy.capturesSensitiveValues ||
            customRedacted) &&
        !header.redacted) {
      throw const FormatException('Header value bypassed redaction policy');
    }
  }
  for (final body in <TlsInspectionRuntimeHttpBody?>[
    requestBody,
    responseBody,
  ]) {
    if (body == null) {
      continue;
    }
    if (!policy.capturesBodies || body.capturedBytes > policy.maxBodyBytes) {
      throw const FormatException('Body captured without authorization');
    }
    if (policy.bodyMode == TlsInspectionCaptureBodyMode.text &&
        body.capturedBytes > 0 &&
        const {'image', 'binary', 'multipart'}.contains(body.kind)) {
      throw const FormatException('Binary body bypassed text-only policy');
    }
  }
}

bool _timelineAfter(
  List<TlsInspectionRuntimeHttpTransaction> transactions,
  int completedDelay,
) => transactions.any(
  (transaction) => _transactionAfter(transaction, completedDelay),
);

bool _streamTimelineAfter(
  List<TlsInspectionRuntimeHttp2Stream> streams,
  int completedDelay,
) => streams.any((stream) => _streamAfter(stream, completedDelay));

bool _transactionAfter(
  TlsInspectionRuntimeHttpTransaction transaction,
  int completedDelay,
) =>
    transaction.requestObservedAfterMilliseconds > completedDelay ||
    transaction.requestCompletedAfterMilliseconds > completedDelay ||
    (transaction.response?.observedAfterMilliseconds ?? 0) > completedDelay ||
    transaction.responseCompletedAfterMilliseconds > completedDelay;

bool _streamAfter(TlsInspectionRuntimeHttp2Stream stream, int completedDelay) =>
    stream.requestObservedAfterMilliseconds > completedDelay ||
    stream.requestCompletedAfterMilliseconds > completedDelay ||
    (stream.response?.observedAfterMilliseconds ?? 0) > completedDelay ||
    stream.responseCompletedAfterMilliseconds > completedDelay;

bool _compatibleTransactions(
  List<TlsInspectionRuntimeHttpTransaction> left,
  List<TlsInspectionRuntimeHttpTransaction> right,
) {
  final count = left.length < right.length ? left.length : right.length;
  for (var index = 0; index < count; index++) {
    final current = left[index];
    final incoming = right[index];
    if (current.sequence != incoming.sequence ||
        !_sameRuntimeHttpRequest(current.request, incoming.request) ||
        (current.response != null &&
            incoming.response != null &&
            !_sameRuntimeHttpResponseIdentity(
              current.response!,
              incoming.response!,
            ))) {
      return false;
    }
  }
  return true;
}

List<TlsInspectionRuntimeHttpTransaction> _mergeTransactions(
  List<TlsInspectionRuntimeHttpTransaction> left,
  List<TlsInspectionRuntimeHttpTransaction> right,
) {
  final count = left.length > right.length ? left.length : right.length;
  return [
    for (var index = 0; index < count; index++)
      if (index < left.length && index < right.length)
        left[index].merge(right[index])
      else if (index < left.length)
        left[index]
      else
        right[index],
  ];
}

bool _compatibleStreams(
  List<TlsInspectionRuntimeHttp2Stream> left,
  List<TlsInspectionRuntimeHttp2Stream> right,
) {
  final count = left.length < right.length ? left.length : right.length;
  for (var index = 0; index < count; index++) {
    final current = left[index];
    final incoming = right[index];
    if (current.sequence != incoming.sequence ||
        current.streamId != incoming.streamId ||
        !_sameRuntimeHttpRequest(current.request, incoming.request) ||
        (current.response != null &&
            incoming.response != null &&
            !_sameRuntimeHttpResponseIdentity(
              current.response!,
              incoming.response!,
            ))) {
      return false;
    }
  }
  return true;
}

List<TlsInspectionRuntimeHttp2Stream> _mergeStreams(
  List<TlsInspectionRuntimeHttp2Stream> left,
  List<TlsInspectionRuntimeHttp2Stream> right,
) {
  final count = left.length > right.length ? left.length : right.length;
  return [
    for (var index = 0; index < count; index++)
      if (index < left.length && index < right.length)
        left[index].merge(right[index])
      else if (index < left.length)
        left[index]
      else
        right[index],
  ];
}

TlsInspectionRuntimeHttp2GoAway? _richerGoAway(
  TlsInspectionRuntimeHttp2GoAway? left,
  TlsInspectionRuntimeHttp2GoAway? right,
) {
  if (left == null) {
    return right;
  }
  if (right == null) {
    return left;
  }
  return right.observedAfterMilliseconds >= left.observedAfterMilliseconds
      ? right
      : left;
}

bool _validRuntimeTransactionHost(
  HttpProtocolObservation request,
  String runtimeHost, {
  required bool allowLegacyMissingHost,
}) {
  if (request.hostTruncated) {
    return false;
  }
  if (request.method == 'CONNECT') {
    return request.host.isNotEmpty &&
        (request.host == request.target ||
            '${request.host}:443' == request.target);
  }
  if (request.host.isEmpty) {
    return allowLegacyMissingHost || request.version == 'HTTP/1.0';
  }
  return request.host == runtimeHost;
}

bool _sameRuntimeHttpRequest(
  HttpProtocolObservation left,
  HttpProtocolObservation right,
) =>
    left.method == right.method &&
    left.target == right.target &&
    left.version == right.version &&
    left.host == right.host &&
    _sameRuntimeList(left.headerNames, right.headerNames) &&
    _sameRuntimeHeaders(left.headers, right.headers) &&
    left.headersComplete == right.headersComplete &&
    left.targetTruncated == right.targetTruncated &&
    left.hostTruncated == right.hostTruncated &&
    left.headerNamesTruncated == right.headerNamesTruncated &&
    left.headerValuesTruncated == right.headerValuesTruncated;

HttpProtocolObservation _richerRuntimeHttpRequest(
  HttpProtocolObservation left,
  HttpProtocolObservation right,
) {
  final preferred = right.headers.length > left.headers.length ? right : left;
  return HttpProtocolObservation(
    method: preferred.method,
    target: preferred.target,
    version: preferred.version,
    host: preferred.host,
    headerNames: preferred.headerNames,
    headers: preferred.headers,
    headersComplete: left.headersComplete || right.headersComplete,
    targetTruncated: left.targetTruncated || right.targetTruncated,
    hostTruncated: left.hostTruncated || right.hostTruncated,
    headerNamesTruncated:
        left.headerNamesTruncated || right.headerNamesTruncated,
    headerValuesTruncated:
        left.headerValuesTruncated || right.headerValuesTruncated,
  );
}

HttpResponseProtocolObservation? _richerRuntimeHttpResponse(
  HttpResponseProtocolObservation? left,
  HttpResponseProtocolObservation? right,
) {
  if (left == null) {
    return right;
  }
  if (right == null) {
    return left;
  }
  if (!_sameRuntimeHttpResponseIdentity(left, right)) {
    return left;
  }
  int rank(HttpResponseProtocolObservation value) =>
      (value.statusCode == 0 ? 0 : 1000000) +
      (value.headersComplete ? 100000 : 0) +
      (value.truncated ? 0 : 10000) +
      value.headers.length * 1000 +
      value.headerNames.length * 100 +
      value.informationalStatusCodes.length * 10 +
      value.observedBytes;
  final preferred = rank(right) > rank(left) ? right : left;
  final alternate = identical(preferred, left) ? right : left;
  final observedAfter = _earlierNonZero(
    preferred.observedAfterMilliseconds,
    alternate.observedAfterMilliseconds,
  );
  return HttpResponseProtocolObservation(
    version: preferred.version,
    statusCode: preferred.statusCode,
    informationalStatusCodes: preferred.informationalStatusCodes,
    headerNames: preferred.headerNames,
    headers: preferred.headers,
    headersComplete: left.headersComplete || right.headersComplete,
    observedBytes: _later(left.observedBytes, right.observedBytes),
    observedAfterMilliseconds: observedAfter,
    truncated: left.truncated || right.truncated,
    headerNamesTruncated:
        left.headerNamesTruncated || right.headerNamesTruncated,
    headerValuesTruncated:
        left.headerValuesTruncated || right.headerValuesTruncated,
    informationalStatusCodesTruncated:
        left.informationalStatusCodesTruncated ||
        right.informationalStatusCodesTruncated,
  );
}

TlsInspectionRuntimeHttpBody? _richerRuntimeHttpBody(
  TlsInspectionRuntimeHttpBody? left,
  TlsInspectionRuntimeHttpBody? right,
) {
  if (left == null) {
    return right;
  }
  if (right == null) {
    return left;
  }
  int rank(TlsInspectionRuntimeHttpBody value) =>
      value.capturedBytes * 1000000 +
      value.observedBytes * 10 +
      (value.truncated ? 0 : 1);
  return rank(right) > rank(left) ? right : left;
}

bool _sameRuntimeHttpResponseIdentity(
  HttpResponseProtocolObservation left,
  HttpResponseProtocolObservation right,
) =>
    left.version == right.version &&
    left.statusCode == right.statusCode &&
    _sameRuntimeList(
      left.informationalStatusCodes,
      right.informationalStatusCodes,
    );

bool _sameRuntimeHeaders(
  List<HttpHeaderObservation> left,
  List<HttpHeaderObservation> right,
) {
  if (left.length != right.length) {
    return false;
  }
  for (var index = 0; index < left.length; index++) {
    final current = left[index];
    final incoming = right[index];
    if (current.name != incoming.name ||
        current.value != incoming.value ||
        current.redacted != incoming.redacted ||
        current.truncated != incoming.truncated) {
      return false;
    }
  }
  return true;
}

bool _sameRuntimeList<T>(List<T> left, List<T> right) {
  if (left.length != right.length) {
    return false;
  }
  for (var index = 0; index < left.length; index++) {
    if (left[index] != right[index]) {
      return false;
    }
  }
  return true;
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
  final headerValuesTruncated = json['headerValuesTruncated'] ?? false;
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
      !const {'HTTP/1.0', 'HTTP/1.1', 'HTTP/2'}.contains(version) ||
      host is! String ||
      host.length > 255 ||
      (host.isNotEmpty && !_validRuntimeHttpHost(host)) ||
      headersComplete is! bool ||
      targetTruncated is! bool ||
      hostTruncated is! bool ||
      headerNamesTruncated is! bool ||
      headerValuesTruncated is! bool ||
      (method != 'CONNECT' && target != '*' && !target.startsWith('/'))) {
    throw const FormatException('Invalid runtime HTTP request contract');
  }
  final headerNames = _runtimeHttpHeaderNames(json['headerNames']);
  final headers = _runtimeHttpHeaders(json['headers']);
  final names = headerNames.toSet();
  if (headers.any((header) => !names.contains(header.name))) {
    throw const FormatException('Invalid runtime HTTP request headers');
  }
  return HttpProtocolObservation(
    method: method,
    target: target,
    version: version,
    host: host,
    headerNames: headerNames,
    headers: headers,
    headersComplete: headersComplete,
    targetTruncated: targetTruncated,
    hostTruncated: hostTruncated,
    headerNamesTruncated: headerNamesTruncated,
    headerValuesTruncated: headerValuesTruncated,
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
  final headerValuesTruncated = json['headerValuesTruncated'] ?? false;
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
      !const {'', 'HTTP/1.0', 'HTTP/1.1', 'HTTP/2'}.contains(version) ||
      !validStatus ||
      headersComplete is! bool ||
      observedBytes is! int ||
      observedBytes <= 0 ||
      observedBytes > 128 * 1024 ||
      observedAfter is! int ||
      observedAfter < 0 ||
      observedAfter > 0x7fffffff ||
      truncated is! bool ||
      headerNamesTruncated is! bool ||
      headerValuesTruncated is! bool ||
      informationalTruncated is! bool ||
      (statusCode != 0 && version.isEmpty) ||
      (headersComplete && statusCode == 0)) {
    throw const FormatException('Invalid runtime HTTP response contract');
  }
  final headerNames = _runtimeHttpHeaderNames(json['headerNames']);
  final headers = _runtimeHttpHeaders(json['headers']);
  final names = headerNames.toSet();
  if (headers.any((header) => !names.contains(header.name)) ||
      statusCode == 0 &&
          (version.isNotEmpty ||
              headerNames.isNotEmpty ||
              headers.isNotEmpty ||
              informational.isEmpty ||
              !truncated)) {
    throw const FormatException('Invalid runtime HTTP response contract');
  }
  return HttpResponseProtocolObservation(
    version: version,
    statusCode: statusCode,
    informationalStatusCodes: informational,
    headerNames: headerNames,
    headers: headers,
    headersComplete: headersComplete,
    observedBytes: observedBytes,
    observedAfterMilliseconds: observedAfter,
    truncated: truncated,
    headerNamesTruncated: headerNamesTruncated,
    headerValuesTruncated: headerValuesTruncated,
    informationalStatusCodesTruncated: informationalTruncated,
  );
}

TlsInspectionRuntimeHttpBody? _runtimeHttpBody(Object? raw) {
  if (raw == null) {
    return null;
  }
  if (raw is! Map) {
    throw const FormatException('Invalid runtime HTTP body');
  }
  return TlsInspectionRuntimeHttpBody.fromJson(Map<String, dynamic>.from(raw));
}

List<HttpHeaderObservation> _runtimeHttpHeaders(Object? raw) {
  if (raw == null) {
    return const [];
  }
  if (raw is! List || raw.length > 64) {
    throw const FormatException('Invalid runtime HTTP headers');
  }
  return List.unmodifiable(
    raw.map((value) {
      if (value is! Map) {
        throw const FormatException('Invalid runtime HTTP header');
      }
      return HttpHeaderObservation.fromJson(Map<String, dynamic>.from(value));
    }),
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

int _runtimeInteger(Object? value, int maximum, {int minimum = 0}) {
  if (value is! int || value < minimum || value > maximum) {
    throw const FormatException('Invalid runtime integer');
  }
  return value;
}

int _later(int left, int right) => left > right ? left : right;

int _earlierNonNegative(int left, int right) => left < right ? left : right;

int _earlierNonZero(int left, int right) {
  if (left == 0) {
    return right;
  }
  if (right == 0) {
    return left;
  }
  return left < right ? left : right;
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
