from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text()
    if old not in text:
        raise RuntimeError(f"missing replacement in {path}: {old[:120]!r}")
    path.write_text(text.replace(old, new, 1))


def patch_models_export() -> None:
    path = ROOT / "lib/models/models.dart"
    text = path.read_text()
    marker = "export 'http_capture.dart';\n"
    if "export 'http_inspection.dart';" not in text:
        text = text.replace(marker, marker + "export 'http_inspection.dart';\n", 1)
    path.write_text(text)


def patch_common_protocol_models() -> None:
    path = ROOT / "lib/models/common.dart"
    text = path.read_text()
    if "import 'http_inspection.dart';" not in text:
        text = text.replace(
            "import '../common/http_payload_observer_contract.dart';\n",
            "import '../common/http_payload_observer_contract.dart';\n\nimport 'http_inspection.dart';\n",
            1,
        )
    replacements = [
        (
            '''    this.headerNames = const <String>[],
    required this.headersComplete,
    this.targetTruncated = false,
    this.hostTruncated = false,
    this.headerNamesTruncated = false,
  });
''',
            '''    this.headerNames = const <String>[],
    this.headers = const <HttpHeaderObservation>[],
    required this.headersComplete,
    this.targetTruncated = false,
    this.hostTruncated = false,
    this.headerNamesTruncated = false,
    this.headerValuesTruncated = false,
  });
''',
        ),
        (
            '''  final List<String> headerNames;
  final bool headersComplete;
  final bool targetTruncated;
  final bool hostTruncated;
  final bool headerNamesTruncated;
''',
            '''  final List<String> headerNames;
  final List<HttpHeaderObservation> headers;
  final bool headersComplete;
  final bool targetTruncated;
  final bool hostTruncated;
  final bool headerNamesTruncated;
  final bool headerValuesTruncated;
''',
        ),
        (
            '''    final rawHeaderNames = json['headerNames'];
    if (rawHeaderNames != null && rawHeaderNames is! List) {
      throw const FormatException('HTTP header names are invalid');
    }
    final headerNames = (rawHeaderNames as List? ?? const [])
        .map(
          (value) => _expectBoundedString(
            value,
            'HTTP header name',
            maximumLength: maximumHttpObservedHeaderNameLength,
          ),
        )
        .toList(growable: false);
    if (headerNames.length > maximumHttpObservedHeaderNames) {
      throw const FormatException('Too many HTTP header names');
    }
    final headersComplete = json['headersComplete'];
''',
            '''    final rawHeaderNames = json['headerNames'];
    if (rawHeaderNames != null && rawHeaderNames is! List) {
      throw const FormatException('HTTP header names are invalid');
    }
    final headerNames = (rawHeaderNames as List? ?? const [])
        .map(
          (value) => _expectBoundedString(
            value,
            'HTTP header name',
            maximumLength: maximumHttpObservedHeaderNameLength,
          ),
        )
        .toList(growable: false);
    if (headerNames.length > maximumHttpObservedHeaderNames) {
      throw const FormatException('Too many HTTP header names');
    }
    final rawHeaders = json['headers'];
    if (rawHeaders != null && rawHeaders is! List) {
      throw const FormatException('HTTP headers are invalid');
    }
    final headers = (rawHeaders as List? ?? const <Object?>[])
        .map((value) {
          if (value is! Map) {
            throw const FormatException('HTTP header is invalid');
          }
          return HttpHeaderObservation.fromJson(
            Map<String, dynamic>.from(value),
          );
        })
        .toList(growable: false);
    if (headers.length > maximumHttpObservedHeaderNames) {
      throw const FormatException('Too many HTTP headers');
    }
    final headerNameSet = headerNames.toSet();
    if (headers.any((value) => !headerNameSet.contains(value.name))) {
      throw const FormatException('HTTP header values do not match names');
    }
    final headersComplete = json['headersComplete'];
''',
        ),
        (
            '''      headerNames: headerNames,
      headersComplete: headersComplete,
      targetTruncated: _boolOrFalse(
''',
            '''      headerNames: headerNames,
      headers: headers,
      headersComplete: headersComplete,
      targetTruncated: _boolOrFalse(
''',
        ),
        (
            '''      headerNamesTruncated: _boolOrFalse(
        json['headerNamesTruncated'],
        'HTTP header names truncated',
      ),
    );
''',
            '''      headerNamesTruncated: _boolOrFalse(
        json['headerNamesTruncated'],
        'HTTP header names truncated',
      ),
      headerValuesTruncated: _boolOrFalse(
        json['headerValuesTruncated'],
        'HTTP header values truncated',
      ),
    );
''',
        ),
        (
            '''    if (headerNames.isNotEmpty) 'headerNames': headerNames,
    'headersComplete': headersComplete,
''',
            '''    if (headerNames.isNotEmpty) 'headerNames': headerNames,
    if (headers.isNotEmpty)
      'headers': headers.map((value) => value.toJson()).toList(),
    'headersComplete': headersComplete,
''',
        ),
        (
            '''    if (headerNamesTruncated) 'headerNamesTruncated': true,
  };
}

class HttpResponseProtocolObservation {
''',
            '''    if (headerNamesTruncated) 'headerNamesTruncated': true,
    if (headerValuesTruncated) 'headerValuesTruncated': true,
  };
}

class HttpResponseProtocolObservation {
''',
        ),
        (
            '''    this.headerNames = const <String>[],
    required this.headersComplete,
    required this.observedBytes,
''',
            '''    this.headerNames = const <String>[],
    this.headers = const <HttpHeaderObservation>[],
    required this.headersComplete,
    required this.observedBytes,
''',
        ),
        (
            '''    this.truncated = false,
    this.headerNamesTruncated = false,
    this.informationalStatusCodesTruncated = false,
  });
''',
            '''    this.truncated = false,
    this.headerNamesTruncated = false,
    this.headerValuesTruncated = false,
    this.informationalStatusCodesTruncated = false,
  });
''',
        ),
        (
            '''  final List<int> informationalStatusCodes;
  final List<String> headerNames;
  final bool headersComplete;
''',
            '''  final List<int> informationalStatusCodes;
  final List<String> headerNames;
  final List<HttpHeaderObservation> headers;
  final bool headersComplete;
''',
        ),
        (
            '''  final bool truncated;
  final bool headerNamesTruncated;
  final bool informationalStatusCodesTruncated;
''',
            '''  final bool truncated;
  final bool headerNamesTruncated;
  final bool headerValuesTruncated;
  final bool informationalStatusCodesTruncated;
''',
        ),
        (
            '''    final rawHeaderNames = json['headerNames'];
    if (rawHeaderNames != null && rawHeaderNames is! List) {
      throw const FormatException('HTTP response header names are invalid');
    }
    final headerNames = (rawHeaderNames as List? ?? const [])
        .map(
          (value) => _expectBoundedString(
            value,
            'HTTP response header name',
            maximumLength: maximumHttpObservedHeaderNameLength,
          ),
        )
        .toList(growable: false);
    if (headerNames.length > maximumHttpObservedHeaderNames) {
      throw const FormatException('Too many HTTP response header names');
    }
    final headersComplete = json['headersComplete'];
''',
            '''    final rawHeaderNames = json['headerNames'];
    if (rawHeaderNames != null && rawHeaderNames is! List) {
      throw const FormatException('HTTP response header names are invalid');
    }
    final headerNames = (rawHeaderNames as List? ?? const [])
        .map(
          (value) => _expectBoundedString(
            value,
            'HTTP response header name',
            maximumLength: maximumHttpObservedHeaderNameLength,
          ),
        )
        .toList(growable: false);
    if (headerNames.length > maximumHttpObservedHeaderNames) {
      throw const FormatException('Too many HTTP response header names');
    }
    final rawHeaders = json['headers'];
    if (rawHeaders != null && rawHeaders is! List) {
      throw const FormatException('HTTP response headers are invalid');
    }
    final headers = (rawHeaders as List? ?? const <Object?>[])
        .map((value) {
          if (value is! Map) {
            throw const FormatException('HTTP response header is invalid');
          }
          return HttpHeaderObservation.fromJson(
            Map<String, dynamic>.from(value),
          );
        })
        .toList(growable: false);
    if (headers.length > maximumHttpObservedHeaderNames) {
      throw const FormatException('Too many HTTP response headers');
    }
    final headerNameSet = headerNames.toSet();
    if (headers.any((value) => !headerNameSet.contains(value.name))) {
      throw const FormatException(
        'HTTP response header values do not match names',
      );
    }
    final headersComplete = json['headersComplete'];
''',
        ),
        (
            '''      informationalStatusCodes: informationalStatusCodes,
      headerNames: headerNames,
      headersComplete: headersComplete,
''',
            '''      informationalStatusCodes: informationalStatusCodes,
      headerNames: headerNames,
      headers: headers,
      headersComplete: headersComplete,
''',
        ),
        (
            '''      headerNamesTruncated: _boolOrFalse(
        json['headerNamesTruncated'],
        'HTTP response header names truncated',
      ),
      informationalStatusCodesTruncated: _boolOrFalse(
''',
            '''      headerNamesTruncated: _boolOrFalse(
        json['headerNamesTruncated'],
        'HTTP response header names truncated',
      ),
      headerValuesTruncated: _boolOrFalse(
        json['headerValuesTruncated'],
        'HTTP response header values truncated',
      ),
      informationalStatusCodesTruncated: _boolOrFalse(
''',
        ),
        (
            '''    if (headerNames.isNotEmpty) 'headerNames': headerNames,
    'headersComplete': headersComplete,
    'observedBytes': observedBytes,
''',
            '''    if (headerNames.isNotEmpty) 'headerNames': headerNames,
    if (headers.isNotEmpty)
      'headers': headers.map((value) => value.toJson()).toList(),
    'headersComplete': headersComplete,
    'observedBytes': observedBytes,
''',
        ),
        (
            '''    if (headerNamesTruncated) 'headerNamesTruncated': true,
    if (informationalStatusCodesTruncated)
''',
            '''    if (headerNamesTruncated) 'headerNamesTruncated': true,
    if (headerValuesTruncated) 'headerValuesTruncated': true,
    if (informationalStatusCodesTruncated)
''',
        ),
    ]
    for old, new in replacements:
        if old not in text:
            raise RuntimeError(f"missing common model replacement: {old[:100]!r}")
        text = text.replace(old, new, 1)
    path.write_text(text)


def _runtime_transaction_and_streams() -> str:
    return r'''class TlsInspectionRuntimeHttpTransaction {
  const TlsInspectionRuntimeHttpTransaction({
    required this.sequence,
    required this.requestObservedAfterMilliseconds,
    this.requestCompletedAfterMilliseconds = 0,
    this.responseCompletedAfterMilliseconds = 0,
    required this.request,
    this.requestBody,
    this.response,
    this.responseBody,
  });

  final int sequence;
  final int requestObservedAfterMilliseconds;
  final int requestCompletedAfterMilliseconds;
  final int responseCompletedAfterMilliseconds;
  final TlsInspectionRuntimeHttpRequest request;
  final TlsInspectionRuntimeHttpBody? requestBody;
  final TlsInspectionRuntimeHttpResponse? response;
  final TlsInspectionRuntimeHttpBody? responseBody;

  bool get complete => responseCompletedAfterMilliseconds > 0;

  factory TlsInspectionRuntimeHttpTransaction.fromJson(
    Map<String, dynamic> json,
  ) {
    final rawRequest = json['request'];
    if (rawRequest is! Map) {
      throw const FormatException('HTTP transaction request is invalid');
    }
    final rawResponse = json['response'];
    if (rawResponse != null && rawResponse is! Map) {
      throw const FormatException('HTTP transaction response is invalid');
    }
    final rawRequestBody = json['requestBody'];
    if (rawRequestBody != null && rawRequestBody is! Map) {
      throw const FormatException('HTTP transaction request body is invalid');
    }
    final rawResponseBody = json['responseBody'];
    if (rawResponseBody != null && rawResponseBody is! Map) {
      throw const FormatException('HTTP transaction response body is invalid');
    }
    final requestObservedAfterMilliseconds = _expectBoundedInt(
      json['requestObservedAfterMilliseconds'],
      'HTTP transaction request delay',
      minimum: 0,
      maximum: maximumTlsInspectionRuntimeElapsedMilliseconds,
    );
    final requestCompletedAfterMilliseconds = _optionalElapsedMilliseconds(
      json['requestCompletedAfterMilliseconds'],
      'HTTP transaction request completion delay',
    );
    final responseCompletedAfterMilliseconds = _optionalElapsedMilliseconds(
      json['responseCompletedAfterMilliseconds'],
      'HTTP transaction response completion delay',
    );
    if (requestCompletedAfterMilliseconds > 0 &&
        requestCompletedAfterMilliseconds < requestObservedAfterMilliseconds) {
      throw const FormatException(
        'HTTP transaction request completion precedes request',
      );
    }
    final response = rawResponse == null
        ? null
        : TlsInspectionRuntimeHttpResponse.fromJson(
            Map<String, dynamic>.from(rawResponse),
          );
    if (response != null &&
        response.observedAfterMilliseconds <
            requestObservedAfterMilliseconds) {
      throw const FormatException(
        'HTTP transaction response precedes its request',
      );
    }
    if (responseCompletedAfterMilliseconds > 0 &&
        (response == null ||
            responseCompletedAfterMilliseconds <
                response.observedAfterMilliseconds)) {
      throw const FormatException(
        'HTTP transaction response completion is invalid',
      );
    }
    return TlsInspectionRuntimeHttpTransaction(
      sequence: _expectBoundedInt(
        json['sequence'],
        'HTTP transaction sequence',
        minimum: 1,
        maximum: maximumTlsInspectionRuntimeTransactions,
      ),
      requestObservedAfterMilliseconds: requestObservedAfterMilliseconds,
      requestCompletedAfterMilliseconds: requestCompletedAfterMilliseconds,
      responseCompletedAfterMilliseconds: responseCompletedAfterMilliseconds,
      request: TlsInspectionRuntimeHttpRequest.fromJson(
        Map<String, dynamic>.from(rawRequest),
      ),
      requestBody: rawRequestBody == null
          ? null
          : TlsInspectionRuntimeHttpBody.fromJson(
              Map<String, dynamic>.from(rawRequestBody),
            ),
      response: response,
      responseBody: rawResponseBody == null
          ? null
          : TlsInspectionRuntimeHttpBody.fromJson(
              Map<String, dynamic>.from(rawResponseBody),
            ),
    );
  }

  Map<String, dynamic> toJson() => {
    'sequence': sequence,
    'requestObservedAfterMilliseconds': requestObservedAfterMilliseconds,
    if (requestCompletedAfterMilliseconds > 0)
      'requestCompletedAfterMilliseconds':
          requestCompletedAfterMilliseconds,
    if (responseCompletedAfterMilliseconds > 0)
      'responseCompletedAfterMilliseconds':
          responseCompletedAfterMilliseconds,
    'request': request.toJson(),
    if (requestBody != null) 'requestBody': requestBody!.toJson(),
    if (response != null) 'response': response!.toJson(),
    if (responseBody != null) 'responseBody': responseBody!.toJson(),
  };
}

class TlsInspectionRuntimeHttp2Stream {
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

  static const supportedStates = <String>{
    'open',
    'request-ended',
    'response-ended',
    'closed',
    'reset',
  };

  final int sequence;
  final int streamId;
  final String state;
  final int requestObservedAfterMilliseconds;
  final int requestCompletedAfterMilliseconds;
  final int responseCompletedAfterMilliseconds;
  final int resetCode;
  final TlsInspectionRuntimeHttpRequest request;
  final TlsInspectionRuntimeHttpBody? requestBody;
  final TlsInspectionRuntimeHttpResponse? response;
  final TlsInspectionRuntimeHttpBody? responseBody;

  bool get reset => state == 'reset';

  bool get closed => state == 'closed' || reset;

  factory TlsInspectionRuntimeHttp2Stream.fromJson(
    Map<String, dynamic> json,
  ) {
    final rawRequest = json['request'];
    if (rawRequest is! Map) {
      throw const FormatException('HTTP/2 stream request is invalid');
    }
    final rawResponse = json['response'];
    if (rawResponse != null && rawResponse is! Map) {
      throw const FormatException('HTTP/2 stream response is invalid');
    }
    final rawRequestBody = json['requestBody'];
    final rawResponseBody = json['responseBody'];
    if (rawRequestBody != null && rawRequestBody is! Map ||
        rawResponseBody != null && rawResponseBody is! Map) {
      throw const FormatException('HTTP/2 stream body is invalid');
    }
    final state = _expectBoundedString(
      json['state'],
      'HTTP/2 stream state',
      maximumLength: 32,
    );
    if (!supportedStates.contains(state)) {
      throw const FormatException('HTTP/2 stream state is unsupported');
    }
    final requestObservedAfterMilliseconds = _expectBoundedInt(
      json['requestObservedAfterMilliseconds'],
      'HTTP/2 request delay',
      minimum: 0,
      maximum: maximumTlsInspectionRuntimeElapsedMilliseconds,
    );
    final requestCompletedAfterMilliseconds = _optionalElapsedMilliseconds(
      json['requestCompletedAfterMilliseconds'],
      'HTTP/2 request completion delay',
    );
    final responseCompletedAfterMilliseconds = _optionalElapsedMilliseconds(
      json['responseCompletedAfterMilliseconds'],
      'HTTP/2 response completion delay',
    );
    final response = rawResponse == null
        ? null
        : TlsInspectionRuntimeHttpResponse.fromJson(
            Map<String, dynamic>.from(rawResponse),
          );
    if (requestCompletedAfterMilliseconds > 0 &&
        requestCompletedAfterMilliseconds < requestObservedAfterMilliseconds) {
      throw const FormatException('HTTP/2 request completion is invalid');
    }
    if (response != null &&
        response.observedAfterMilliseconds <
            requestObservedAfterMilliseconds) {
      throw const FormatException('HTTP/2 response precedes request');
    }
    if (responseCompletedAfterMilliseconds > 0 &&
        (response == null ||
            responseCompletedAfterMilliseconds <
                response.observedAfterMilliseconds)) {
      throw const FormatException('HTTP/2 response completion is invalid');
    }
    final streamId = _expectBoundedInt(
      json['streamId'],
      'HTTP/2 stream ID',
      minimum: 1,
      maximum: 0x7fffffff,
    );
    if (streamId.isEven) {
      throw const FormatException('Retained HTTP/2 stream ID must be odd');
    }
    final resetCode = _expectBoundedInt(
      json['resetCode'] ?? 0,
      'HTTP/2 reset code',
      minimum: 0,
      maximum: 0xffffffff,
    );
    if (state != 'reset' && resetCode != 0) {
      throw const FormatException('HTTP/2 reset code requires reset state');
    }
    return TlsInspectionRuntimeHttp2Stream(
      sequence: _expectBoundedInt(
        json['sequence'],
        'HTTP/2 stream sequence',
        minimum: 1,
        maximum: maximumTlsInspectionRuntimeTransactions,
      ),
      streamId: streamId,
      state: state,
      requestObservedAfterMilliseconds: requestObservedAfterMilliseconds,
      requestCompletedAfterMilliseconds: requestCompletedAfterMilliseconds,
      responseCompletedAfterMilliseconds: responseCompletedAfterMilliseconds,
      resetCode: resetCode,
      request: TlsInspectionRuntimeHttpRequest.fromJson(
        Map<String, dynamic>.from(rawRequest),
      ),
      requestBody: rawRequestBody == null
          ? null
          : TlsInspectionRuntimeHttpBody.fromJson(
              Map<String, dynamic>.from(rawRequestBody),
            ),
      response: response,
      responseBody: rawResponseBody == null
          ? null
          : TlsInspectionRuntimeHttpBody.fromJson(
              Map<String, dynamic>.from(rawResponseBody),
            ),
    );
  }

  Map<String, dynamic> toJson() => {
    'sequence': sequence,
    'streamId': streamId,
    'state': state,
    'requestObservedAfterMilliseconds': requestObservedAfterMilliseconds,
    if (requestCompletedAfterMilliseconds > 0)
      'requestCompletedAfterMilliseconds':
          requestCompletedAfterMilliseconds,
    if (responseCompletedAfterMilliseconds > 0)
      'responseCompletedAfterMilliseconds':
          responseCompletedAfterMilliseconds,
    if (resetCode != 0) 'resetCode': resetCode,
    'request': request.toJson(),
    if (requestBody != null) 'requestBody': requestBody!.toJson(),
    if (response != null) 'response': response!.toJson(),
    if (responseBody != null) 'responseBody': responseBody!.toJson(),
  };
}

class TlsInspectionRuntimeHttp2GoAway {
  const TlsInspectionRuntimeHttp2GoAway({
    required this.lastStreamId,
    required this.errorCode,
    required this.observedAfterMilliseconds,
  });

  final int lastStreamId;
  final int errorCode;
  final int observedAfterMilliseconds;

  factory TlsInspectionRuntimeHttp2GoAway.fromJson(
    Map<String, dynamic> json,
  ) {
    return TlsInspectionRuntimeHttp2GoAway(
      lastStreamId: _expectBoundedInt(
        json['lastStreamId'],
        'HTTP/2 GOAWAY last stream ID',
        minimum: 0,
        maximum: 0x7fffffff,
      ),
      errorCode: _expectBoundedInt(
        json['errorCode'],
        'HTTP/2 GOAWAY error code',
        minimum: 0,
        maximum: 0xffffffff,
      ),
      observedAfterMilliseconds: _expectBoundedInt(
        json['observedAfterMilliseconds'],
        'HTTP/2 GOAWAY delay',
        minimum: 0,
        maximum: maximumTlsInspectionRuntimeElapsedMilliseconds,
      ),
    );
  }

  Map<String, dynamic> toJson() => {
    'lastStreamId': lastStreamId,
    'errorCode': errorCode,
    'observedAfterMilliseconds': observedAfterMilliseconds,
  };
}

'''


def _runtime_observation() -> str:
    return r'''class TlsInspectionRuntimeObservation {
  const TlsInspectionRuntimeObservation({
    required this.sessionId,
    required this.connectionId,
    required this.runtimeId,
    required this.host,
    required this.state,
    required this.startedAt,
    this.completedAt,
    this.downstreamTlsVersion = '',
    this.upstreamTlsVersion = '',
    this.alpn = '',
    this.uploadedBytes = 0,
    this.downloadedBytes = 0,
    this.failureKind = '',
    this.downstreamTlsCompletedAfterMilliseconds = 0,
    this.upstreamDialCompletedAfterMilliseconds = 0,
    this.upstreamTlsCompletedAfterMilliseconds = 0,
    this.capturePolicy = TlsInspectionCapturePolicy.metadataOnly,
    this.httpTransactions = const <TlsInspectionRuntimeHttpTransaction>[],
    this.httpTransactionsTruncated = false,
    this.http2Streams = const <TlsInspectionRuntimeHttp2Stream>[],
    this.http2StreamsTruncated = false,
    this.http2GoAway,
    this.httpRequest,
    this.httpResponse,
  });

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
  final int uploadedBytes;
  final int downloadedBytes;
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
  final TlsInspectionRuntimeHttpRequest? httpRequest;
  final TlsInspectionRuntimeHttpResponse? httpResponse;

  bool get completed => state == 'completed';

  bool get failed => state == 'failed';

  bool get interrupted => state == 'interrupted';

  bool get terminal => completed || failed || interrupted;

  bool get hasHttp2Streams => http2Streams.isNotEmpty;

  bool get hasPayloadCapture =>
      capturePolicy.headerValues || capturePolicy.capturesBodies;

  TlsInspectionRuntimeHttpRequest? get effectiveHttpRequest {
    if (httpTransactions.isNotEmpty) {
      return httpTransactions.first.request;
    }
    if (http2Streams.isNotEmpty) {
      return http2Streams.first.request;
    }
    return httpRequest;
  }

  TlsInspectionRuntimeHttpResponse? get effectiveHttpResponse {
    if (httpTransactions.isNotEmpty) {
      return httpTransactions.first.response;
    }
    if (http2Streams.isNotEmpty) {
      return http2Streams.first.response;
    }
    return httpResponse;
  }

  int get metadataRank {
    if (http2Streams.isNotEmpty || httpTransactions.isNotEmpty) {
      return 5;
    }
    if (httpResponse != null) {
      return 4;
    }
    if (httpRequest != null) {
      return 3;
    }
    if (terminal) {
      return 2;
    }
    return 1;
  }

  TlsInspectionRuntimeObservation interrupt(DateTime at) {
    if (terminal) {
      return this;
    }
    final completed = at.isBefore(startedAt) ? startedAt : at.toUtc();
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
      uploadedBytes: uploadedBytes,
      downloadedBytes: downloadedBytes,
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
      httpRequest: httpRequest,
      httpResponse: httpResponse,
    );
  }

  factory TlsInspectionRuntimeObservation.fromJson(
    Map<String, dynamic> json,
  ) {
    final sessionId = _expectBoundedString(
      json['sessionId'],
      'runtime observation session ID',
      maximumLength: maximumTlsInspectionRuntimeSessionIdLength,
    );
    if (!RegExp(r'^[a-f0-9]{32}$').hasMatch(sessionId)) {
      throw const FormatException('Runtime observation session ID is invalid');
    }
    final connectionId = _expectBoundedString(
      json['connectionId'],
      'runtime observation connection ID',
      maximumLength: maximumTlsInspectionRuntimeConnectionIdLength,
    );
    if (!RegExp(r'^[a-f0-9]{32}$').hasMatch(connectionId)) {
      throw const FormatException(
        'Runtime observation connection ID is invalid',
      );
    }
    final runtimeId = _expectBoundedString(
      json['runtimeId'],
      'runtime observation ID',
      maximumLength: maximumTlsInspectionRuntimeIdLength,
    );
    if (!RegExp(r'^[a-f0-9]{32}$').hasMatch(runtimeId)) {
      throw const FormatException('Runtime observation ID is invalid');
    }
    final host = _normalizeInspectionHost(
      json['host'],
      'runtime observation host',
    );
    final state = _expectBoundedString(
      json['state'],
      'runtime observation state',
      maximumLength: 16,
    );
    if (!const {'running', 'completed', 'failed', 'interrupted'}.contains(
      state,
    )) {
      throw const FormatException('Runtime observation state is unsupported');
    }
    final startedAt = _expectUtcTimestamp(
      json['startedAt'],
      'runtime observation start',
    );
    final rawCompletedAt = json['completedAt'];
    final completedAt = rawCompletedAt == null
        ? null
        : _expectUtcTimestamp(
            rawCompletedAt,
            'runtime observation completion',
          );
    if (state == 'running' && completedAt != null ||
        state != 'running' && completedAt == null ||
        completedAt != null && completedAt.isBefore(startedAt)) {
      throw const FormatException(
        'Runtime observation completion is invalid',
      );
    }
    final downstreamTlsVersion = _optionalBoundedString(
      json['downstreamTlsVersion'],
      'downstream TLS version',
      maximumLength: maximumTlsInspectionRuntimeProtocolValueLength,
    );
    final upstreamTlsVersion = _optionalBoundedString(
      json['upstreamTlsVersion'],
      'upstream TLS version',
      maximumLength: maximumTlsInspectionRuntimeProtocolValueLength,
    );
    final alpn = _optionalBoundedString(
      json['alpn'],
      'ALPN',
      maximumLength: maximumTlsInspectionRuntimeProtocolValueLength,
    );
    if (alpn.isNotEmpty && alpn != 'http/1.1' && alpn != 'h2') {
      throw const FormatException('Runtime observation ALPN is unsupported');
    }
    final uploadedBytes = _optionalByteCount(
      json['uploadedBytes'],
      'runtime observation upload',
    );
    final downloadedBytes = _optionalByteCount(
      json['downloadedBytes'],
      'runtime observation download',
    );
    final failureKind = _optionalBoundedString(
      json['failureKind'],
      'runtime observation failure kind',
      maximumLength: maximumTlsInspectionRuntimeFailureKindLength,
    );
    if (state == 'failed' && failureKind.isEmpty ||
        state != 'failed' && failureKind.isNotEmpty) {
      throw const FormatException('Runtime observation failure is invalid');
    }
    final downstreamTlsCompleted = _optionalElapsedMilliseconds(
      json['downstreamTlsCompletedAfterMilliseconds'],
      'downstream TLS completion delay',
    );
    final upstreamDialCompleted = _optionalElapsedMilliseconds(
      json['upstreamDialCompletedAfterMilliseconds'],
      'upstream dial completion delay',
    );
    final upstreamTlsCompleted = _optionalElapsedMilliseconds(
      json['upstreamTlsCompletedAfterMilliseconds'],
      'upstream TLS completion delay',
    );
    if (upstreamTlsCompleted > 0 &&
            upstreamDialCompleted > upstreamTlsCompleted ||
        downstreamTlsCompleted > 0 &&
            upstreamTlsCompleted > downstreamTlsCompleted) {
      throw const FormatException('Runtime timing milestones are invalid');
    }
    final rawPolicy = json['capturePolicy'];
    if (rawPolicy != null && rawPolicy is! Map) {
      throw const FormatException('Runtime capture policy is invalid');
    }
    final capturePolicy = rawPolicy == null
        ? TlsInspectionCapturePolicy.metadataOnly
        : TlsInspectionCapturePolicy.fromJson(
            Map<String, dynamic>.from(rawPolicy),
          );
    final rawTransactions = json['httpTransactions'];
    if (rawTransactions != null && rawTransactions is! List) {
      throw const FormatException('Runtime HTTP transactions are invalid');
    }
    final transactions = (rawTransactions as List? ?? const <Object?>[])
        .map((value) {
          if (value is! Map) {
            throw const FormatException(
              'Runtime HTTP transaction is invalid',
            );
          }
          return TlsInspectionRuntimeHttpTransaction.fromJson(
            Map<String, dynamic>.from(value),
          );
        })
        .toList(growable: false);
    final rawStreams = json['http2Streams'];
    if (rawStreams != null && rawStreams is! List) {
      throw const FormatException('Runtime HTTP/2 streams are invalid');
    }
    final streams = (rawStreams as List? ?? const <Object?>[])
        .map((value) {
          if (value is! Map) {
            throw const FormatException('Runtime HTTP/2 stream is invalid');
          }
          return TlsInspectionRuntimeHttp2Stream.fromJson(
            Map<String, dynamic>.from(value),
          );
        })
        .toList(growable: false);
    if (transactions.length > maximumTlsInspectionRuntimeTransactions ||
        streams.length > maximumTlsInspectionRuntimeTransactions ||
        transactions.isNotEmpty && streams.isNotEmpty) {
      throw const FormatException('Runtime HTTP timeline is invalid');
    }
    final rawGoAway = json['http2GoAway'];
    if (rawGoAway != null && rawGoAway is! Map) {
      throw const FormatException('Runtime HTTP/2 GOAWAY is invalid');
    }
    final goAway = rawGoAway == null
        ? null
        : TlsInspectionRuntimeHttp2GoAway.fromJson(
            Map<String, dynamic>.from(rawGoAway),
          );
    if ((streams.isNotEmpty || goAway != null) && alpn != 'h2') {
      throw const FormatException('HTTP/2 metadata requires h2 ALPN');
    }
    final rawHttpRequest = json['httpRequest'];
    final rawHttpResponse = json['httpResponse'];
    if (rawHttpRequest != null && rawHttpRequest is! Map ||
        rawHttpResponse != null && rawHttpResponse is! Map) {
      throw const FormatException('Legacy runtime HTTP metadata is invalid');
    }
    if ((transactions.isNotEmpty || streams.isNotEmpty) &&
        (rawHttpRequest != null || rawHttpResponse != null)) {
      throw const FormatException(
        'Runtime HTTP timelines cannot mix with legacy metadata',
      );
    }
    final httpRequest = rawHttpRequest == null
        ? null
        : TlsInspectionRuntimeHttpRequest.fromJson(
            Map<String, dynamic>.from(rawHttpRequest),
          );
    final httpResponse = rawHttpResponse == null
        ? null
        : TlsInspectionRuntimeHttpResponse.fromJson(
            Map<String, dynamic>.from(rawHttpResponse),
          );
    if (httpResponse != null && httpRequest == null) {
      throw const FormatException(
        'Runtime HTTP response requires request metadata',
      );
    }
    if (httpRequest != null && httpRequest.host != host) {
      throw const FormatException(
        'Runtime HTTP request host does not match connection host',
      );
    }
    _validateHttpTimeline(
      transactions,
      streams,
      host,
      completedAt?.difference(startedAt).inMilliseconds,
      capturePolicy,
    );
    return TlsInspectionRuntimeObservation(
      sessionId: sessionId,
      connectionId: connectionId,
      runtimeId: runtimeId,
      host: host,
      state: state,
      startedAt: startedAt,
      completedAt: completedAt,
      downstreamTlsVersion: downstreamTlsVersion,
      upstreamTlsVersion: upstreamTlsVersion,
      alpn: alpn,
      uploadedBytes: uploadedBytes,
      downloadedBytes: downloadedBytes,
      failureKind: failureKind,
      downstreamTlsCompletedAfterMilliseconds: downstreamTlsCompleted,
      upstreamDialCompletedAfterMilliseconds: upstreamDialCompleted,
      upstreamTlsCompletedAfterMilliseconds: upstreamTlsCompleted,
      capturePolicy: capturePolicy,
      httpTransactions: List.unmodifiable(transactions),
      httpTransactionsTruncated: _boolOrFalse(
        json['httpTransactionsTruncated'],
        'runtime HTTP transactions truncated',
      ),
      http2Streams: List.unmodifiable(streams),
      http2StreamsTruncated: _boolOrFalse(
        json['http2StreamsTruncated'],
        'runtime HTTP/2 streams truncated',
      ),
      http2GoAway: goAway,
      httpRequest: httpRequest,
      httpResponse: httpResponse,
    );
  }

  Map<String, dynamic> toJson() => {
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
    if (upstreamTlsVersion.isNotEmpty)
      'upstreamTlsVersion': upstreamTlsVersion,
    if (alpn.isNotEmpty) 'alpn': alpn,
    if (uploadedBytes > 0) 'uploadedBytes': uploadedBytes,
    if (downloadedBytes > 0) 'downloadedBytes': downloadedBytes,
    if (failureKind.isNotEmpty) 'failureKind': failureKind,
    if (downstreamTlsCompletedAfterMilliseconds > 0)
      'downstreamTlsCompletedAfterMilliseconds':
          downstreamTlsCompletedAfterMilliseconds,
    if (upstreamDialCompletedAfterMilliseconds > 0)
      'upstreamDialCompletedAfterMilliseconds':
          upstreamDialCompletedAfterMilliseconds,
    if (upstreamTlsCompletedAfterMilliseconds > 0)
      'upstreamTlsCompletedAfterMilliseconds':
          upstreamTlsCompletedAfterMilliseconds,
    'capturePolicy': capturePolicy.toJson(),
    if (httpTransactions.isNotEmpty)
      'httpTransactions': httpTransactions
          .map((value) => value.toJson())
          .toList(growable: false),
    if (httpTransactionsTruncated) 'httpTransactionsTruncated': true,
    if (http2Streams.isNotEmpty)
      'http2Streams': http2Streams
          .map((value) => value.toJson())
          .toList(growable: false),
    if (http2StreamsTruncated) 'http2StreamsTruncated': true,
    if (http2GoAway != null) 'http2GoAway': http2GoAway!.toJson(),
    if (httpRequest != null) 'httpRequest': httpRequest!.toJson(),
    if (httpResponse != null) 'httpResponse': httpResponse!.toJson(),
  };
}

int _optionalElapsedMilliseconds(Object? value, String name) {
  if (value == null) {
    return 0;
  }
  return _expectBoundedInt(
    value,
    name,
    minimum: 0,
    maximum: maximumTlsInspectionRuntimeElapsedMilliseconds,
  );
}

void _validateHttpTimeline(
  List<TlsInspectionRuntimeHttpTransaction> transactions,
  List<TlsInspectionRuntimeHttp2Stream> streams,
  String host,
  int? durationMilliseconds,
  TlsInspectionCapturePolicy policy,
) {
  var previousDelay = -1;
  final streamIds = <int>{};
  for (var index = 0; index < transactions.length; index++) {
    final transaction = transactions[index];
    if (transaction.sequence != index + 1 ||
        transaction.requestObservedAfterMilliseconds < previousDelay ||
        transaction.request.host != host) {
      throw const FormatException('Runtime HTTP transaction order is invalid');
    }
    previousDelay = transaction.requestObservedAfterMilliseconds;
    _validateCaptureAuthorization(
      transaction.request,
      transaction.requestBody,
      transaction.response,
      transaction.responseBody,
      policy,
    );
    _validateTimelineDuration(
      durationMilliseconds,
      <int>[
        transaction.requestObservedAfterMilliseconds,
        transaction.requestCompletedAfterMilliseconds,
        transaction.response?.observedAfterMilliseconds ?? 0,
        transaction.responseCompletedAfterMilliseconds,
      ],
    );
  }
  previousDelay = -1;
  for (var index = 0; index < streams.length; index++) {
    final stream = streams[index];
    if (stream.sequence != index + 1 ||
        stream.requestObservedAfterMilliseconds < previousDelay ||
        stream.request.host != host ||
        !streamIds.add(stream.streamId)) {
      throw const FormatException('Runtime HTTP/2 stream order is invalid');
    }
    previousDelay = stream.requestObservedAfterMilliseconds;
    _validateCaptureAuthorization(
      stream.request,
      stream.requestBody,
      stream.response,
      stream.responseBody,
      policy,
    );
    _validateTimelineDuration(
      durationMilliseconds,
      <int>[
        stream.requestObservedAfterMilliseconds,
        stream.requestCompletedAfterMilliseconds,
        stream.response?.observedAfterMilliseconds ?? 0,
        stream.responseCompletedAfterMilliseconds,
      ],
    );
  }
}

void _validateTimelineDuration(int? durationMilliseconds, List<int> values) {
  if (durationMilliseconds == null) {
    return;
  }
  if (values.any((value) => value > durationMilliseconds)) {
    throw const FormatException('Runtime HTTP timing exceeds connection');
  }
}

void _validateCaptureAuthorization(
  HttpProtocolObservation request,
  TlsInspectionRuntimeHttpBody? requestBody,
  HttpResponseProtocolObservation? response,
  TlsInspectionRuntimeHttpBody? responseBody,
  TlsInspectionCapturePolicy policy,
) {
  if (!policy.headerValues &&
      (request.headers.isNotEmpty || response?.headers.isNotEmpty == true)) {
    throw const FormatException('Header values were captured without consent');
  }
  for (final header in <HttpHeaderObservation>[
    ...request.headers,
    ...?response?.headers,
  ]) {
    if (header.sensitive &&
        !header.redacted &&
        !policy.capturesSensitiveValues) {
      throw const FormatException(
        'Sensitive header value was captured without consent',
      );
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
      throw const FormatException('Body was captured without consent');
    }
    if (policy.bodyMode == TlsInspectionCaptureBodyMode.text &&
        body.capturedBytes > 0 &&
        const {'image', 'binary', 'multipart'}.contains(body.kind)) {
      throw const FormatException('Binary body exceeded capture consent');
    }
  }
}

'''


def _runtime_status() -> str:
    return r'''class TlsInspectionRuntimeStatus {
  const TlsInspectionRuntimeStatus({
    required this.state,
    required this.id,
    required this.listenHost,
    required this.listenPort,
    required this.mode,
    required this.capacity,
    required this.connectionLifetimeSeconds,
    required this.clientAuthenticationRequired,
    required this.hostAllowlistRequired,
    required this.upstreamCertificateVerification,
    required this.acceptsConnectOnly,
    required this.capturesPayload,
    this.capturePolicy = TlsInspectionCapturePolicy.metadataOnly,
    required this.changesSystemProxy,
  });

  final String state;
  final String id;
  final String listenHost;
  final int listenPort;
  final String mode;
  final int capacity;
  final int connectionLifetimeSeconds;
  final bool clientAuthenticationRequired;
  final bool hostAllowlistRequired;
  final bool upstreamCertificateVerification;
  final bool acceptsConnectOnly;
  final bool capturesPayload;
  final TlsInspectionCapturePolicy capturePolicy;
  final bool changesSystemProxy;

  bool get running => state == 'running';

  bool get supportsHttp2 => mode == 'loopback-connect-http1-h2';

  factory TlsInspectionRuntimeStatus.fromJson(Map<String, dynamic> json) {
    final state = _expectBoundedString(
      json['state'],
      'runtime state',
      maximumLength: 16,
    );
    if (state != 'running' && state != 'stopped') {
      throw const FormatException('Unsupported runtime state');
    }
    final mode = _expectBoundedString(
      json['mode'],
      'runtime mode',
      maximumLength: 64,
    );
    if (mode != 'loopback-connect-http1' &&
        mode != 'loopback-connect-http1-h2') {
      throw const FormatException('Unsupported runtime mode');
    }
    final rawPolicy = json['capturePolicy'];
    if (rawPolicy != null && rawPolicy is! Map) {
      throw const FormatException('Runtime capture policy is invalid');
    }
    final policy = rawPolicy == null
        ? TlsInspectionCapturePolicy.metadataOnly
        : TlsInspectionCapturePolicy.fromJson(
            Map<String, dynamic>.from(rawPolicy),
          );
    final capturesPayload = _expectBool(
      json['capturesPayload'],
      'payload capture flag',
    );
    if (capturesPayload != policy.capturesBodies) {
      throw const FormatException('Runtime payload policy is inconsistent');
    }
    final status = TlsInspectionRuntimeStatus(
      state: state,
      id: _optionalBoundedString(
        json['id'],
        'runtime ID',
        maximumLength: maximumTlsInspectionRuntimeIdLength,
      ),
      listenHost: _expectBoundedString(
        json['listenHost'],
        'runtime listen host',
        maximumLength: 64,
      ),
      listenPort: _expectBoundedInt(
        json['listenPort'],
        'runtime listen port',
        minimum: 0,
        maximum: 65535,
      ),
      mode: mode,
      capacity: _expectBoundedInt(
        json['capacity'],
        'runtime capacity',
        minimum: 1,
        maximum: 4096,
      ),
      connectionLifetimeSeconds: _expectBoundedInt(
        json['connectionLifetimeSeconds'],
        'runtime connection lifetime',
        minimum: 1,
        maximum: 86400,
      ),
      clientAuthenticationRequired: _expectBool(
        json['clientAuthenticationRequired'],
        'client authentication flag',
      ),
      hostAllowlistRequired: _expectBool(
        json['hostAllowlistRequired'],
        'host allowlist flag',
      ),
      upstreamCertificateVerification: _expectBool(
        json['upstreamCertificateVerification'],
        'upstream certificate verification flag',
      ),
      acceptsConnectOnly: _expectBool(
        json['acceptsConnectOnly'],
        'CONNECT-only flag',
      ),
      capturesPayload: capturesPayload,
      capturePolicy: policy,
      changesSystemProxy: _expectBool(
        json['changesSystemProxy'],
        'system proxy flag',
      ),
    );
    _validateRuntimeStatus(status);
    return status;
  }

  Map<String, dynamic> toJson() => {
    'state': state,
    'id': id,
    'listenHost': listenHost,
    'listenPort': listenPort,
    'mode': mode,
    'capacity': capacity,
    'connectionLifetimeSeconds': connectionLifetimeSeconds,
    'clientAuthenticationRequired': clientAuthenticationRequired,
    'hostAllowlistRequired': hostAllowlistRequired,
    'upstreamCertificateVerification': upstreamCertificateVerification,
    'acceptsConnectOnly': acceptsConnectOnly,
    'capturesPayload': capturesPayload,
    'capturePolicy': capturePolicy.toJson(),
    'changesSystemProxy': changesSystemProxy,
  };
}

'''


def patch_runtime_models() -> None:
    path = ROOT / "lib/models/tls_inspection_runtime.dart"
    text = path.read_text()
    if "import 'http_inspection.dart';" not in text:
        text = text.replace("import 'common.dart';\n", "import 'common.dart';\nimport 'http_inspection.dart';\n", 1)
    text = text.replace(
        '''    super.headerNames = const <String>[],
    required super.headersComplete,
    super.targetTruncated = false,
    super.hostTruncated = false,
    super.headerNamesTruncated = false,
  });
''',
        '''    super.headerNames = const <String>[],
    super.headers = const <HttpHeaderObservation>[],
    required super.headersComplete,
    super.targetTruncated = false,
    super.hostTruncated = false,
    super.headerNamesTruncated = false,
    super.headerValuesTruncated = false,
  });
''',
        1,
    )
    text = text.replace(
        '''    super.headerNames = const <String>[],
    required super.headersComplete,
    required super.observedBytes,
''',
        '''    super.headerNames = const <String>[],
    super.headers = const <HttpHeaderObservation>[],
    required super.headersComplete,
    required super.observedBytes,
''',
        1,
    )
    text = text.replace(
        '''    super.truncated = false,
    super.headerNamesTruncated = false,
    super.informationalStatusCodesTruncated = false,
  });
''',
        '''    super.truncated = false,
    super.headerNamesTruncated = false,
    super.headerValuesTruncated = false,
    super.informationalStatusCodesTruncated = false,
  });
''',
        1,
    )
    transaction_start = text.index("class TlsInspectionRuntimeHttpTransaction {")
    observation_start = text.index("class TlsInspectionRuntimeObservation {")
    text = (
        text[:transaction_start]
        + _runtime_transaction_and_streams()
        + text[observation_start:]
    )
    observation_start = text.index("class TlsInspectionRuntimeObservation {")
    status_start = text.index("class TlsInspectionRuntimeStatus {")
    text = text[:observation_start] + _runtime_observation() + text[status_start:]
    status_start = text.index("class TlsInspectionRuntimeStatus {")
    start_params = text.index("class TlsInspectionRuntimeStartParams {")
    text = text[:status_start] + _runtime_status() + text[start_params:]
    text = text.replace(
        '''  if (status.mode != 'loopback-connect-http1' ||
      status.listenHost != '127.0.0.1' ||
''',
        '''  if ((status.mode != 'loopback-connect-http1' &&
          status.mode != 'loopback-connect-http1-h2') ||
      status.listenHost != '127.0.0.1' ||
''',
        1,
    )
    text = text.replace(
        '''      !status.acceptsConnectOnly ||
      status.capturesPayload ||
      status.changesSystemProxy) {
''',
        '''      !status.acceptsConnectOnly ||
      status.capturesPayload != status.capturePolicy.capturesBodies ||
      status.changesSystemProxy) {
''',
        1,
    )
    path.write_text(text)


def patch_all() -> None:
    patch_models_export()
    patch_common_protocol_models()
    patch_runtime_models()
