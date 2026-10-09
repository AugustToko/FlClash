import 'dart:convert';
import 'dart:typed_data';

const int maximumInspectionHeaderValueBytes = 4096;
const int maximumInspectionBodyBytes = 64 * 1024;
const int defaultInspectionBodyBytes = 16 * 1024;
const int maximumInspectionRedactedHeaderNames = 32;

final RegExp _httpTokenPattern = RegExp(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$");

String _boundedString(
  Object? value,
  String name, {
  required int maximumLength,
  bool allowEmpty = true,
}) {
  if (value is! String || (!allowEmpty && value.isEmpty)) {
    throw FormatException('$name is invalid');
  }
  if (value.length > maximumLength) {
    throw FormatException('$name is too long');
  }
  return value;
}

int _boundedInt(
  Object? value,
  String name, {
  required int minimum,
  required int maximum,
}) {
  if (value is! num || !value.isFinite || value != value.roundToDouble()) {
    throw FormatException('$name is invalid');
  }
  final result = value.toInt();
  if (result < minimum || result > maximum) {
    throw FormatException('$name is out of range');
  }
  return result;
}

bool _boolOrFalse(Object? value, String name) {
  if (value == null) {
    return false;
  }
  if (value is! bool) {
    throw FormatException('$name is invalid');
  }
  return value;
}

class HttpHeaderObservation {
  const HttpHeaderObservation({
    required this.name,
    this.value = '',
    this.redacted = false,
    this.truncated = false,
  });

  final String name;
  final String value;
  final bool redacted;
  final bool truncated;

  bool get hasVisibleValue => !redacted && value.isNotEmpty;

  bool get sensitive {
    final normalized = name.toLowerCase();
    return const <String>{
          'authorization',
          'proxy-authorization',
          'cookie',
          'set-cookie',
          'x-api-key',
          'api-key',
          'x-auth-token',
          'x-csrf-token',
          'x-xsrf-token',
          'www-authenticate',
          'proxy-authenticate',
        }.contains(normalized) ||
        normalized.contains('token') ||
        normalized.contains('secret') ||
        normalized.contains('credential') ||
        normalized.contains('session');
  }

  factory HttpHeaderObservation.fromJson(Map<String, dynamic> json) {
    final name = _boundedString(
      json['name'],
      'header.name',
      maximumLength: 256,
      allowEmpty: false,
    );
    if (name != name.toLowerCase() || !_httpTokenPattern.hasMatch(name)) {
      throw const FormatException('header.name is invalid');
    }
    final redacted = _boolOrFalse(json['redacted'], 'header.redacted');
    final value = _boundedString(
      json['value'] ?? '',
      'header.value',
      maximumLength: maximumInspectionHeaderValueBytes,
    );
    if (redacted && value.isNotEmpty) {
      throw const FormatException('redacted header value must be empty');
    }
    return HttpHeaderObservation(
      name: name,
      value: value,
      redacted: redacted,
      truncated: _boolOrFalse(json['truncated'], 'header.truncated'),
    );
  }

  Map<String, dynamic> toJson() => {
    'name': name,
    if (value.isNotEmpty) 'value': value,
    if (redacted) 'redacted': true,
    if (truncated) 'truncated': true,
  };
}

enum TlsInspectionCaptureBodyMode {
  none('none'),
  text('text'),
  all('all');

  const TlsInspectionCaptureBodyMode(this.value);

  final String value;

  static TlsInspectionCaptureBodyMode parse(Object? value) {
    for (final mode in values) {
      if (mode.value == value) {
        return mode;
      }
    }
    throw const FormatException('capturePolicy.bodyMode is invalid');
  }
}

class TlsInspectionCapturePolicy {
  const TlsInspectionCapturePolicy({
    this.headerValues = false,
    this.sensitiveHeaderValues = false,
    this.redactedHeaderNames = const <String>[],
    this.bodyMode = TlsInspectionCaptureBodyMode.none,
    this.maxBodyBytes = 0,
  });

  static const metadataOnly = TlsInspectionCapturePolicy();

  final bool headerValues;
  final bool sensitiveHeaderValues;
  final List<String> redactedHeaderNames;
  final TlsInspectionCaptureBodyMode bodyMode;
  final int maxBodyBytes;

  bool get capturesBodies => bodyMode != TlsInspectionCaptureBodyMode.none;

  bool get capturesSensitiveValues => headerValues && sensitiveHeaderValues;

  bool get isMetadataOnly => !headerValues && !capturesBodies;

  TlsInspectionCapturePolicy normalized() {
    final normalizedNames = <String>{};
    for (final rawName in redactedHeaderNames) {
      final name = rawName.trim().toLowerCase();
      if (name.isEmpty ||
          name.length > 256 ||
          !_httpTokenPattern.hasMatch(name)) {
        continue;
      }
      normalizedNames.add(name);
      if (normalizedNames.length >= maximumInspectionRedactedHeaderNames) {
        break;
      }
    }
    final names = normalizedNames.toList()..sort();
    final normalizedMode = bodyMode;
    final normalizedMaximum =
        normalizedMode == TlsInspectionCaptureBodyMode.none
        ? 0
        : maxBodyBytes.clamp(1, maximumInspectionBodyBytes);
    return TlsInspectionCapturePolicy(
      headerValues: headerValues,
      sensitiveHeaderValues: headerValues && sensitiveHeaderValues,
      redactedHeaderNames: List.unmodifiable(names),
      bodyMode: normalizedMode,
      maxBodyBytes: normalizedMaximum,
    );
  }

  TlsInspectionCapturePolicy copyWith({
    bool? headerValues,
    bool? sensitiveHeaderValues,
    List<String>? redactedHeaderNames,
    TlsInspectionCaptureBodyMode? bodyMode,
    int? maxBodyBytes,
  }) {
    return TlsInspectionCapturePolicy(
      headerValues: headerValues ?? this.headerValues,
      sensitiveHeaderValues:
          sensitiveHeaderValues ?? this.sensitiveHeaderValues,
      redactedHeaderNames: redactedHeaderNames ?? this.redactedHeaderNames,
      bodyMode: bodyMode ?? this.bodyMode,
      maxBodyBytes: maxBodyBytes ?? this.maxBodyBytes,
    ).normalized();
  }

  factory TlsInspectionCapturePolicy.fromJson(Map<String, dynamic> json) {
    final headerValues = _boolOrFalse(
      json['headerValues'],
      'capturePolicy.headerValues',
    );
    final sensitiveHeaderValues = _boolOrFalse(
      json['sensitiveHeaderValues'],
      'capturePolicy.sensitiveHeaderValues',
    );
    if (sensitiveHeaderValues && !headerValues) {
      throw const FormatException(
        'sensitive header capture requires header capture',
      );
    }
    final rawNames = json['redactedHeaderNames'];
    if (rawNames != null && rawNames is! List) {
      throw const FormatException(
        'capturePolicy.redactedHeaderNames is invalid',
      );
    }
    final names = <String>[];
    final seen = <String>{};
    for (final value in rawNames as List? ?? const <Object?>[]) {
      final name = _boundedString(
        value,
        'capturePolicy.redactedHeaderNames',
        maximumLength: 256,
        allowEmpty: false,
      );
      if (name != name.toLowerCase() ||
          !_httpTokenPattern.hasMatch(name) ||
          !seen.add(name)) {
        throw const FormatException(
          'capturePolicy.redactedHeaderNames is invalid',
        );
      }
      names.add(name);
      if (names.length > maximumInspectionRedactedHeaderNames) {
        throw const FormatException(
          'capturePolicy.redactedHeaderNames is too large',
        );
      }
    }
    final bodyMode = TlsInspectionCaptureBodyMode.parse(
      json['bodyMode'] ?? 'none',
    );
    final maxBodyBytes = json['maxBodyBytes'] == null
        ? 0
        : _boundedInt(
            json['maxBodyBytes'],
            'capturePolicy.maxBodyBytes',
            minimum: 0,
            maximum: maximumInspectionBodyBytes,
          );
    if (bodyMode == TlsInspectionCaptureBodyMode.none && maxBodyBytes != 0) {
      throw const FormatException(
        'metadata-only capture cannot retain body bytes',
      );
    }
    if (bodyMode != TlsInspectionCaptureBodyMode.none && maxBodyBytes <= 0) {
      throw const FormatException('body capture requires a positive limit');
    }
    return TlsInspectionCapturePolicy(
      headerValues: headerValues,
      sensitiveHeaderValues: sensitiveHeaderValues,
      redactedHeaderNames: List.unmodifiable(names),
      bodyMode: bodyMode,
      maxBodyBytes: maxBodyBytes,
    );
  }

  Map<String, dynamic> toJson() => {
    'headerValues': headerValues,
    'sensitiveHeaderValues': sensitiveHeaderValues,
    if (redactedHeaderNames.isNotEmpty)
      'redactedHeaderNames': redactedHeaderNames,
    'bodyMode': bodyMode.value,
    'maxBodyBytes': maxBodyBytes,
  };

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) {
      return true;
    }
    if (other is! TlsInspectionCapturePolicy ||
        headerValues != other.headerValues ||
        sensitiveHeaderValues != other.sensitiveHeaderValues ||
        bodyMode != other.bodyMode ||
        maxBodyBytes != other.maxBodyBytes ||
        redactedHeaderNames.length != other.redactedHeaderNames.length) {
      return false;
    }
    for (var index = 0; index < redactedHeaderNames.length; index++) {
      if (redactedHeaderNames[index] != other.redactedHeaderNames[index]) {
        return false;
      }
    }
    return true;
  }

  @override
  int get hashCode => Object.hash(
    headerValues,
    sensitiveHeaderValues,
    bodyMode,
    maxBodyBytes,
    Object.hashAll(redactedHeaderNames),
  );
}

class TlsInspectionRuntimeHttpBody {
  const TlsInspectionRuntimeHttpBody({
    required this.kind,
    this.contentType = '',
    this.contentEncoding = '',
    this.encoding = '',
    this.text = '',
    this.base64 = '',
    required this.capturedBytes,
    required this.observedBytes,
    this.truncated = false,
    this.omittedReason = '',
  });

  static const Set<String> supportedKinds = {
    'json',
    'form',
    'multipart',
    'image',
    'text',
    'binary',
  };

  final String kind;
  final String contentType;
  final String contentEncoding;
  final String encoding;
  final String text;
  final String base64;
  final int capturedBytes;
  final int observedBytes;
  final bool truncated;
  final String omittedReason;

  bool get omitted => omittedReason.isNotEmpty;

  bool get hasPayload => text.isNotEmpty || base64.isNotEmpty;

  Uint8List? get decodedBytes {
    if (encoding != 'base64' || base64.isEmpty) {
      return null;
    }
    try {
      return base64Decode(base64);
    } on FormatException {
      return null;
    }
  }

  String get prettyText {
    if (text.isEmpty || kind != 'json') {
      return text;
    }
    try {
      return const JsonEncoder.withIndent('  ').convert(jsonDecode(text));
    } on FormatException {
      return text;
    }
  }

  Map<String, String> get formFields {
    if (kind != 'form' || text.isEmpty) {
      return const {};
    }
    try {
      return Uri.splitQueryString(text);
    } on FormatException {
      return const {};
    }
  }

  factory TlsInspectionRuntimeHttpBody.fromJson(Map<String, dynamic> json) {
    final kind = _boundedString(
      json['kind'],
      'body.kind',
      maximumLength: 16,
      allowEmpty: false,
    );
    if (!supportedKinds.contains(kind)) {
      throw const FormatException('body.kind is unsupported');
    }
    final contentType = _boundedString(
      json['contentType'] ?? '',
      'body.contentType',
      maximumLength: 256,
    );
    final contentEncoding = _boundedString(
      json['contentEncoding'] ?? '',
      'body.contentEncoding',
      maximumLength: 256,
    );
    final encoding = _boundedString(
      json['encoding'] ?? '',
      'body.encoding',
      maximumLength: 16,
    );
    if (encoding.isNotEmpty && encoding != 'utf8' && encoding != 'base64') {
      throw const FormatException('body.encoding is unsupported');
    }
    final text = _boundedString(
      json['text'] ?? '',
      'body.text',
      maximumLength: maximumInspectionBodyBytes,
    );
    final encoded = _boundedString(
      json['base64'] ?? '',
      'body.base64',
      maximumLength: ((maximumInspectionBodyBytes + 2) ~/ 3) * 4,
    );
    if (text.isNotEmpty && encoded.isNotEmpty) {
      throw const FormatException('body has multiple payload encodings');
    }
    if (text.isNotEmpty && encoding != 'utf8') {
      throw const FormatException('text body encoding is invalid');
    }
    if (encoded.isNotEmpty && encoding != 'base64') {
      throw const FormatException('binary body encoding is invalid');
    }
    Uint8List? decoded;
    if (encoded.isNotEmpty) {
      try {
        decoded = base64Decode(encoded);
      } on FormatException {
        throw const FormatException('body.base64 is invalid');
      }
    }
    final capturedBytes = _boundedInt(
      json['capturedBytes'],
      'body.capturedBytes',
      minimum: 0,
      maximum: maximumInspectionBodyBytes,
    );
    final observedBytes = _boundedInt(
      json['observedBytes'],
      'body.observedBytes',
      minimum: 0,
      maximum: 1 << 53,
    );
    if (observedBytes < capturedBytes ||
        (decoded != null && decoded.length != capturedBytes)) {
      throw const FormatException('body byte counts are invalid');
    }
    final omittedReason = _boundedString(
      json['omittedReason'] ?? '',
      'body.omittedReason',
      maximumLength: 64,
    );
    if (omittedReason.isNotEmpty && capturedBytes != 0) {
      throw const FormatException('omitted body cannot retain payload bytes');
    }
    return TlsInspectionRuntimeHttpBody(
      kind: kind,
      contentType: contentType,
      contentEncoding: contentEncoding,
      encoding: encoding,
      text: text,
      base64: encoded,
      capturedBytes: capturedBytes,
      observedBytes: observedBytes,
      truncated: _boolOrFalse(json['truncated'], 'body.truncated'),
      omittedReason: omittedReason,
    );
  }

  Map<String, dynamic> toJson() => {
    'kind': kind,
    if (contentType.isNotEmpty) 'contentType': contentType,
    if (contentEncoding.isNotEmpty) 'contentEncoding': contentEncoding,
    if (encoding.isNotEmpty) 'encoding': encoding,
    if (text.isNotEmpty) 'text': text,
    if (base64.isNotEmpty) 'base64': base64,
    'capturedBytes': capturedBytes,
    'observedBytes': observedBytes,
    if (truncated) 'truncated': true,
    if (omittedReason.isNotEmpty) 'omittedReason': omittedReason,
  };
}
