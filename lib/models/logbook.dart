import 'dart:convert';

import 'package:flutter/foundation.dart';

enum LogbookEventKind {
  app,
  core,
  log,
  request,
  profile,
  network,
  provider,
  geo,
  quickRouting,
}

enum LogbookSeverity {
  debug,
  info,
  warning,
  error,
}

LogbookEventKind logbookEventKindFromName(String value) {
  return LogbookEventKind.values.firstWhere(
    (item) => item.name == value,
    orElse: () => LogbookEventKind.app,
  );
}

LogbookSeverity logbookSeverityFromName(String value) {
  return LogbookSeverity.values.firstWhere(
    (item) => item.name == value,
    orElse: () => LogbookSeverity.info,
  );
}

@immutable
class LogbookRetentionPolicy {
  final Duration maxAge;
  final int maxEvents;

  const LogbookRetentionPolicy({
    this.maxAge = const Duration(days: 7),
    this.maxEvents = 50000,
  }) : assert(maxEvents > 0);
}

@immutable
class LogbookEventDraft {
  final int? profileId;
  final DateTime occurredAt;
  final LogbookEventKind kind;
  final LogbookSeverity severity;
  final String title;
  final String message;
  final String? correlationId;
  final String? host;
  final String? process;
  final String? ruleText;
  final String? policyText;
  final Map<String, Object?> payload;

  const LogbookEventDraft({
    this.profileId,
    required this.occurredAt,
    required this.kind,
    this.severity = LogbookSeverity.info,
    this.title = '',
    this.message = '',
    this.correlationId,
    this.host,
    this.process,
    this.ruleText,
    this.policyText,
    this.payload = const {},
  });

  LogbookEventDraft copyWith({
    int? profileId,
    bool clearProfileId = false,
    DateTime? occurredAt,
    LogbookEventKind? kind,
    LogbookSeverity? severity,
    String? title,
    String? message,
    String? correlationId,
    String? host,
    String? process,
    String? ruleText,
    String? policyText,
    Map<String, Object?>? payload,
  }) {
    return LogbookEventDraft(
      profileId: clearProfileId ? null : profileId ?? this.profileId,
      occurredAt: occurredAt ?? this.occurredAt,
      kind: kind ?? this.kind,
      severity: severity ?? this.severity,
      title: title ?? this.title,
      message: message ?? this.message,
      correlationId: correlationId ?? this.correlationId,
      host: host ?? this.host,
      process: process ?? this.process,
      ruleText: ruleText ?? this.ruleText,
      policyText: policyText ?? this.policyText,
      payload: payload ?? this.payload,
    );
  }

  String get searchText {
    final values = <String>[
      kind.name,
      severity.name,
      title,
      message,
      correlationId ?? '',
      host ?? '',
      process ?? '',
      ruleText ?? '',
      policyText ?? '',
      if (payload.isNotEmpty) _safeJsonEncode(payload),
    ];
    return values
        .where((value) => value.trim().isNotEmpty)
        .join('\n')
        .toLowerCase();
  }
}

@immutable
class LogbookEvent {
  final int id;
  final int sessionId;
  final int? profileId;
  final DateTime occurredAt;
  final LogbookEventKind kind;
  final LogbookSeverity severity;
  final String title;
  final String message;
  final String? correlationId;
  final String? host;
  final String? process;
  final String? ruleText;
  final String? policyText;
  final Map<String, Object?> payload;

  const LogbookEvent({
    required this.id,
    required this.sessionId,
    required this.profileId,
    required this.occurredAt,
    required this.kind,
    required this.severity,
    required this.title,
    required this.message,
    required this.correlationId,
    required this.host,
    required this.process,
    required this.ruleText,
    required this.policyText,
    required this.payload,
  });
}

@immutable
class LogbookQuery {
  final int? profileId;
  final Set<LogbookEventKind> kinds;
  final Set<LogbookSeverity> severities;
  final String search;
  final int limit;
  final int offset;

  const LogbookQuery({
    this.profileId,
    this.kinds = const {},
    this.severities = const {},
    this.search = '',
    this.limit = 100,
    this.offset = 0,
  }) : assert(limit > 0),
       assert(offset >= 0);

  LogbookQuery copyWith({
    int? profileId,
    bool clearProfileId = false,
    Set<LogbookEventKind>? kinds,
    Set<LogbookSeverity>? severities,
    String? search,
    int? limit,
    int? offset,
  }) {
    return LogbookQuery(
      profileId: clearProfileId ? null : profileId ?? this.profileId,
      kinds: kinds ?? this.kinds,
      severities: severities ?? this.severities,
      search: search ?? this.search,
      limit: limit ?? this.limit,
      offset: offset ?? this.offset,
    );
  }
}

@immutable
class LogbookStats {
  final int total;
  final Map<LogbookEventKind, int> byKind;
  final Map<LogbookSeverity, int> bySeverity;

  const LogbookStats({
    required this.total,
    required this.byKind,
    required this.bySeverity,
  });
}

String _safeJsonEncode(Object? value) {
  try {
    return jsonEncode(value);
  } on Object {
    return jsonEncode({'value': '$value'});
  }
}
