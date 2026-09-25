import 'dart:convert';

import 'package:flutter/foundation.dart';

enum LogbookCategory {
  core,
  profile,
  routing,
  network,
  provider,
  dns,
  script,
  system,
}

enum LogbookSeverity { info, success, warning, error }

@immutable
class LogbookEvent {
  final int id;
  final int? profileId;
  final DateTime createdAt;
  final DateTime updatedAt;
  final LogbookCategory category;
  final LogbookSeverity severity;
  final String eventType;
  final String title;
  final String message;
  final String correlationId;
  final Map<String, Object?> details;

  const LogbookEvent({
    required this.id,
    required this.profileId,
    required this.createdAt,
    required this.updatedAt,
    required this.category,
    required this.severity,
    required this.eventType,
    required this.title,
    required this.message,
    this.correlationId = '',
    this.details = const {},
  });

  String get scopeKey => profileId == null ? 'global' : 'profile:$profileId';

  String get identity => correlationId.isEmpty
      ? '$scopeKey:${category.name}:$eventType:$id'
      : '$scopeKey:${category.name}:$eventType:$correlationId';

  String get searchText {
    final detailText = details.entries
        .map((entry) => '${entry.key}=${entry.value}')
        .join('\n');
    return [
      category.name,
      severity.name,
      eventType,
      title,
      message,
      correlationId,
      detailText,
    ].where((value) => value.trim().isNotEmpty).join('\n').toLowerCase();
  }

  LogbookEvent copyWith({
    int? id,
    int? profileId,
    bool clearProfileId = false,
    DateTime? createdAt,
    DateTime? updatedAt,
    LogbookCategory? category,
    LogbookSeverity? severity,
    String? eventType,
    String? title,
    String? message,
    String? correlationId,
    Map<String, Object?>? details,
  }) {
    return LogbookEvent(
      id: id ?? this.id,
      profileId: clearProfileId ? null : (profileId ?? this.profileId),
      createdAt: createdAt ?? this.createdAt,
      updatedAt: updatedAt ?? this.updatedAt,
      category: category ?? this.category,
      severity: severity ?? this.severity,
      eventType: eventType ?? this.eventType,
      title: title ?? this.title,
      message: message ?? this.message,
      correlationId: correlationId ?? this.correlationId,
      details: details ?? this.details,
    );
  }

  Map<String, Object?> toJson() {
    return {
      'id': id,
      'profileId': profileId,
      'createdAt': createdAt.toIso8601String(),
      'updatedAt': updatedAt.toIso8601String(),
      'category': category.name,
      'severity': severity.name,
      'eventType': eventType,
      'title': title,
      'message': message,
      'correlationId': correlationId,
      'details': details,
    };
  }

  factory LogbookEvent.fromJson(Map<String, Object?> json) {
    final categoryName = json['category'] as String? ?? '';
    final severityName = json['severity'] as String? ?? '';
    final rawDetails = json['details'];
    return LogbookEvent(
      id: (json['id'] as num?)?.toInt() ?? -1,
      profileId: (json['profileId'] as num?)?.toInt(),
      createdAt:
          DateTime.tryParse(json['createdAt'] as String? ?? '') ??
          DateTime.fromMillisecondsSinceEpoch(0),
      updatedAt:
          DateTime.tryParse(json['updatedAt'] as String? ?? '') ??
          DateTime.fromMillisecondsSinceEpoch(0),
      category: LogbookCategory.values.firstWhere(
        (value) => value.name == categoryName,
        orElse: () => LogbookCategory.system,
      ),
      severity: LogbookSeverity.values.firstWhere(
        (value) => value.name == severityName,
        orElse: () => LogbookSeverity.info,
      ),
      eventType: json['eventType'] as String? ?? '',
      title: json['title'] as String? ?? '',
      message: json['message'] as String? ?? '',
      correlationId: json['correlationId'] as String? ?? '',
      details: rawDetails is Map<Object?, Object?>
          ? Map<String, Object?>.unmodifiable(
              Map<String, Object?>.from(rawDetails),
            )
          : const {},
    );
  }

  String encodePayload() => jsonEncode(toJson());

  factory LogbookEvent.decodePayload(String value) {
    final decoded = jsonDecode(value);
    if (decoded is! Map<Object?, Object?>) {
      throw const FormatException('Invalid logbook event payload');
    }
    return LogbookEvent.fromJson(Map<String, Object?>.from(decoded));
  }
}

const logbookExportFormat = 'flclash-logbook';
const logbookExportVersion = 1;

Map<String, Object?> buildLogbookExportPayload({
  required Iterable<LogbookEvent> events,
  DateTime? exportedAt,
}) {
  final ordered = events.toList(growable: false)
    ..sort((first, second) {
      final updated = second.updatedAt.compareTo(first.updatedAt);
      return updated != 0 ? updated : second.id.compareTo(first.id);
    });
  return {
    'format': logbookExportFormat,
    'version': logbookExportVersion,
    'exportedAt': (exportedAt ?? DateTime.now()).toUtc().toIso8601String(),
    'count': ordered.length,
    'events': ordered.map((event) => event.toJson()).toList(growable: false),
  };
}

String encodeLogbookExport({
  required Iterable<LogbookEvent> events,
  DateTime? exportedAt,
}) {
  return const JsonEncoder.withIndent(
    '  ',
  ).convert(buildLogbookExportPayload(events: events, exportedAt: exportedAt));
}
