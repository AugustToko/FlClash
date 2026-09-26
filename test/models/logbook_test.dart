import 'dart:convert';

import 'package:fl_clash/models/models.dart';
import 'package:flutter_test/flutter_test.dart';

LogbookEvent _event({
  required int id,
  required DateTime updatedAt,
  required String message,
}) {
  return LogbookEvent(
    id: id,
    profileId: 7,
    createdAt: updatedAt.subtract(const Duration(minutes: 1)),
    updatedAt: updatedAt,
    category: LogbookCategory.provider,
    severity: LogbookSeverity.success,
    eventType: 'provider.external.update',
    title: 'provider.external.update',
    message: message,
    correlationId: 'provider:$id',
    details: {'status': 'completed', 'count': id * 10},
  );
}

void main() {
  test('logbook export is versioned, ordered, and deterministic', () {
    final exportedAt = DateTime.utc(2026, 9, 25, 7, 30);
    final older = _event(
      id: 1,
      updatedAt: DateTime.utc(2026, 9, 25, 7, 20),
      message: 'older',
    );
    final newer = _event(
      id: 2,
      updatedAt: DateTime.utc(2026, 9, 25, 7, 25),
      message: 'newer',
    );

    final encoded = encodeLogbookExport(
      events: [older, newer],
      exportedAt: exportedAt,
    );
    final decoded = jsonDecode(encoded) as Map<String, dynamic>;
    final events = decoded['events'] as List<dynamic>;

    expect(decoded['format'], logbookExportFormat);
    expect(decoded['version'], logbookExportVersion);
    expect(decoded['exportedAt'], exportedAt.toIso8601String());
    expect(decoded['count'], 2);
    expect((events.first as Map<String, dynamic>)['id'], newer.id);
    expect((events.last as Map<String, dynamic>)['id'], older.id);
    expect((events.first as Map<String, dynamic>)['details'], {
      'status': 'completed',
      'count': 20,
    });
  });

  test('empty logbook export remains a valid portable document', () {
    final payload = buildLogbookExportPayload(
      events: const [],
      exportedAt: DateTime.utc(2026, 9, 25),
    );

    expect(payload['count'], 0);
    expect(payload['events'], isEmpty);
    expect(payload.keys, {
      'format',
      'version',
      'exportedAt',
      'count',
      'events',
    });
  });
}
