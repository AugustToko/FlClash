part of 'database.dart';

const _logbookEventsTable = 'logbook_events';
const _logbookScopeTimeIndex = 'idx_logbook_scope_updated';
const _logbookCategoryTimeIndex = 'idx_logbook_category_updated';
const _logbookCorrelationIndex = 'idx_logbook_correlation';

Future<void> _createLogbookSchema(Database database) async {
  await database.customStatement('''
    CREATE TABLE IF NOT EXISTS $_logbookEventsTable (
      id INTEGER NOT NULL PRIMARY KEY,
      scope_key TEXT NOT NULL,
      profile_id INTEGER,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      category TEXT NOT NULL,
      severity TEXT NOT NULL,
      event_type TEXT NOT NULL,
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      correlation_id TEXT,
      search_text TEXT NOT NULL,
      payload TEXT NOT NULL
    )
  ''');
  await database.customStatement('''
    CREATE INDEX IF NOT EXISTS $_logbookScopeTimeIndex
    ON $_logbookEventsTable(scope_key, updated_at DESC, id DESC)
  ''');
  await database.customStatement('''
    CREATE INDEX IF NOT EXISTS $_logbookCategoryTimeIndex
    ON $_logbookEventsTable(category, updated_at DESC, id DESC)
  ''');
  await database.customStatement('''
    CREATE UNIQUE INDEX IF NOT EXISTS $_logbookCorrelationIndex
    ON $_logbookEventsTable(
      scope_key,
      category,
      event_type,
      correlation_id
    )
    WHERE correlation_id IS NOT NULL
  ''');
}

LogbookEvent _logbookEventFromRow(QueryRow row) {
  final payload = LogbookEvent.decodePayload(row.read<String>('payload'));
  return payload.copyWith(
    id: row.read<int>('id'),
    profileId: row.readNullable<int>('profile_id'),
    clearProfileId: row.readNullable<int>('profile_id') == null,
    createdAt: DateTime.fromMillisecondsSinceEpoch(
      row.read<int>('created_at'),
      isUtc: true,
    ),
    updatedAt: DateTime.fromMillisecondsSinceEpoch(
      row.read<int>('updated_at'),
      isUtc: true,
    ),
  );
}

extension LogbookDatabaseExt on Database {
  Future<List<LogbookEvent>> loadLogbookEvents({
    int limit = 500,
    int? profileId,
    bool includeGlobal = true,
  }) async {
    if (limit <= 0) {
      return const [];
    }
    final where = <String>[];
    final variables = <Variable<Object>>[];
    if (profileId != null) {
      if (includeGlobal) {
        where.add('(profile_id = ? OR profile_id IS NULL)');
      } else {
        where.add('profile_id = ?');
      }
      variables.add(Variable.withInt(profileId));
    } else if (!includeGlobal) {
      where.add('profile_id IS NOT NULL');
    }
    variables.add(Variable.withInt(limit));
    final rows = await customSelect('''
        SELECT
          id,
          profile_id,
          created_at,
          updated_at,
          payload
        FROM $_logbookEventsTable
        ${where.isEmpty ? '' : 'WHERE ${where.join(' AND ')}'}
        ORDER BY updated_at DESC, id DESC
        LIMIT ?
      ''', variables: variables).get();
    final result = <LogbookEvent>[];
    for (final row in rows) {
      try {
        result.add(_logbookEventFromRow(row));
      } catch (error, stackTrace) {
        commonPrint.log(
          'logbook event decode failed: ${compactError(error)}, $stackTrace',
          logLevel: LogLevel.warning,
        );
      }
    }
    return List.unmodifiable(result);
  }

  Future<LogbookEvent> upsertLogbookEvent(
    LogbookEvent event, {
    int maxEntriesPerScope = 500,
  }) async {
    if (maxEntriesPerScope <= 0) {
      throw ArgumentError.value(maxEntriesPerScope, 'maxEntriesPerScope');
    }
    late int canonicalId;
    late DateTime canonicalCreatedAt;
    await transaction(() async {
      QueryRow? existing;
      if (event.correlationId.isNotEmpty) {
        existing = await customSelect(
          '''
            SELECT id, created_at
            FROM $_logbookEventsTable
            WHERE scope_key = ?
              AND category = ?
              AND event_type = ?
              AND correlation_id = ?
            LIMIT 1
          ''',
          variables: [
            Variable.withString(event.scopeKey),
            Variable.withString(event.category.name),
            Variable.withString(event.eventType),
            Variable.withString(event.correlationId),
          ],
        ).getSingleOrNull();
      }
      canonicalId = existing?.read<int>('id') ?? event.id;
      canonicalCreatedAt = existing == null
          ? event.createdAt
          : DateTime.fromMillisecondsSinceEpoch(
              existing.read<int>('created_at'),
              isUtc: true,
            );
      final canonical = event.copyWith(
        id: canonicalId,
        createdAt: canonicalCreatedAt,
      );
      await customStatement(
        '''
          INSERT INTO $_logbookEventsTable (
            id,
            scope_key,
            profile_id,
            created_at,
            updated_at,
            category,
            severity,
            event_type,
            title,
            message,
            correlation_id,
            search_text,
            payload
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET
            scope_key = excluded.scope_key,
            profile_id = excluded.profile_id,
            updated_at = excluded.updated_at,
            category = excluded.category,
            severity = excluded.severity,
            event_type = excluded.event_type,
            title = excluded.title,
            message = excluded.message,
            correlation_id = excluded.correlation_id,
            search_text = excluded.search_text,
            payload = excluded.payload
        ''',
        [
          canonical.id,
          canonical.scopeKey,
          canonical.profileId,
          canonical.createdAt.millisecondsSinceEpoch,
          canonical.updatedAt.millisecondsSinceEpoch,
          canonical.category.name,
          canonical.severity.name,
          canonical.eventType,
          canonical.title,
          canonical.message,
          canonical.correlationId.isEmpty ? null : canonical.correlationId,
          canonical.searchText,
          canonical.encodePayload(),
        ],
      );
      await customStatement(
        '''
          DELETE FROM $_logbookEventsTable
          WHERE scope_key = ?
            AND id NOT IN (
              SELECT id
              FROM $_logbookEventsTable
              WHERE scope_key = ?
              ORDER BY updated_at DESC, id DESC
              LIMIT ?
            )
        ''',
        [event.scopeKey, event.scopeKey, maxEntriesPerScope],
      );
    });

    final row = await customSelect(
      '''
        SELECT id, profile_id, created_at, updated_at, payload
        FROM $_logbookEventsTable
        WHERE id = ?
        LIMIT 1
      ''',
      variables: [Variable.withInt(canonicalId)],
    ).getSingleOrNull();
    if (row == null) {
      throw StateError('Logbook event disappeared after upsert');
    }
    return _logbookEventFromRow(row);
  }

  Future<void> deleteLogbookEvent(int id) {
    return customStatement('DELETE FROM $_logbookEventsTable WHERE id = ?', [
      id,
    ]);
  }

  Future<void> clearLogbook({int? profileId, bool includeGlobal = false}) {
    if (profileId == null) {
      return customStatement('DELETE FROM $_logbookEventsTable');
    }
    if (includeGlobal) {
      return customStatement(
        'DELETE FROM $_logbookEventsTable '
        'WHERE profile_id = ? OR profile_id IS NULL',
        [profileId],
      );
    }
    return customStatement(
      'DELETE FROM $_logbookEventsTable WHERE profile_id = ?',
      [profileId],
    );
  }

  Future<int> countLogbookEvents({int? profileId}) async {
    final row = await customSelect(
      '''
        SELECT COUNT(*) AS count
        FROM $_logbookEventsTable
        ${profileId == null ? '' : 'WHERE profile_id = ?'}
      ''',
      variables: profileId == null ? const [] : [Variable.withInt(profileId)],
    ).getSingle();
    return row.read<int>('count');
  }
}
