part of 'database.dart';

const _httpCaptureTable = 'http_capture_entries';
const _httpCaptureScopeTimeIndex = 'idx_http_capture_scope_observed';
const _httpCaptureProtocolTimeIndex = 'idx_http_capture_protocol_observed';
const _httpCaptureProfileInsertTrigger = 'trg_http_capture_profile_insert';
const _httpCaptureProfileDeleteTrigger = 'trg_http_capture_profile_delete';

Future<void> _createHttpCaptureSchema(Database database) async {
  await database.customStatement('''
    CREATE TABLE IF NOT EXISTS $_httpCaptureTable (
      id INTEGER NOT NULL PRIMARY KEY,
      connection_id TEXT NOT NULL,
      session_id TEXT NOT NULL,
      scope_key TEXT NOT NULL,
      profile_id INTEGER,
      started_at INTEGER NOT NULL,
      observed_at INTEGER NOT NULL,
      protocol TEXT NOT NULL,
      search_text TEXT NOT NULL,
      payload TEXT NOT NULL,
      UNIQUE(scope_key, session_id, connection_id),
      FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE CASCADE
    )
  ''');
  await database.customStatement('''
    CREATE INDEX IF NOT EXISTS $_httpCaptureScopeTimeIndex
    ON $_httpCaptureTable(scope_key, observed_at DESC, id DESC)
  ''');
  await database.customStatement('''
    CREATE INDEX IF NOT EXISTS $_httpCaptureProtocolTimeIndex
    ON $_httpCaptureTable(protocol, observed_at DESC, id DESC)
  ''');
  await database.customStatement('''
    CREATE TRIGGER IF NOT EXISTS $_httpCaptureProfileInsertTrigger
    BEFORE INSERT ON $_httpCaptureTable
    WHEN NEW.profile_id IS NOT NULL
      AND NOT EXISTS (
        SELECT 1 FROM profiles WHERE id = NEW.profile_id
      )
    BEGIN
      SELECT RAISE(ABORT, 'HTTP capture profile does not exist');
    END;
  ''');
  await database.customStatement('''
    CREATE TRIGGER IF NOT EXISTS $_httpCaptureProfileDeleteTrigger
    AFTER DELETE ON profiles
    BEGIN
      DELETE FROM $_httpCaptureTable
      WHERE profile_id = OLD.id;
    END;
  ''');
}

HttpCaptureEntry _httpCaptureEntryFromRow(QueryRow row) {
  final payload = HttpCaptureEntry.decodePayload(row.read<String>('payload'));
  return payload.copyWith(
    id: row.read<int>('id'),
    profileId: row.readNullable<int>('profile_id'),
    clearProfileId: row.readNullable<int>('profile_id') == null,
    startedAt: DateTime.fromMillisecondsSinceEpoch(
      row.read<int>('started_at'),
      isUtc: true,
    ),
    observedAt: DateTime.fromMillisecondsSinceEpoch(
      row.read<int>('observed_at'),
      isUtc: true,
    ),
  );
}

extension HttpCaptureDatabaseExt on Database {
  Future<List<HttpCaptureEntry>> loadHttpCaptureEntries({
    int limit = 1000,
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
        SELECT id, profile_id, started_at, observed_at, payload
        FROM $_httpCaptureTable
        ${where.isEmpty ? '' : 'WHERE ${where.join(' AND ')}'}
        ORDER BY observed_at DESC, id DESC
        LIMIT ?
      ''', variables: variables).get();
    final result = <HttpCaptureEntry>[];
    for (final row in rows) {
      try {
        result.add(_httpCaptureEntryFromRow(row));
      } catch (error, stackTrace) {
        commonPrint.log(
          'HTTP capture decode failed: ${compactError(error)}, $stackTrace',
          logLevel: LogLevel.warning,
        );
      }
    }
    return List.unmodifiable(result);
  }

  Future<HttpCaptureEntry> upsertHttpCaptureEntry(
    HttpCaptureEntry entry, {
    int maxEntriesPerScope = 1000,
  }) async {
    if (maxEntriesPerScope <= 0) {
      throw ArgumentError.value(maxEntriesPerScope, 'maxEntriesPerScope');
    }
    late int canonicalId;
    await transaction(() async {
      final existing = await customSelect(
        '''
          SELECT id
          FROM $_httpCaptureTable
          WHERE scope_key = ? AND session_id = ? AND connection_id = ?
          LIMIT 1
        ''',
        variables: [
          Variable.withString(entry.scopeKey),
          Variable.withString(entry.sessionId),
          Variable.withString(entry.connectionId),
        ],
      ).getSingleOrNull();
      canonicalId = existing?.read<int>('id') ?? entry.id;
      final canonical = entry.copyWith(id: canonicalId);
      await customStatement(
        '''
          INSERT INTO $_httpCaptureTable (
            id,
            connection_id,
            session_id,
            scope_key,
            profile_id,
            started_at,
            observed_at,
            protocol,
            search_text,
            payload
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(scope_key, session_id, connection_id) DO UPDATE SET
            observed_at = excluded.observed_at,
            protocol = excluded.protocol,
            search_text = excluded.search_text,
            payload = excluded.payload
        ''',
        [
          canonical.id,
          canonical.connectionId,
          canonical.sessionId,
          canonical.scopeKey,
          canonical.profileId,
          canonical.startedAt.millisecondsSinceEpoch,
          canonical.observedAt.millisecondsSinceEpoch,
          canonical.protocol.name,
          canonical.searchText,
          canonical.encodePayload(),
        ],
      );
      await customStatement(
        '''
          DELETE FROM $_httpCaptureTable
          WHERE scope_key = ?
            AND id NOT IN (
              SELECT id
              FROM $_httpCaptureTable
              WHERE scope_key = ?
              ORDER BY observed_at DESC, id DESC
              LIMIT ?
            )
        ''',
        [entry.scopeKey, entry.scopeKey, maxEntriesPerScope],
      );
    });

    final row = await customSelect(
      '''
        SELECT id, profile_id, started_at, observed_at, payload
        FROM $_httpCaptureTable
        WHERE id = ?
        LIMIT 1
      ''',
      variables: [Variable.withInt(canonicalId)],
    ).getSingleOrNull();
    if (row == null) {
      throw StateError('HTTP capture entry disappeared after upsert');
    }
    return _httpCaptureEntryFromRow(row);
  }

  Future<void> deleteHttpCaptureEntry(int id) {
    return customStatement('DELETE FROM $_httpCaptureTable WHERE id = ?', [id]);
  }

  Future<void> deleteHttpCaptureEntryByIdentity({
    required String scopeKey,
    required String sessionId,
    required String connectionId,
  }) {
    return customStatement(
      'DELETE FROM $_httpCaptureTable '
      'WHERE scope_key = ? AND session_id = ? AND connection_id = ?',
      [scopeKey, sessionId, connectionId],
    );
  }

  Future<void> clearHttpCaptureEntries({
    int? profileId,
    bool includeGlobal = false,
  }) {
    if (profileId == null) {
      return customStatement('DELETE FROM $_httpCaptureTable');
    }
    if (includeGlobal) {
      return customStatement(
        'DELETE FROM $_httpCaptureTable '
        'WHERE profile_id = ? OR profile_id IS NULL',
        [profileId],
      );
    }
    return customStatement(
      'DELETE FROM $_httpCaptureTable WHERE profile_id = ?',
      [profileId],
    );
  }

  Future<int> countHttpCaptureEntries({int? profileId}) async {
    final row = await customSelect(
      '''
        SELECT COUNT(*) AS count
        FROM $_httpCaptureTable
        ${profileId == null ? '' : 'WHERE profile_id = ?'}
      ''',
      variables: profileId == null ? const [] : [Variable.withInt(profileId)],
    ).getSingle();
    return row.read<int>('count');
  }
}
