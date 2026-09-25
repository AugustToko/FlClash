part of 'database.dart';

const _quickRoutingDiagnosticsTable = 'quick_routing_diagnostics';
const _quickRoutingDiagnosticsProfileIndex =
    'idx_quick_routing_diagnostics_profile_checked';
const _quickRoutingDiagnosticsStatusIndex =
    'idx_quick_routing_diagnostics_profile_status';
const _quickRoutingDiagnosticsProfileInsertTrigger =
    'trg_quick_routing_diagnostics_profile_insert';
const _quickRoutingDiagnosticsProfileDeleteTrigger =
    'trg_quick_routing_diagnostics_profile_delete';

class QuickRoutingDiagnosticSnapshot {
  final int id;
  final int profileId;
  final String fingerprint;
  final DateTime createdAt;
  final DateTime checkedAt;
  final String status;
  final String searchText;
  final String payload;

  const QuickRoutingDiagnosticSnapshot({
    required this.id,
    required this.profileId,
    required this.fingerprint,
    required this.createdAt,
    required this.checkedAt,
    required this.status,
    required this.searchText,
    required this.payload,
  });

  factory QuickRoutingDiagnosticSnapshot.fromRow(QueryRow row) {
    return QuickRoutingDiagnosticSnapshot(
      id: row.read<int>('id'),
      profileId: row.read<int>('profile_id'),
      fingerprint: row.read<String>('fingerprint'),
      createdAt: DateTime.fromMillisecondsSinceEpoch(
        row.read<int>('created_at'),
      ),
      checkedAt: DateTime.fromMillisecondsSinceEpoch(
        row.read<int>('checked_at'),
      ),
      status: row.read<String>('status'),
      searchText: row.read<String>('search_text'),
      payload: row.read<String>('payload'),
    );
  }
}

Future<void> _createQuickRoutingDiagnosticsSchema(Database database) async {
  await database.customStatement('''
    CREATE TABLE IF NOT EXISTS $_quickRoutingDiagnosticsTable (
      id INTEGER NOT NULL PRIMARY KEY,
      profile_id INTEGER NOT NULL,
      fingerprint TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      checked_at INTEGER NOT NULL,
      status TEXT NOT NULL,
      search_text TEXT NOT NULL,
      payload TEXT NOT NULL,
      UNIQUE(profile_id, fingerprint),
      FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE CASCADE
    )
  ''');
  await database.customStatement('''
    CREATE INDEX IF NOT EXISTS $_quickRoutingDiagnosticsProfileIndex
    ON $_quickRoutingDiagnosticsTable(profile_id, checked_at DESC, id DESC)
  ''');
  await database.customStatement('''
    CREATE INDEX IF NOT EXISTS $_quickRoutingDiagnosticsStatusIndex
    ON $_quickRoutingDiagnosticsTable(profile_id, status, checked_at DESC)
  ''');
  // SQLite foreign-key enforcement is connection scoped. The triggers keep
  // this custom table consistent even if a legacy connection has it disabled.
  await database.customStatement('''
    CREATE TRIGGER IF NOT EXISTS $_quickRoutingDiagnosticsProfileInsertTrigger
    BEFORE INSERT ON $_quickRoutingDiagnosticsTable
    WHEN NOT EXISTS (
      SELECT 1 FROM profiles WHERE id = NEW.profile_id
    )
    BEGIN
      SELECT RAISE(ABORT, 'quick routing diagnostic profile does not exist');
    END
  ''');
  await database.customStatement('''
    CREATE TRIGGER IF NOT EXISTS $_quickRoutingDiagnosticsProfileDeleteTrigger
    AFTER DELETE ON profiles
    BEGIN
      DELETE FROM $_quickRoutingDiagnosticsTable
      WHERE profile_id = OLD.id;
    END
  ''');
}

extension QuickRoutingDiagnosticsDatabaseExt on Database {
  Future<List<QuickRoutingDiagnosticSnapshot>> loadQuickRoutingDiagnostics({
    required int profileId,
    int limit = 100,
  }) async {
    if (limit <= 0) {
      return const [];
    }
    final rows = await customSelect(
      '''
        SELECT
          id,
          profile_id,
          fingerprint,
          created_at,
          checked_at,
          status,
          search_text,
          payload
        FROM $_quickRoutingDiagnosticsTable
        WHERE profile_id = ?
        ORDER BY checked_at DESC, id DESC
        LIMIT ?
      ''',
      variables: [Variable.withInt(profileId), Variable.withInt(limit)],
    ).get();
    return List.unmodifiable(rows.map(QuickRoutingDiagnosticSnapshot.fromRow));
  }

  Future<QuickRoutingDiagnosticSnapshot> upsertQuickRoutingDiagnostic(
    QuickRoutingDiagnosticSnapshot snapshot, {
    int maxEntries = 100,
  }) async {
    if (maxEntries <= 0) {
      throw ArgumentError.value(maxEntries, 'maxEntries');
    }
    await transaction(() async {
      await customStatement(
        '''
          INSERT INTO $_quickRoutingDiagnosticsTable (
            id,
            profile_id,
            fingerprint,
            created_at,
            checked_at,
            status,
            search_text,
            payload
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(profile_id, fingerprint) DO UPDATE SET
            checked_at = excluded.checked_at,
            status = excluded.status,
            search_text = excluded.search_text,
            payload = excluded.payload
        ''',
        [
          snapshot.id,
          snapshot.profileId,
          snapshot.fingerprint,
          snapshot.createdAt.millisecondsSinceEpoch,
          snapshot.checkedAt.millisecondsSinceEpoch,
          snapshot.status,
          snapshot.searchText,
          snapshot.payload,
        ],
      );
      await customStatement(
        '''
          DELETE FROM $_quickRoutingDiagnosticsTable
          WHERE profile_id = ?
            AND id NOT IN (
              SELECT id
              FROM $_quickRoutingDiagnosticsTable
              WHERE profile_id = ?
              ORDER BY checked_at DESC, id DESC
              LIMIT ?
            )
        ''',
        [snapshot.profileId, snapshot.profileId, maxEntries],
      );
    });

    final row = await customSelect(
      '''
        SELECT
          id,
          profile_id,
          fingerprint,
          created_at,
          checked_at,
          status,
          search_text,
          payload
        FROM $_quickRoutingDiagnosticsTable
        WHERE profile_id = ? AND fingerprint = ?
        LIMIT 1
      ''',
      variables: [
        Variable.withInt(snapshot.profileId),
        Variable.withString(snapshot.fingerprint),
      ],
    ).getSingleOrNull();
    if (row == null) {
      throw StateError('Quick routing diagnostic disappeared after upsert');
    }
    return QuickRoutingDiagnosticSnapshot.fromRow(row);
  }

  Future<void> deleteQuickRoutingDiagnostic(int id) {
    return customStatement(
      'DELETE FROM $_quickRoutingDiagnosticsTable WHERE id = ?',
      [id],
    );
  }

  Future<void> clearQuickRoutingDiagnostics(int profileId) {
    return customStatement(
      'DELETE FROM $_quickRoutingDiagnosticsTable WHERE profile_id = ?',
      [profileId],
    );
  }

  Future<int> countQuickRoutingDiagnostics(int profileId) async {
    final row = await customSelect(
      '''
        SELECT COUNT(*) AS count
        FROM $_quickRoutingDiagnosticsTable
        WHERE profile_id = ?
      ''',
      variables: [Variable.withInt(profileId)],
    ).getSingle();
    return row.read<int>('count');
  }
}
