import 'package:drift/native.dart';
import 'package:fl_clash/database/database.dart' as fl;
import 'package:fl_clash/enum/enum.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sqlite3/sqlite3.dart';

const _diagnosticsInsertTrigger =
    'trg_quick_routing_diagnostics_profile_insert';
const _diagnosticsDeleteTrigger =
    'trg_quick_routing_diagnostics_profile_delete';

/// Rebuilds [raw] into the shape schema version 1 left behind: no
/// `proxy_groups`, no `icon_records`, and a `rules` table that still stores the
/// whole rule in one `value` column.
///
/// Drift creates the current schema outright on a fresh database, so walking a
/// real database back to v1 and reopening it is the only way to run the real
/// `onUpgrade` against a real SQLite file.
void _downgradeToV1(Database raw) {
  _downgradeToV2(raw);
  raw.execute('DROP TABLE IF EXISTS proxy_groups');
  raw.execute('DROP TABLE IF EXISTS icon_records');
  raw.execute('DROP INDEX IF EXISTS idx_rule_target');
  raw.execute('DROP TABLE IF EXISTS rules');
  raw.execute('''
    CREATE TABLE rules (
      id INTEGER NOT NULL PRIMARY KEY,
      value TEXT NOT NULL
    )
  ''');
  raw.execute('PRAGMA user_version = 1');
}

void _dropV4Diagnostics(Database raw) {
  raw.execute('DROP TRIGGER IF EXISTS $_diagnosticsInsertTrigger');
  raw.execute('DROP TRIGGER IF EXISTS $_diagnosticsDeleteTrigger');
  raw.execute('DROP TABLE IF EXISTS quick_routing_diagnostics');
}

void _dropV5Logbook(Database raw) {
  raw.execute('DROP TABLE IF EXISTS logbook_events');
}

/// Schema version 2 had no `match_target` on `profiles` and no diagnostics.
void _downgradeToV2(Database raw) {
  _dropV5Logbook(raw);
  _dropV4Diagnostics(raw);
  raw.execute('ALTER TABLE profiles DROP COLUMN match_target');
  raw.execute('PRAGMA user_version = 2');
}

/// Schema version 3 already had `match_target`, but no diagnostics table.
void _downgradeToV3(Database raw) {
  _dropV5Logbook(raw);
  _dropV4Diagnostics(raw);
  raw.execute('PRAGMA user_version = 3');
}

void _downgradeToV4(Database raw) {
  _dropV5Logbook(raw);
  raw.execute('PRAGMA user_version = 4');
}

Set<String> _columnsOf(Database raw, String table) => {
  for (final row in raw.select('PRAGMA table_info($table)'))
    row['name'] as String,
};

bool _hasTable(Database raw, String name) => raw.select(
  "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
  [name],
).isNotEmpty;

bool _hasTrigger(Database raw, String name) => raw.select(
  "SELECT name FROM sqlite_master WHERE type='trigger' AND name=?",
  [name],
).isNotEmpty;

int _userVersion(Database raw) =>
    raw.select('PRAGMA user_version').single['user_version'] as int;

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late Database raw;

  setUp(() async {
    raw = sqlite3.openInMemory();
    final seed = fl.Database(
      NativeDatabase.opened(raw, closeUnderlyingOnClose: false),
    );
    await seed.customSelect('SELECT 1').get();
    await seed.close();
  });

  tearDown(() => raw.close());

  Future<fl.Database> openAndMigrate() async {
    final database = fl.Database(
      NativeDatabase.opened(raw, closeUnderlyingOnClose: false),
    );
    addTearDown(database.close);
    await database.customSelect('SELECT 1').get();
    return database;
  }

  test('a v1 database is left at the current schema version', () async {
    _downgradeToV1(raw);
    expect(_userVersion(raw), 1);

    await openAndMigrate();

    expect(_userVersion(raw), 5);
  });

  test('the v3 upgrade adds match_target to profiles', () async {
    _downgradeToV2(raw);
    expect(_columnsOf(raw, 'profiles'), isNot(contains('match_target')));

    await openAndMigrate();

    expect(_columnsOf(raw, 'profiles'), contains('match_target'));
    expect(_userVersion(raw), 5);
  });

  test(
    'a v2 user_version with match_target already present still opens',
    () async {
      _dropV5Logbook(raw);
      _dropV4Diagnostics(raw);
      raw.execute('PRAGMA user_version = 2');
      expect(_columnsOf(raw, 'profiles'), contains('match_target'));

      await openAndMigrate();

      expect(_columnsOf(raw, 'profiles'), contains('match_target'));
      expect(_hasTable(raw, 'quick_routing_diagnostics'), isTrue);
      expect(_userVersion(raw), 5);
    },
  );

  test('the upgrade creates the tables v2 added', () async {
    _downgradeToV1(raw);
    expect(_hasTable(raw, 'proxy_groups'), isFalse);
    expect(_hasTable(raw, 'icon_records'), isFalse);

    await openAndMigrate();

    expect(_hasTable(raw, 'proxy_groups'), isTrue);
    expect(_hasTable(raw, 'icon_records'), isTrue);
  });

  test('the v4 upgrade creates persistent diagnostics storage', () async {
    _downgradeToV3(raw);
    expect(_hasTable(raw, 'quick_routing_diagnostics'), isFalse);
    expect(_hasTrigger(raw, _diagnosticsInsertTrigger), isFalse);
    expect(_hasTrigger(raw, _diagnosticsDeleteTrigger), isFalse);

    await openAndMigrate();

    expect(_hasTable(raw, 'quick_routing_diagnostics'), isTrue);
    expect(
      _columnsOf(raw, 'quick_routing_diagnostics'),
      containsAll(<String>[
        'id',
        'profile_id',
        'fingerprint',
        'created_at',
        'checked_at',
        'status',
        'search_text',
        'payload',
      ]),
    );
    expect(_hasTrigger(raw, _diagnosticsInsertTrigger), isTrue);
    expect(_hasTrigger(raw, _diagnosticsDeleteTrigger), isTrue);
    expect(_userVersion(raw), 5);
  });

  test('the v5 upgrade creates persistent Logbook storage', () async {
    _downgradeToV4(raw);
    expect(_hasTable(raw, 'logbook_events'), isFalse);
    expect(_userVersion(raw), 4);

    await openAndMigrate();

    expect(_hasTable(raw, 'logbook_events'), isTrue);
    expect(
      _columnsOf(raw, 'logbook_events'),
      containsAll(<String>[
        'id',
        'scope_key',
        'profile_id',
        'created_at',
        'updated_at',
        'category',
        'severity',
        'event_type',
        'title',
        'message',
        'correlation_id',
        'search_text',
        'payload',
      ]),
    );
    expect(_userVersion(raw), 5);
  });

  test(
    'opening the current schema repairs missing diagnostics triggers',
    () async {
      raw.execute('DROP TRIGGER IF EXISTS $_diagnosticsInsertTrigger');
      raw.execute('DROP TRIGGER IF EXISTS $_diagnosticsDeleteTrigger');
      expect(_userVersion(raw), 5);
      expect(_hasTrigger(raw, _diagnosticsInsertTrigger), isFalse);
      expect(_hasTrigger(raw, _diagnosticsDeleteTrigger), isFalse);

      await openAndMigrate();

      expect(_hasTrigger(raw, _diagnosticsInsertTrigger), isTrue);
      expect(_hasTrigger(raw, _diagnosticsDeleteTrigger), isTrue);
      expect(_userVersion(raw), 5);
    },
  );

  test('the upgrade splits the rules value column into parsed ones', () async {
    _downgradeToV1(raw);
    expect(_columnsOf(raw, 'rules'), {'id', 'value'});

    await openAndMigrate();

    expect(
      _columnsOf(raw, 'rules'),
      containsAll(<String>[
        'rule_action',
        'content',
        'rule_target',
        'rule_provider',
        'sub_rule',
        'no_resolve',
        'src',
      ]),
    );
    expect(_columnsOf(raw, 'rules'), isNot(contains('value')));
  });

  test('every v1 rule row is parsed into the new columns', () async {
    _downgradeToV1(raw);
    raw.execute(
      'INSERT INTO rules (id, value) '
      "VALUES (1, 'DOMAIN-SUFFIX,example.com,DIRECT')",
    );
    raw.execute(
      'INSERT INTO rules (id, value) '
      "VALUES (2, 'IP-CIDR,10.0.0.0/8,REJECT,no-resolve')",
    );

    final database = await openAndMigrate();
    final rows = await database
        .customSelect(
          'SELECT id, rule_action, content, rule_target, no_resolve '
          'FROM rules ORDER BY id',
        )
        .get();

    expect(rows, hasLength(2));
    expect(rows[0].read<String>('rule_action'), RuleAction.DOMAIN_SUFFIX.name);
    expect(rows[0].read<String>('content'), 'example.com');
    expect(rows[0].read<String>('rule_target'), 'DIRECT');
    expect(rows[0].read<int>('no_resolve'), 0);
    expect(rows[1].read<String>('rule_action'), RuleAction.IP_CIDR.name);
    expect(rows[1].read<String>('content'), '10.0.0.0/8');
    expect(rows[1].read<String>('rule_target'), 'REJECT');
    expect(
      rows[1].read<int>('no_resolve'),
      1,
      reason: 'the no-resolve modifier has to survive the column split',
    );
  });

  test('an empty v1 rules table still reaches the current schema', () async {
    _downgradeToV1(raw);

    final database = await openAndMigrate();

    expect(_userVersion(raw), 5);
    expect(await database.customSelect('SELECT * FROM rules').get(), isEmpty);
  });

  test(
    'opening a database already at the current version changes nothing',
    () async {
      final before = _columnsOf(raw, 'rules');

      await openAndMigrate();

      expect(_columnsOf(raw, 'rules'), before);
      expect(_userVersion(raw), 5);
      expect(_hasTable(raw, 'proxy_groups'), isTrue);
      expect(_hasTable(raw, 'quick_routing_diagnostics'), isTrue);
      expect(_hasTable(raw, 'logbook_events'), isTrue);
      expect(_hasTrigger(raw, _diagnosticsInsertTrigger), isTrue);
      expect(_hasTrigger(raw, _diagnosticsDeleteTrigger), isTrue);
    },
  );
}
