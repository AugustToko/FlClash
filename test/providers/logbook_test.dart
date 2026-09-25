import 'package:drift/native.dart';
import 'package:fl_clash/database/database.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/logbook.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  late Database originalDatabase;
  late Database testDatabase;
  late ProviderContainer container;

  setUp(() async {
    originalDatabase = database;
    testDatabase = Database(NativeDatabase.memory());
    database = testDatabase;
    container = ProviderContainer(
      overrides: [logbookPersistenceEnabledProvider.overrideWithValue(true)],
    );
    await container.read(logbookProvider.notifier).reload();
  });

  tearDown(() async {
    container.dispose();
    database = originalDatabase;
    await testDatabase.close();
  });

  test('record publishes immediately and persists the event', () async {
    final event = await container
        .read(logbookProvider.notifier)
        .record(
          profileId: 3,
          category: LogbookCategory.core,
          severity: LogbookSeverity.success,
          eventType: 'core.started',
          title: 'Core started',
          message: 'Ready',
        );

    expect(container.read(logbookProvider).single.id, event.id);
    expect(await testDatabase.countLogbookEvents(profileId: 3), 1);
  });

  test('remove and clear stay deleted after a reload', () async {
    final notifier = container.read(logbookProvider.notifier);
    final first = await notifier.record(
      profileId: 1,
      category: LogbookCategory.core,
      severity: LogbookSeverity.info,
      eventType: 'core.one',
      title: 'One',
    );
    await notifier.record(
      profileId: 2,
      category: LogbookCategory.core,
      severity: LogbookSeverity.info,
      eventType: 'core.two',
      title: 'Two',
    );

    await notifier.remove(first.id);
    await notifier.reload();
    expect(container.read(logbookProvider).map((event) => event.profileId), [
      2,
    ]);

    await notifier.clear(profileId: 2);
    await notifier.reload();
    expect(container.read(logbookProvider), isEmpty);
  });

  test('correlation updates one in-memory event', () async {
    final notifier = container.read(logbookProvider.notifier);
    final first = await notifier.record(
      category: LogbookCategory.network,
      severity: LogbookSeverity.info,
      eventType: 'network.changed',
      title: 'Wi-Fi',
      correlationId: 'network-state',
    );
    final second = await notifier.record(
      category: LogbookCategory.network,
      severity: LogbookSeverity.warning,
      eventType: 'network.changed',
      title: 'Offline',
      correlationId: 'network-state',
    );

    expect(second.id, first.id);
    expect(container.read(logbookProvider), hasLength(1));
    expect(container.read(logbookProvider).single.title, 'Offline');
  });
}
