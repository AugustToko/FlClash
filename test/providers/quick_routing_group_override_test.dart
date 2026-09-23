import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/quick_routing.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:riverpod/riverpod.dart';

void main() {
  QuickRoutingRuleEntry put(
    QuickRoutingRules notifier, {
    required int id,
    required String content,
    required QuickRoutingLifetime lifetime,
    required QuickRoutingGroupOverride groupOverride,
    required DateTime now,
  }) {
    return notifier.put(
      profileId: 1,
      rule: Rule(
        id: id,
        ruleAction: RuleAction.DOMAIN,
        content: content,
        ruleTarget: 'Auto',
      ),
      lifetime: lifetime,
      sourceId: content,
      sourceDesc: content,
      previousRule: 'MATCH',
      previousChains: const ['Auto'],
      groupOverride: groupOverride,
      now: now,
    );
  }

  test('replacement inherits the baseline from an unpurged expired rule', () {
    final container = ProviderContainer();
    addTearDown(container.dispose);
    final notifier = container.read(quickRoutingRulesProvider.notifier);
    final createdAt = DateTime.utc(2026, 9, 23, 12);

    put(
      notifier,
      id: 1,
      content: 'old.example',
      lifetime: QuickRoutingLifetime.tenMinutes,
      groupOverride: const QuickRoutingGroupOverride(
        groupName: 'Auto',
        previousFixed: '',
        expectedFixed: '',
        desiredFixed: 'HK-01',
      ),
      now: createdAt,
    );

    final replacement = put(
      notifier,
      id: 2,
      content: 'new.example',
      lifetime: QuickRoutingLifetime.oneHour,
      groupOverride: const QuickRoutingGroupOverride(
        groupName: 'Auto',
        previousFixed: 'HK-01',
        expectedFixed: 'HK-01',
        desiredFixed: 'JP-01',
      ),
      now: createdAt.add(const Duration(minutes: 11)),
    );

    expect(replacement.groupOverride?.previousFixed, '');
    expect(replacement.groupOverride?.expectedFixed, 'HK-01');
    expect(replacement.groupOverride?.desiredFixed, 'JP-01');
    expect(container.read(quickRoutingRulesProvider), hasLength(1));
  });

  test('expected fixed defaults to the immediate previous state', () {
    const override = QuickRoutingGroupOverride(
      groupName: 'Auto',
      previousFixed: 'HK-01',
      desiredFixed: 'JP-01',
    );

    expect(override.expectedFixed, 'HK-01');
    expect(override.changes, isTrue);
  });
}
