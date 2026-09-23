import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/quick_routing.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:riverpod/riverpod.dart';

void main() {
  Rule rule({
    required int id,
    required String content,
    required String target,
  }) {
    return Rule(
      id: id,
      ruleAction: RuleAction.DOMAIN,
      content: content,
      ruleTarget: target,
    );
  }

  QuickRoutingRuleEntry put(
    QuickRoutingRules notifier, {
    required Rule value,
    required QuickRoutingLifetime lifetime,
    int profileId = 1,
    QuickRoutingGroupOverride? groupOverride,
    DateTime? now,
  }) {
    return notifier.put(
      profileId: profileId,
      rule: value,
      lifetime: lifetime,
      sourceId: 'request',
      sourceDesc: 'tcp://example.com:443',
      previousRule: 'MATCH',
      previousChains: const ['Proxy'],
      groupOverride: groupOverride,
      now: now,
    );
  }

  test('put replaces the target of an equivalent runtime matcher', () {
    final container = ProviderContainer();
    addTearDown(container.dispose);
    final notifier = container.read(quickRoutingRulesProvider.notifier);

    final first = put(
      notifier,
      value: rule(id: 10, content: 'example.com', target: 'Proxy'),
      lifetime: QuickRoutingLifetime.session,
    );
    final second = put(
      notifier,
      value: rule(id: 11, content: 'example.com', target: 'DIRECT'),
      lifetime: QuickRoutingLifetime.oneHour,
    );

    final entries = container.read(quickRoutingRulesProvider);
    expect(entries, hasLength(1));
    expect(second.rule.id, first.rule.id);
    expect(entries.single.rule.ruleTarget, 'DIRECT');
    expect(entries.single.lifetime, QuickRoutingLifetime.oneHour);
  });

  test('runtime rule priorities can move without touching other profiles', () {
    final container = ProviderContainer();
    addTearDown(container.dispose);
    final notifier = container.read(quickRoutingRulesProvider.notifier);

    put(
      notifier,
      value: rule(id: 10, content: 'first.example', target: 'Proxy'),
      lifetime: QuickRoutingLifetime.session,
    );
    put(
      notifier,
      value: rule(id: 20, content: 'other.example', target: 'Proxy'),
      lifetime: QuickRoutingLifetime.session,
      profileId: 2,
    );
    put(
      notifier,
      value: rule(id: 11, content: 'second.example', target: 'DIRECT'),
      lifetime: QuickRoutingLifetime.session,
    );

    expect(
      container
          .read(quickRoutingRulesProvider)
          .map((entry) => entry.rule.id),
      [11, 20, 10],
    );
    expect(notifier.move(1, 10, -1), isTrue);
    expect(
      container
          .read(quickRoutingRulesProvider)
          .map((entry) => entry.rule.id),
      [10, 20, 11],
    );
    expect(notifier.move(1, 10, -1), isFalse);
    expect(notifier.move(1, 10, 1), isTrue);
    expect(
      container
          .read(quickRoutingRulesProvider)
          .map((entry) => entry.rule.id),
      [11, 20, 10],
    );
  });

  test('timed entries expire and can be purged deterministically', () {
    final container = ProviderContainer();
    addTearDown(container.dispose);
    final notifier = container.read(quickRoutingRulesProvider.notifier);
    final now = DateTime.utc(2026, 9, 23, 12);

    put(
      notifier,
      value: rule(id: 10, content: 'example.com', target: 'Proxy'),
      lifetime: QuickRoutingLifetime.tenMinutes,
      now: now,
    );

    expect(
      notifier.activeRulesFor(1, now: now.add(const Duration(minutes: 9))),
      hasLength(1),
    );
    expect(
      notifier.activeRulesFor(1, now: now.add(const Duration(minutes: 10))),
      isEmpty,
    );
    expect(
      notifier.purgeExpired(now: now.add(const Duration(minutes: 10))),
      isTrue,
    );
    expect(container.read(quickRoutingRulesProvider), isEmpty);
  });

  test('network cleanup preserves other runtime lifetimes', () {
    final container = ProviderContainer();
    addTearDown(container.dispose);
    final notifier = container.read(quickRoutingRulesProvider.notifier);

    put(
      notifier,
      value: rule(id: 10, content: 'network.example', target: 'Proxy'),
      lifetime: QuickRoutingLifetime.network,
    );
    put(
      notifier,
      value: rule(id: 11, content: 'session.example', target: 'DIRECT'),
      lifetime: QuickRoutingLifetime.session,
    );

    expect(notifier.clearNetworkBound(), isTrue);
    final entries = container.read(quickRoutingRulesProvider);
    expect(entries, hasLength(1));
    expect(entries.single.rule.content, 'session.example');
  });

  test('conditional replacement restores the exact applied state', () {
    final container = ProviderContainer();
    addTearDown(container.dispose);
    final notifier = container.read(quickRoutingRulesProvider.notifier);
    final snapshot = container.read(quickRoutingRulesProvider);

    put(
      notifier,
      value: rule(id: 10, content: 'example.com', target: 'Proxy'),
      lifetime: QuickRoutingLifetime.session,
    );
    final applied = container.read(quickRoutingRulesProvider);
    final restored = notifier.replaceAllIfCurrent(
      expected: applied,
      entries: snapshot,
    );

    expect(restored, isNotNull);
    expect(container.read(quickRoutingRulesProvider), isEmpty);
  });

  test('conditional replacement refuses to overwrite newer changes', () {
    final container = ProviderContainer();
    addTearDown(container.dispose);
    final notifier = container.read(quickRoutingRulesProvider.notifier);

    put(
      notifier,
      value: rule(id: 10, content: 'first.example', target: 'Proxy'),
      lifetime: QuickRoutingLifetime.session,
    );
    final stale = container.read(quickRoutingRulesProvider);
    put(
      notifier,
      value: rule(id: 11, content: 'second.example', target: 'DIRECT'),
      lifetime: QuickRoutingLifetime.session,
    );
    final current = container.read(quickRoutingRulesProvider);

    final restored = notifier.replaceAllIfCurrent(
      expected: stale,
      entries: const [],
    );

    expect(restored, isNull);
    expect(container.read(quickRoutingRulesProvider), same(current));
    expect(current, hasLength(2));
  });

  group('automatic group override lifecycle', () {
    const initialOverride = QuickRoutingGroupOverride(
      groupName: 'Auto',
      previousFixed: '',
      expectedFixed: '',
      desiredFixed: 'HK-01',
    );

    test('adding an override produces a fixed-state transition', () {
      final container = ProviderContainer();
      addTearDown(container.dispose);
      final notifier = container.read(quickRoutingRulesProvider.notifier);
      final previous = container.read(quickRoutingRulesProvider);

      put(
        notifier,
        value: rule(id: 10, content: 'example.com', target: 'Auto'),
        lifetime: QuickRoutingLifetime.session,
        groupOverride: initialOverride,
      );
      final next = container.read(quickRoutingRulesProvider);

      expect(
        buildQuickRoutingGroupOverrideTransitions(
          previous: previous,
          next: next,
        ),
        const [
          QuickRoutingGroupOverrideTransition(
            profileId: 1,
            groupName: 'Auto',
            expectedFixed: '',
            targetFixed: 'HK-01',
          ),
        ],
      );
    });

    test('a replacement keeps the original restoration baseline', () {
      final container = ProviderContainer();
      addTearDown(container.dispose);
      final notifier = container.read(quickRoutingRulesProvider.notifier);

      put(
        notifier,
        value: rule(id: 10, content: 'first.example', target: 'Auto'),
        lifetime: QuickRoutingLifetime.session,
        groupOverride: initialOverride,
      );
      final previous = container.read(quickRoutingRulesProvider);
      final second = put(
        notifier,
        value: rule(id: 11, content: 'second.example', target: 'Auto'),
        lifetime: QuickRoutingLifetime.oneHour,
        groupOverride: const QuickRoutingGroupOverride(
          groupName: 'Auto',
          previousFixed: 'HK-01',
          expectedFixed: 'HK-01',
          desiredFixed: 'JP-01',
        ),
      );
      final next = container.read(quickRoutingRulesProvider);

      expect(second.groupOverride?.previousFixed, '');
      expect(second.groupOverride?.expectedFixed, 'HK-01');
      expect(second.groupOverride?.desiredFixed, 'JP-01');
      expect(
        next.where((entry) => entry.groupOverride != null),
        hasLength(1),
      );
      expect(
        buildQuickRoutingGroupOverrideTransitions(
          previous: previous,
          next: next,
        ),
        const [
          QuickRoutingGroupOverrideTransition(
            profileId: 1,
            groupName: 'Auto',
            expectedFixed: 'HK-01',
            targetFixed: 'JP-01',
          ),
        ],
      );

      expect(notifier.clearProfile(1), isTrue);
      expect(
        buildQuickRoutingGroupOverrideTransitions(
          previous: next,
          next: container.read(quickRoutingRulesProvider),
        ),
        const [
          QuickRoutingGroupOverrideTransition(
            profileId: 1,
            groupName: 'Auto',
            expectedFixed: 'JP-01',
            targetFixed: '',
          ),
        ],
      );
    });

    test('expiration restores the initial fixed state', () {
      final container = ProviderContainer();
      addTearDown(container.dispose);
      final notifier = container.read(quickRoutingRulesProvider.notifier);
      final now = DateTime.utc(2026, 9, 23, 12);

      put(
        notifier,
        value: rule(id: 10, content: 'example.com', target: 'Auto'),
        lifetime: QuickRoutingLifetime.tenMinutes,
        groupOverride: initialOverride,
        now: now,
      );
      final entries = container.read(quickRoutingRulesProvider);

      expect(
        buildQuickRoutingGroupOverrideTransitions(
          previous: entries,
          next: entries,
          now: now.add(const Duration(minutes: 10)),
        ),
        const [
          QuickRoutingGroupOverrideTransition(
            profileId: 1,
            groupName: 'Auto',
            expectedFixed: 'HK-01',
            targetFixed: '',
          ),
        ],
      );
    });

    test('the same group name stays isolated between profiles', () {
      final container = ProviderContainer();
      addTearDown(container.dispose);
      final notifier = container.read(quickRoutingRulesProvider.notifier);
      final previous = container.read(quickRoutingRulesProvider);

      put(
        notifier,
        value: rule(id: 10, content: 'one.example', target: 'Auto'),
        lifetime: QuickRoutingLifetime.session,
        profileId: 1,
        groupOverride: initialOverride,
      );
      put(
        notifier,
        value: rule(id: 20, content: 'two.example', target: 'Auto'),
        lifetime: QuickRoutingLifetime.session,
        profileId: 2,
        groupOverride: const QuickRoutingGroupOverride(
          groupName: 'Auto',
          previousFixed: '',
          expectedFixed: '',
          desiredFixed: 'JP-01',
        ),
      );
      final next = container.read(quickRoutingRulesProvider);

      expect(
        next.where((entry) => entry.groupOverride != null),
        hasLength(2),
      );
      expect(
        buildQuickRoutingGroupOverrideTransitions(
          previous: previous,
          next: next,
        ),
        unorderedEquals(const [
          QuickRoutingGroupOverrideTransition(
            profileId: 1,
            groupName: 'Auto',
            expectedFixed: '',
            targetFixed: 'HK-01',
          ),
          QuickRoutingGroupOverrideTransition(
            profileId: 2,
            groupName: 'Auto',
            expectedFixed: '',
            targetFixed: 'JP-01',
          ),
        ]),
      );
    });
  });

  group('mergeQuickRoutingRules', () {
    final runtime = rule(id: 1, content: 'runtime.example', target: 'DIRECT');
    final custom = rule(id: 2, content: 'custom.example', target: 'Proxy');
    final added = rule(id: 3, content: 'added.example', target: 'Proxy');

    test('prepends runtime rules to an explicit custom rule set', () {
      final result = mergeQuickRoutingRules(
        overwriteType: OverwriteType.custom,
        runtimeRules: [runtime],
        rules: [custom],
        addedRules: [added],
      );

      expect(result.rules, [runtime, custom]);
      expect(result.addedRules, [added]);
    });

    test('keeps inherited custom profile rules when no custom list exists', () {
      final result = mergeQuickRoutingRules(
        overwriteType: OverwriteType.custom,
        runtimeRules: [runtime],
        rules: const [],
        addedRules: [added],
      );

      expect(result.rules, isEmpty);
      expect(result.addedRules, [runtime, added]);
    });

    test('injects runtime rules after script evaluation', () {
      final result = mergeQuickRoutingRules(
        overwriteType: OverwriteType.script,
        runtimeRules: [runtime],
        rules: const [],
        addedRules: const [],
      );

      expect(result.rules, isEmpty);
      expect(result.addedRules, [runtime]);
    });
  });
}
