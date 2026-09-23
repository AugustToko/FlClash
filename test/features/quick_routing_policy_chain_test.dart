import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/features/features.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/providers.dart';
import 'package:test/test.dart';

void main() {
  test('normalizes Mihomo tracker chains from leaf-first to policy-first', () {
    expect(
      normalizeQuickRoutingHistoricalPolicyChain([
        'HK-01',
        'Automatic',
        'Proxy',
      ]),
      ['Proxy', 'Automatic', 'HK-01'],
    );
  });

  test('resolves nested selector and fixed automatic group chains', () {
    const groups = [
      Group(
        name: 'Proxy',
        type: GroupType.Selector,
        now: 'Automatic',
      ),
      Group(
        name: 'Automatic',
        type: GroupType.URLTest,
        now: 'HK-01',
      ),
    ];

    final result = buildQuickRoutingPolicyChainPreview(
      target: 'Proxy',
      groups: groups,
      fixedStates: const {'Automatic': 'HK-01'},
    );

    expect(result.nodes, ['Proxy', 'Automatic', 'HK-01']);
    expect(result.complete, isTrue);
    expect(result.automatic, isFalse);
  });

  test('keeps automatic computed groups explicitly approximate', () {
    const groups = [
      Group(
        name: 'Proxy',
        type: GroupType.Selector,
        now: 'Automatic',
      ),
      Group(
        name: 'Automatic',
        type: GroupType.Fallback,
        now: 'HK-01',
      ),
    ];

    final result = buildQuickRoutingPolicyChainPreview(
      target: 'Proxy',
      groups: groups,
      fixedStates: const {'Automatic': ''},
    );

    expect(result.nodes, ['Proxy', 'Automatic']);
    expect(result.displayNodes('AUTO'), ['Proxy', 'Automatic', 'AUTO']);
    expect(result.complete, isFalse);
    expect(result.automatic, isTrue);
  });

  test('a temporary fixed override predicts the selected member', () {
    const groups = [
      Group(
        name: 'Automatic',
        type: GroupType.URLTest,
        now: 'HK-01',
      ),
    ];
    const override = QuickRoutingGroupOverride(
      groupName: 'Automatic',
      previousFixed: '',
      expectedFixed: '',
      desiredFixed: 'JP-01',
    );

    final result = buildQuickRoutingPolicyChainPreview(
      target: 'Automatic',
      groups: groups,
      fixedStates: const {'Automatic': ''},
      groupOverride: override,
    );

    expect(result.nodes, ['Automatic', 'JP-01']);
    expect(result.complete, isTrue);
    expect(result.automatic, isFalse);
  });

  test('cycles and metadata-dependent groups remain approximate', () {
    const cyclicGroups = [
      Group(name: 'A', type: GroupType.Selector, now: 'B'),
      Group(name: 'B', type: GroupType.Selector, now: 'A'),
    ];
    final cycle = buildQuickRoutingPolicyChainPreview(
      target: 'A',
      groups: cyclicGroups,
    );
    expect(cycle.nodes, ['A', 'B']);
    expect(cycle.complete, isFalse);

    const loadBalanceGroups = [
      Group(
        name: 'Balance',
        type: GroupType.LoadBalance,
        now: 'HK-01',
      ),
    ];
    final loadBalance = buildQuickRoutingPolicyChainPreview(
      target: 'Balance',
      groups: loadBalanceGroups,
    );
    expect(loadBalance.nodes, ['Balance']);
    expect(loadBalance.complete, isFalse);
  });
}
