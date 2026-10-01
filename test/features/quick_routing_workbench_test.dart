import 'package:fl_clash/core/controller.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/features/features.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/quick_routing.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:riverpod/riverpod.dart';

void main() {
  TrackerInfo trackerInfo({
    String id = 'request',
    String host = 'api.example.com',
  }) {
    return TrackerInfo(
      id: id,
      start: DateTime.utc(2026, 9, 24),
      metadata: Metadata(network: 'tcp', host: host, destinationPort: '443'),
      chains: const ['DIRECT'],
      rule: 'MATCH',
      rulePayload: '',
    );
  }

  const selection = QuickRoutingSelection(
    candidate: QuickRoutingCandidate(
      ruleAction: RuleAction.DOMAIN,
      content: 'api.example.com',
    ),
    target: 'DIRECT',
    lifetime: QuickRoutingLifetime.session,
  );

  QuickRoutingVerification verification(QuickRoutingVerificationStatus status) {
    return QuickRoutingVerification(
      status: status,
      result: status == QuickRoutingVerificationStatus.unavailable
          ? null
          : const CoreRuleMatchResult(
              mode: 'rule',
              matched: true,
              ruleScope: 'default',
              ruleIndex: 0,
              ruleType: 'Domain',
              payload: 'api.example.com',
              target: 'DIRECT',
              policyChain: ['DIRECT'],
              ruleTrace: [],
              providerNames: [],
              resolvedIP: '',
              complete: true,
              warnings: [],
            ),
      issues: const [],
    );
  }

  Rule appliedRule(int id) {
    return Rule(
      id: id,
      ruleAction: RuleAction.DOMAIN,
      content: 'api.example.com',
      ruleTarget: 'DIRECT',
    );
  }

  test('verification history is bounded and keeps newest entries first', () {
    final container = ProviderContainer();
    addTearDown(container.dispose);
    final notifier = container.read(
      quickRoutingVerificationHistoryProvider.notifier,
    );
    final base = DateTime.utc(2026, 9, 24);

    for (
      var index = 0;
      index < QuickRoutingVerificationHistory.maxEntries + 5;
      index++
    ) {
      notifier.upsert(
        id: index,
        profileId: 1,
        trackerInfo: trackerInfo(id: 'request-$index'),
        selection: selection,
        appliedRule: appliedRule(index),
        verification: verification(QuickRoutingVerificationStatus.verified),
        now: base.add(Duration(seconds: index)),
      );
    }

    final entries = container.read(quickRoutingVerificationHistoryProvider);
    expect(entries, hasLength(QuickRoutingVerificationHistory.maxEntries));
    expect(entries.first.id, QuickRoutingVerificationHistory.maxEntries + 4);
    expect(entries.last.id, 5);
  });

  test('upsert refreshes an existing request without duplicating history', () {
    final container = ProviderContainer();
    addTearDown(container.dispose);
    final notifier = container.read(
      quickRoutingVerificationHistoryProvider.notifier,
    );
    final createdAt = DateTime.utc(2026, 9, 24, 1);

    final first = notifier.upsert(
      id: 10,
      profileId: 1,
      trackerInfo: trackerInfo(),
      selection: selection,
      appliedRule: appliedRule(10),
      verification: verification(QuickRoutingVerificationStatus.unavailable),
      now: createdAt,
    );
    final updated = notifier.upsert(
      profileId: 1,
      trackerInfo: trackerInfo(),
      selection: selection,
      appliedRule: appliedRule(99),
      verification: verification(QuickRoutingVerificationStatus.verified),
      now: createdAt.add(const Duration(minutes: 1)),
    );

    final entries = container.read(quickRoutingVerificationHistoryProvider);
    expect(entries, hasLength(1));
    expect(updated.id, first.id);
    expect(updated.createdAt, createdAt);
    expect(
      updated.verification.status,
      QuickRoutingVerificationStatus.verified,
    );
  });

  test('history updates one result and clears only the requested profile', () {
    final container = ProviderContainer();
    addTearDown(container.dispose);
    final notifier = container.read(
      quickRoutingVerificationHistoryProvider.notifier,
    );

    notifier.upsert(
      id: 1,
      profileId: 1,
      trackerInfo: trackerInfo(id: 'one'),
      selection: selection,
      appliedRule: appliedRule(1),
      verification: verification(QuickRoutingVerificationStatus.unavailable),
    );
    notifier.upsert(
      id: 2,
      profileId: 2,
      trackerInfo: trackerInfo(id: 'two'),
      selection: selection,
      appliedRule: appliedRule(2),
      verification: verification(QuickRoutingVerificationStatus.verified),
    );

    expect(
      notifier.updateVerification(
        1,
        verification(QuickRoutingVerificationStatus.mismatch),
      ),
      isTrue,
    );
    expect(
      container
          .read(quickRoutingVerificationHistoryProvider)
          .firstWhere((entry) => entry.id == 1)
          .verification
          .status,
      QuickRoutingVerificationStatus.mismatch,
    );

    expect(notifier.clearProfile(1, persist: false), isTrue);
    final remaining = container.read(quickRoutingVerificationHistoryProvider);
    expect(remaining.map((entry) => entry.profileId), [2]);
  });

  test('conflict scan locates equivalent, competing and opaque rules', () {
    final conflicts = buildQuickRoutingConflictEntries(
      selection: selection,
      trackerInfo: trackerInfo(),
      knownRules: const [
        Rule(
          id: 1,
          ruleAction: RuleAction.RULE_SET,
          content: 'opaque-provider',
          ruleTarget: 'Proxy',
        ),
        Rule(
          id: 2,
          ruleAction: RuleAction.DOMAIN_SUFFIX,
          content: 'example.com',
          ruleTarget: 'Proxy',
        ),
        Rule(
          id: 3,
          ruleAction: RuleAction.DOMAIN,
          content: 'api.example.com',
          ruleTarget: 'DIRECT',
        ),
        Rule(id: 4, ruleAction: RuleAction.MATCH, ruleTarget: 'DIRECT'),
      ],
    );

    expect(conflicts.map((entry) => entry.kind), [
      QuickRoutingConflictKind.opaque,
      QuickRoutingConflictKind.competing,
      QuickRoutingConflictKind.equivalent,
    ]);
    expect(conflicts.map((entry) => entry.index), [0, 1, 2]);
  });

  test('conflict scan ignores matching rules with the requested target', () {
    final conflicts = buildQuickRoutingConflictEntries(
      selection: selection,
      trackerInfo: trackerInfo(),
      knownRules: const [
        Rule(
          id: 1,
          ruleAction: RuleAction.DOMAIN_SUFFIX,
          content: 'example.com',
          ruleTarget: 'DIRECT',
        ),
        Rule(id: 2, ruleAction: RuleAction.MATCH, ruleTarget: 'DIRECT'),
      ],
    );

    expect(conflicts, isEmpty);
  });
}
