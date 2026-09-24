import 'package:fl_clash/core/controller.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/features/features.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/quick_routing.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TrackerInfo trackerInfo({
    required String id,
    String host = 'api.example.com',
    String process = 'com.example.app',
    String destinationIP = '1.1.1.1',
  }) {
    return TrackerInfo(
      id: id,
      start: DateTime.utc(2026, 9, 24),
      metadata: Metadata(
        network: 'tcp',
        host: host,
        process: process,
        destinationIP: destinationIP,
        destinationPort: '443',
      ),
      chains: const ['HK-01', 'Proxy'],
      rule: 'MATCH',
      rulePayload: '',
    );
  }

  const selection = QuickRoutingSelection(
    candidate: QuickRoutingCandidate(
      ruleAction: RuleAction.DOMAIN,
      content: 'api.example.com',
    ),
    target: 'Proxy',
    lifetime: QuickRoutingLifetime.session,
  );

  CoreRuleMatchResult coreResult({
    String target = 'Proxy',
    List<String> policyChain = const ['Proxy', 'HK-01'],
  }) {
    return CoreRuleMatchResult(
      mode: 'rule',
      matched: true,
      ruleScope: 'default',
      ruleIndex: 0,
      ruleType: 'Domain',
      payload: 'api.example.com',
      target: target,
      policyChain: policyChain,
      ruleTrace: const [],
      providerNames: const ['provider-a'],
      resolvedIP: '1.1.1.1',
      complete: true,
      warnings: const [],
    );
  }

  QuickRoutingVerification verification(
    QuickRoutingVerificationStatus status, {
    CoreRuleMatchResult? result,
  }) {
    return QuickRoutingVerification(
      status: status,
      result: result ??
          (status == QuickRoutingVerificationStatus.unavailable
              ? null
              : coreResult()),
      issues: status == QuickRoutingVerificationStatus.unavailable
          ? const ['core-unavailable']
          : status == QuickRoutingVerificationStatus.mismatch
              ? const ['target-mismatch']
              : const [],
    );
  }

  QuickRoutingVerificationRecord record({
    required int id,
    required QuickRoutingVerificationStatus status,
    String host = 'api.example.com',
    String process = 'com.example.app',
    CoreRuleMatchResult? result,
  }) {
    final checkedAt = DateTime.utc(2026, 9, 24, 0, 0, id);
    return QuickRoutingVerificationRecord(
      id: id,
      profileId: 1,
      createdAt: checkedAt,
      checkedAt: checkedAt,
      trackerInfo: trackerInfo(
        id: 'request-$id',
        host: host,
        process: process,
      ),
      selection: selection,
      appliedRule: Rule(
        id: id,
        ruleAction: RuleAction.DOMAIN,
        content: 'api.example.com',
        ruleTarget: 'Proxy',
      ),
      verification: verification(status, result: result),
    );
  }

  final records = [
    record(id: 1, status: QuickRoutingVerificationStatus.verified),
    record(id: 2, status: QuickRoutingVerificationStatus.approximate),
    record(id: 3, status: QuickRoutingVerificationStatus.mismatch),
    record(id: 4, status: QuickRoutingVerificationStatus.unavailable),
  ];

  test('counts every diagnostics status', () {
    final counts = countQuickRoutingVerificationStatuses(records);

    for (final status in QuickRoutingVerificationStatus.values) {
      expect(counts[status], 1);
    }
  });

  test('attention filter includes every non-verified result', () {
    final filtered = filterQuickRoutingVerificationRecords(
      records,
      filter: QuickRoutingVerificationFilter.attention,
    );

    expect(
      filtered.map((entry) => entry.verification.status),
      [
        QuickRoutingVerificationStatus.approximate,
        QuickRoutingVerificationStatus.mismatch,
        QuickRoutingVerificationStatus.unavailable,
      ],
    );
  });

  test('status filter preserves source order', () {
    final filtered = filterQuickRoutingVerificationRecords(
      records,
      filter: QuickRoutingVerificationFilter.mismatch,
    );

    expect(filtered.map((entry) => entry.id), [3]);
  });

  test('search matches metadata and compiled policy chain with all terms', () {
    final searchable = [
      record(
        id: 5,
        status: QuickRoutingVerificationStatus.verified,
        host: 'api.openai.com',
        process: 'com.openai.chatgpt',
        result: coreResult(
          policyChain: const ['Proxy', 'Singapore Auto', 'SG-01'],
        ),
      ),
      record(
        id: 6,
        status: QuickRoutingVerificationStatus.verified,
        host: 'example.org',
        process: 'org.example.app',
      ),
    ];

    expect(
      filterQuickRoutingVerificationRecords(
        searchable,
        query: 'openai sg-01',
      ).map((entry) => entry.id),
      [5],
    );
    expect(
      filterQuickRoutingVerificationRecords(
        searchable,
        query: 'openai missing',
      ),
      isEmpty,
    );
  });

  test('search includes issue codes for unavailable records', () {
    expect(
      filterQuickRoutingVerificationRecords(
        records,
        query: 'core-unavailable',
      ).map((entry) => entry.id),
      [4],
    );
  });

  test('profile-safe unavailable result keeps a distinct issue', () {
    final result = unavailableQuickRoutingVerification(
      'profile-not-active',
    );

    expect(result.status, QuickRoutingVerificationStatus.unavailable);
    expect(result.issues, ['profile-not-active']);
    expect(result.attempts, 0);
  });
}
