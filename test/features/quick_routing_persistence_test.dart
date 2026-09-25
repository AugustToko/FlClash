import 'package:drift/native.dart';
import 'package:fl_clash/core/controller.dart';
import 'package:fl_clash/database/database.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/features/features.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/quick_routing.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  late Database originalDatabase;
  late Database testDatabase;
  const persistence = DatabaseQuickRoutingDiagnosticsPersistence();

  setUp(() async {
    originalDatabase = database;
    testDatabase = Database(NativeDatabase.memory());
    database = testDatabase;
    await testDatabase.profilesDao.putAll([
      const Profile(id: 7, autoUpdateDuration: Duration.zero).toCompanion(),
    ]);
  });

  tearDown(() async {
    database = originalDatabase;
    await testDatabase.close();
  });

  test('round trips request, selection and full Core verification', () async {
    final checkedAt = DateTime.utc(2026, 9, 24, 12);
    const selection = QuickRoutingSelection(
      candidate: QuickRoutingCandidate(
        ruleAction: RuleAction.DOMAIN_SUFFIX,
        content: 'example.com',
        scopeHint: 'eTLD+1',
      ),
      target: 'Proxy',
      lifetime: QuickRoutingLifetime.oneHour,
      groupOverride: QuickRoutingGroupOverride(
        groupName: 'Proxy',
        previousFixed: '',
        expectedFixed: '',
        desiredFixed: 'node-a',
      ),
    );
    const result = CoreRuleMatchResult(
      mode: 'rule',
      matched: true,
      ruleScope: 'default',
      ruleIndex: 2,
      ruleType: 'DomainSuffix',
      payload: 'example.com',
      target: 'Proxy',
      policyChain: ['Proxy', 'node-a'],
      ruleTrace: [
        CoreRuleMatchTraceStep(
          ruleScope: 'default',
          ruleIndex: 2,
          ruleType: 'DomainSuffix',
          payload: 'example.com',
          target: 'Proxy',
          policyChain: ['Proxy', 'node-a'],
          outcome: 'matched',
          rematchName: '',
          subRule: '',
        ),
      ],
      providerNames: ['domains'],
      resolvedIP: '203.0.113.7',
      complete: true,
      warnings: [],
      policyExplanation: CorePolicyExplanation(
        target: 'Proxy',
        policyChain: ['Proxy', 'node-a'],
        steps: [
          CorePolicyExplainStep(
            name: 'Proxy',
            type: 'Selector',
            selected: 'node-a',
            reason: 'manual-selection',
            strategy: '',
            key: '',
            keySource: '',
            testURL: '',
            fastest: '',
            candidateCount: 2,
            selectedIndex: 0,
            bucket: -1,
            retry: -1,
            tolerance: 0,
            selectedDelay: 0,
            fastestDelay: 0,
            fixed: false,
            healthKnown: false,
            selectedAlive: true,
            complete: true,
          ),
        ],
        complete: true,
        warnings: [],
      ),
    );
    final record = QuickRoutingVerificationRecord(
      id: 99,
      profileId: 7,
      createdAt: checkedAt.subtract(const Duration(minutes: 3)),
      checkedAt: checkedAt,
      trackerInfo: TrackerInfo(
        id: 'request-7',
        start: checkedAt.subtract(const Duration(seconds: 5)),
        metadata: const Metadata(
          network: 'tcp',
          host: 'api.example.com',
          destinationIP: '203.0.113.7',
          destinationPort: '443',
          process: 'browser',
        ),
        chains: const ['node-a', 'Proxy'],
        rule: 'DOMAIN-SUFFIX',
        rulePayload: 'example.com',
      ),
      selection: selection,
      appliedRule: const Rule(
        id: -1,
        ruleAction: RuleAction.DOMAIN_SUFFIX,
        content: 'example.com',
        ruleTarget: 'Proxy',
      ),
      verification: const QuickRoutingVerification(
        status: QuickRoutingVerificationStatus.verified,
        result: result,
        issues: [],
        attempts: 1,
      ),
    );

    await persistence.upsert(record);
    final loaded = await persistence.loadProfile(7);

    expect(loaded, hasLength(1));
    final restored = loaded.single;
    expect(restored.id, record.id);
    expect(restored.createdAt.isAtSameMomentAs(record.createdAt), isTrue);
    expect(restored.checkedAt.isAtSameMomentAs(record.checkedAt), isTrue);
    expect(restored.trackerInfo.metadata.host, 'api.example.com');
    expect(restored.selection.candidate.scopeHint, 'eTLD+1');
    expect(restored.selection.lifetime, QuickRoutingLifetime.oneHour);
    expect(restored.selection.groupOverride?.desiredFixed, 'node-a');
    expect(restored.verification.status, QuickRoutingVerificationStatus.verified);
    expect(restored.verification.result?.policyChain, ['Proxy', 'node-a']);
    expect(
      restored.verification.result?.policyExplanation?.steps.single.reason,
      'manual-selection',
    );
  });

  test('updating one diagnostic preserves its original record identity', () async {
    final base = DateTime.utc(2026, 9, 24);
    QuickRoutingVerificationRecord record(
      int id,
      QuickRoutingVerificationStatus status,
      DateTime checkedAt,
    ) {
      return QuickRoutingVerificationRecord(
        id: id,
        profileId: 7,
        createdAt: base,
        checkedAt: checkedAt,
        trackerInfo: TrackerInfo(
          id: 'same-request',
          start: base,
          metadata: const Metadata(host: 'api.example.com'),
          chains: const [],
          rule: 'MATCH',
          rulePayload: '',
        ),
        selection: const QuickRoutingSelection(
          candidate: QuickRoutingCandidate(
            ruleAction: RuleAction.DOMAIN,
            content: 'api.example.com',
          ),
          target: 'DIRECT',
          lifetime: QuickRoutingLifetime.session,
        ),
        appliedRule: const Rule(
          id: -1,
          ruleAction: RuleAction.DOMAIN,
          content: 'api.example.com',
          ruleTarget: 'DIRECT',
        ),
        verification: QuickRoutingVerification(
          status: status,
          result: null,
          issues: const ['core-unavailable'],
        ),
      );
    }

    await persistence.upsert(
      record(10, QuickRoutingVerificationStatus.unavailable, base),
    );
    final updated = await persistence.upsert(
      record(
        20,
        QuickRoutingVerificationStatus.mismatch,
        base.add(const Duration(minutes: 1)),
      ),
    );

    expect(updated.id, 10);
    expect(updated.createdAt.isAtSameMomentAs(base), isTrue);
    expect(updated.verification.status, QuickRoutingVerificationStatus.mismatch);
    expect(await testDatabase.countQuickRoutingDiagnostics(7), 1);
  });
}
