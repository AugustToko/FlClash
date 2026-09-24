import 'package:fl_clash/core/controller.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/features/features.dart';
import 'package:fl_clash/providers/quick_routing.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  CoreRuleMatchResult coreResult({
    bool matched = true,
    String mode = 'rule',
    String ruleType = 'Domain',
    String payload = 'api.example.com',
    String target = 'DIRECT',
    List<String> policyChain = const ['DIRECT'],
    bool complete = true,
  }) {
    return CoreRuleMatchResult(
      mode: mode,
      matched: matched,
      ruleScope: matched ? 'default' : '',
      ruleIndex: matched ? 0 : -1,
      ruleType: ruleType,
      payload: payload,
      target: target,
      policyChain: policyChain,
      ruleTrace: const [],
      providerNames: const [],
      resolvedIP: '',
      complete: complete,
      warnings: complete ? const [] : const ['diagnostic-incomplete'],
    );
  }

  test('verifies the compiled matcher and target', () {
    final verification = evaluateQuickRoutingVerification(
      candidate: const QuickRoutingCandidate(
        ruleAction: RuleAction.DOMAIN,
        content: 'Api.Example.com.',
      ),
      target: 'DIRECT',
      result: coreResult(payload: 'api.example.com'),
    );

    expect(verification.status, QuickRoutingVerificationStatus.verified);
    expect(verification.confirmsApplied, isTrue);
    expect(verification.exact, isTrue);
    expect(verification.issues, isEmpty);
    expect(verification.marker, '✓');
    expect(verification.messageLevel, MessageLevel.success);
  });

  test('normalizes IPv6 CIDR payloads while preserving rule type', () {
    final verification = evaluateQuickRoutingVerification(
      candidate: const QuickRoutingCandidate(
        ruleAction: RuleAction.IP_CIDR6,
        content: '2001:0db8::1/128',
        noResolve: true,
      ),
      target: 'Proxy',
      result: coreResult(
        ruleType: 'IPCIDR',
        payload: '2001:db8::1/128',
        target: 'Proxy',
        policyChain: const ['Proxy', 'HK-01'],
      ),
    );

    expect(verification.status, QuickRoutingVerificationStatus.verified);
  });

  test('verifies an automatic group fixed to its immediate member', () {
    final verification = evaluateQuickRoutingVerification(
      candidate: const QuickRoutingCandidate(
        ruleAction: RuleAction.DOMAIN_SUFFIX,
        content: 'example.com',
      ),
      target: 'Auto',
      groupOverride: const QuickRoutingGroupOverride(
        groupName: 'Auto',
        previousFixed: '',
        expectedFixed: '',
        desiredFixed: 'Nested',
      ),
      result: coreResult(
        ruleType: 'DomainSuffix',
        payload: 'example.com',
        target: 'Auto',
        policyChain: const ['Auto', 'Nested', 'HK-01'],
      ),
    );

    expect(verification.status, QuickRoutingVerificationStatus.verified);
  });

  test('reports matcher, target and fixed-member mismatches together', () {
    final verification = evaluateQuickRoutingVerification(
      candidate: const QuickRoutingCandidate(
        ruleAction: RuleAction.DOMAIN_SUFFIX,
        content: 'example.com',
      ),
      target: 'Auto',
      groupOverride: const QuickRoutingGroupOverride(
        groupName: 'Auto',
        previousFixed: '',
        expectedFixed: '',
        desiredFixed: 'HK-01',
      ),
      result: coreResult(
        ruleType: 'Domain',
        payload: 'other.example',
        target: 'DIRECT',
        policyChain: const ['DIRECT'],
      ),
    );

    expect(verification.status, QuickRoutingVerificationStatus.mismatch);
    expect(
      verification.issues,
      containsAll([
        'rule-type-mismatch',
        'rule-payload-mismatch',
        'target-mismatch',
        'fixed-policy-mismatch',
      ]),
    );
    expect(verification.confirmsApplied, isFalse);
    expect(verification.marker, '⚠');
    expect(verification.messageLevel, MessageLevel.error);
  });

  test('detects global or direct mode bypassing the new rule', () {
    final verification = evaluateQuickRoutingVerification(
      candidate: const QuickRoutingCandidate(
        ruleAction: RuleAction.DOMAIN,
        content: 'api.example.com',
      ),
      target: 'DIRECT',
      result: coreResult(
        matched: false,
        mode: 'direct',
        ruleType: '',
        payload: '',
      ),
    );

    expect(verification.status, QuickRoutingVerificationStatus.mismatch);
    expect(verification.issues, contains('rule-not-matched'));
  });

  test('keeps an exact but incomplete Core result visibly approximate', () {
    final verification = evaluateQuickRoutingVerification(
      candidate: const QuickRoutingCandidate(
        ruleAction: RuleAction.PROCESS_NAME,
        content: 'com.example.app',
      ),
      target: 'Proxy',
      result: coreResult(
        ruleType: 'ProcessName',
        payload: 'com.example.app',
        target: 'Proxy',
        policyChain: const ['Proxy', 'HK-01'],
        complete: false,
      ),
    );

    expect(verification.status, QuickRoutingVerificationStatus.approximate);
    expect(verification.confirmsApplied, isTrue);
    expect(verification.exact, isFalse);
    expect(verification.issues, ['core-result-incomplete']);
    expect(verification.messageLevel, MessageLevel.warning);
  });

  test('reports unavailable Core verification without invalidating the rule', () {
    final verification = evaluateQuickRoutingVerification(
      candidate: const QuickRoutingCandidate(
        ruleAction: RuleAction.DOMAIN,
        content: 'api.example.com',
      ),
      target: 'DIRECT',
      result: null,
      attempts: 0,
    );

    expect(verification.status, QuickRoutingVerificationStatus.unavailable);
    expect(verification.attempts, 0);
    expect(verification.issues, ['core-unavailable']);
    expect(verification.marker, '?');
    expect(verification.messageLevel, MessageLevel.warning);
  });
}
