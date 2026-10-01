import 'package:fl_clash/core/controller.dart';
import 'package:fl_clash/core/method.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('parses a complete compiled rule match result', () {
    final result = CoreRuleMatchResult.fromJson({
      'mode': 'rule',
      'matched': true,
      'ruleScope': 'secondary',
      'ruleIndex': 12,
      'ruleType': 'RuleSet',
      'payload': 'OpenAI',
      'target': 'Proxy',
      'policyChain': ['Proxy', 'Auto', 'HK-01'],
      'ruleTrace': [
        {
          'ruleScope': 'default',
          'ruleIndex': 3,
          'ruleType': 'Match',
          'payload': '',
          'target': 'REMATCH-TO-SECONDARY',
          'policyChain': ['REMATCH-TO-SECONDARY'],
          'outcome': 'rematch',
          'rematchName': 'stage-two',
          'subRule': 'secondary',
        },
        {
          'ruleScope': 'secondary',
          'ruleIndex': 12,
          'ruleType': 'RuleSet',
          'payload': 'OpenAI',
          'target': 'Proxy',
          'policyChain': ['Proxy', 'Auto', 'HK-01'],
          'outcome': 'final',
          'rematchName': 'stage-two',
          'subRule': 'secondary',
        },
      ],
      'providerNames': ['OpenAI'],
      'resolvedIP': '1.1.1.1',
      'complete': true,
      'warnings': <String>[],
    });

    expect(result.mode, 'rule');
    expect(result.matched, isTrue);
    expect(result.ruleScope, 'secondary');
    expect(result.ruleIndex, 12);
    expect(result.ruleText, 'RuleSet(OpenAI)');
    expect(result.target, 'Proxy');
    expect(result.policyChain, ['Proxy', 'Auto', 'HK-01']);
    expect(result.policyText, 'Proxy → Auto → HK-01');
    expect(result.finalPolicy, 'HK-01');
    expect(result.ruleTrace, hasLength(2));
    expect(result.ruleTrace.first.ruleScope, 'default');
    expect(result.ruleTrace.first.ruleText, 'Match');
    expect(result.ruleTrace.first.outcome, 'rematch');
    expect(result.ruleTrace.first.rematchName, 'stage-two');
    expect(result.ruleTrace.first.subRule, 'secondary');
    expect(result.ruleTrace.last.policyText, 'Proxy → Auto → HK-01');
    expect(result.providerNames, ['OpenAI']);
    expect(result.resolvedIP, '1.1.1.1');
    expect(result.complete, isTrue);
    expect(result.warnings, isEmpty);
    expect(result.policyExplanation, isNull);
  });

  test(
    'parses policy group selection reasons and attaches them to a match',
    () {
      final explanation = CorePolicyExplanation.fromJson({
        'target': 'Proxy',
        'policyChain': ['Proxy', 'Balance', 'HK-01'],
        'steps': [
          {
            'name': 'Proxy',
            'type': 'Selector',
            'selected': 'Balance',
            'reason': 'manual-selection',
            'strategy': '',
            'key': '',
            'keySource': '',
            'testURL': '',
            'fastest': '',
            'candidateCount': 4,
            'selectedIndex': 2,
            'bucket': -1,
            'retry': -1,
            'tolerance': 0,
            'selectedDelay': 65535,
            'fastestDelay': 0,
            'fixed': false,
            'healthKnown': false,
            'selectedAlive': true,
            'complete': true,
          },
          {
            'name': 'Balance',
            'type': 'LoadBalance',
            'selected': 'HK-01',
            'reason': 'consistent-hash',
            'strategy': 'consistent-hashing',
            'key': 'example.com',
            'keySource': 'etld+1',
            'testURL': 'https://www.gstatic.com/generate_204',
            'fastest': '',
            'candidateCount': 3,
            'selectedIndex': 1,
            'bucket': 1,
            'retry': 0,
            'tolerance': 0,
            'selectedDelay': 42,
            'fastestDelay': 0,
            'fixed': false,
            'healthKnown': true,
            'selectedAlive': true,
            'complete': true,
          },
          'malformed',
        ],
        'complete': true,
        'warnings': <String>[],
      });

      expect(explanation.target, 'Proxy');
      expect(explanation.policyChain, ['Proxy', 'Balance', 'HK-01']);
      expect(explanation.steps, hasLength(2));
      expect(explanation.steps.first.reason, 'manual-selection');
      expect(explanation.steps.last.strategy, 'consistent-hashing');
      expect(explanation.steps.last.key, 'example.com');
      expect(explanation.steps.last.bucket, 1);
      expect(explanation.steps.last.hasSelectedDelay, isTrue);
      expect(explanation.steps.first.hasSelectedDelay, isFalse);
      expect(explanation.complete, isTrue);

      final match = CoreRuleMatchResult.fromJson({
        'mode': 'rule',
        'matched': true,
        'ruleScope': 'default',
        'ruleIndex': 0,
        'ruleType': 'Domain',
        'payload': 'example.com',
        'target': 'Proxy',
        'policyChain': ['Proxy', 'Balance', 'HK-01'],
        'complete': true,
      }).copyWith(policyExplanation: explanation);

      expect(match.policyExplanation, same(explanation));
      expect(match.finalPolicy, 'HK-01');
    },
  );

  test('keeps hidden load-balance state explicit', () {
    final explanation = CorePolicyExplanation.fromJson({
      'target': 'Balance',
      'policyChain': ['Balance', 'JP-01'],
      'steps': [
        {
          'name': 'Balance',
          'type': 'LoadBalance',
          'selected': 'JP-01',
          'reason': 'sticky-session-cache',
          'strategy': 'sticky-sessions',
          'key': '10.0.0.2example.com',
          'keySource': 'source-ip+etld+1',
          'candidateCount': 3,
          'selectedIndex': 1,
          'bucket': -1,
          'retry': -1,
          'complete': false,
        },
      ],
      'complete': false,
      'warnings': ['policy-strategy-state-hidden'],
    });

    expect(explanation.complete, isFalse);
    expect(explanation.warnings, ['policy-strategy-state-hidden']);
    expect(explanation.steps.single.reason, 'sticky-session-cache');
    expect(explanation.steps.single.key, '10.0.0.2example.com');
    expect(explanation.steps.single.hasSelectedDelay, isFalse);
  });

  test('keeps limitations explicit when metadata is incomplete', () {
    final result = CoreRuleMatchResult.fromJson({
      'mode': 'rule',
      'matched': false,
      'ruleIndex': -1,
      'target': 'DIRECT',
      'complete': false,
      'warnings': ['missing-inbound-name', 'sub-rule-target-unavailable'],
    });

    expect(result.matched, isFalse);
    expect(result.ruleScope, isEmpty);
    expect(result.ruleText, isEmpty);
    expect(result.target, 'DIRECT');
    expect(result.policyChain, isEmpty);
    expect(result.ruleTrace, isEmpty);
    expect(result.finalPolicy, 'DIRECT');
    expect(result.providerNames, isEmpty);
    expect(result.complete, isFalse);
    expect(result.warnings, [
      'missing-inbound-name',
      'sub-rule-target-unavailable',
    ]);
  });

  test('ignores malformed trace entries without dropping the result', () {
    final result = CoreRuleMatchResult.fromJson({
      'mode': 'rule',
      'matched': true,
      'ruleScope': 'default',
      'ruleIndex': 0,
      'ruleType': 'Match',
      'target': 'DIRECT',
      'ruleTrace': [
        'invalid',
        {
          'ruleScope': 'default',
          'ruleIndex': 0,
          'ruleType': 'Match',
          'target': 'DIRECT',
          'outcome': 'final',
        },
      ],
      'complete': true,
    });

    expect(result.ruleTrace, hasLength(1));
    expect(result.ruleTrace.single.target, 'DIRECT');
    expect(result.ruleTrace.single.policyChain, isEmpty);
  });

  test('serializes and parses the rule diagnostic protocol methods', () {
    const matchCall = CoreMethodCall(
      id: 'request-1',
      method: CoreMethod.matchRule,
      arguments: {'network': 'tcp', 'host': 'example.com'},
    );
    const explainCall = CoreMethodCall(
      id: 'request-2',
      method: CoreMethod.explainPolicy,
      arguments: {
        'target': 'Proxy',
        'policyChain': ['Proxy', 'HK-01'],
      },
    );

    expect(matchCall.toJson(), {
      'id': 'request-1',
      'method': 'matchRule',
      'arguments': {'network': 'tcp', 'host': 'example.com'},
    });
    expect(explainCall.toJson(), {
      'id': 'request-2',
      'method': 'explainPolicy',
      'arguments': {
        'target': 'Proxy',
        'policyChain': ['Proxy', 'HK-01'],
      },
    });
    expect(
      CoreMethodCall.fromJson(matchCall.toJson()).method,
      CoreMethod.matchRule,
    );
    expect(
      CoreMethodCall.fromJson(explainCall.toJson()).method,
      CoreMethod.explainPolicy,
    );
  });
}
