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
          'policyChain': [
            'REMATCH-TO-SECONDARY',
          ],
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

  test('serializes and parses the matchRule protocol method name', () {
    const call = CoreMethodCall(
      id: 'request-1',
      method: CoreMethod.matchRule,
      arguments: {'network': 'tcp', 'host': 'example.com'},
    );

    expect(call.toJson(), {
      'id': 'request-1',
      'method': 'matchRule',
      'arguments': {'network': 'tcp', 'host': 'example.com'},
    });
    expect(
      CoreMethodCall.fromJson(call.toJson()).method,
      CoreMethod.matchRule,
    );
  });
}
