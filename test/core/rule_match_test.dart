import 'package:fl_clash/core/controller.dart';
import 'package:fl_clash/core/method.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('parses a complete compiled rule match result', () {
    final result = CoreRuleMatchResult.fromJson({
      'mode': 'rule',
      'matched': true,
      'ruleIndex': 12,
      'ruleType': 'RuleSet',
      'payload': 'OpenAI',
      'target': 'Proxy',
      'policyChain': ['Proxy', 'Auto', 'HK-01'],
      'providerNames': ['OpenAI'],
      'resolvedIP': '1.1.1.1',
      'complete': true,
      'warnings': <String>[],
    });

    expect(result.mode, 'rule');
    expect(result.matched, isTrue);
    expect(result.ruleIndex, 12);
    expect(result.ruleText, 'RuleSet(OpenAI)');
    expect(result.target, 'Proxy');
    expect(result.policyChain, ['Proxy', 'Auto', 'HK-01']);
    expect(result.policyText, 'Proxy → Auto → HK-01');
    expect(result.finalPolicy, 'HK-01');
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
      'warnings': ['missing-inbound-name', 'sub-rule-context-unavailable'],
    });

    expect(result.matched, isFalse);
    expect(result.ruleText, isEmpty);
    expect(result.target, 'DIRECT');
    expect(result.policyChain, isEmpty);
    expect(result.finalPolicy, 'DIRECT');
    expect(result.providerNames, isEmpty);
    expect(result.complete, isFalse);
    expect(result.warnings, [
      'missing-inbound-name',
      'sub-rule-context-unavailable',
    ]);
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
