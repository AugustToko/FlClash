import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/features/features.dart';
import 'package:fl_clash/models/models.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  const rule = Rule(
    id: 10,
    ruleAction: RuleAction.DOMAIN,
    content: 'api.example.com',
    ruleTarget: 'DIRECT',
  );

  test('classifies runtime rules before permanent and read-only rules', () {
    expect(
      classifyQuickRoutingConflictSource(
        rule: rule,
        runtimeRules: const [rule],
        permanentRules: const [rule],
      ),
      QuickRoutingConflictSource.runtime,
    );
    expect(
      classifyQuickRoutingConflictSource(
        rule: rule,
        runtimeRules: const [],
        permanentRules: const [rule],
      ),
      QuickRoutingConflictSource.permanent,
    );
    expect(
      classifyQuickRoutingConflictSource(
        rule: rule,
        runtimeRules: const [],
        permanentRules: const [],
      ),
      QuickRoutingConflictSource.readOnly,
    );
  });

  test('does not identify a same-matcher rule with a different id', () {
    const other = Rule(
      id: 11,
      ruleAction: RuleAction.DOMAIN,
      content: 'api.example.com',
      ruleTarget: 'DIRECT',
    );

    expect(quickRoutingConflictRuleIdentityMatches(rule, other), isFalse);
    expect(
      classifyQuickRoutingConflictSource(
        rule: rule,
        runtimeRules: const [other],
        permanentRules: const [],
      ),
      QuickRoutingConflictSource.readOnly,
    );
  });

  test('allows simple persisted rules in standard and custom modes', () {
    for (final overwriteType in [
      OverwriteType.standard,
      OverwriteType.custom,
    ]) {
      expect(
        canEditQuickRoutingConflictRule(
          rule: rule,
          source: QuickRoutingConflictSource.permanent,
          overwriteType: overwriteType,
        ),
        isTrue,
      );
    }
  });

  test('keeps runtime, script and subscription rules out of direct editor', () {
    expect(
      canEditQuickRoutingConflictRule(
        rule: rule,
        source: QuickRoutingConflictSource.runtime,
        overwriteType: OverwriteType.standard,
      ),
      isFalse,
    );
    expect(
      canEditQuickRoutingConflictRule(
        rule: rule,
        source: QuickRoutingConflictSource.readOnly,
        overwriteType: OverwriteType.standard,
      ),
      isFalse,
    );
    expect(
      canEditQuickRoutingConflictRule(
        rule: rule,
        source: QuickRoutingConflictSource.permanent,
        overwriteType: OverwriteType.script,
      ),
      isFalse,
    );
  });

  test('keeps provider and sub-rule payloads in the dedicated editor', () {
    const ruleSet = Rule(
      id: 20,
      ruleAction: RuleAction.RULE_SET,
      ruleProvider: 'private',
      ruleTarget: 'Proxy',
    );
    const subRule = Rule(
      id: 21,
      ruleAction: RuleAction.SUB_RULE,
      subRule: 'special',
    );

    for (final candidate in [ruleSet, subRule]) {
      expect(
        canEditQuickRoutingConflictRule(
          rule: candidate,
          source: QuickRoutingConflictSource.permanent,
          overwriteType: OverwriteType.custom,
        ),
        isFalse,
      );
    }
  });

  test('requires both matcher content and target for direct editing', () {
    expect(
      canEditQuickRoutingConflictRule(
        rule: const Rule(
          id: 30,
          ruleAction: RuleAction.DOMAIN,
          content: '',
          ruleTarget: 'DIRECT',
        ),
        source: QuickRoutingConflictSource.permanent,
        overwriteType: OverwriteType.standard,
      ),
      isFalse,
    );
    expect(
      canEditQuickRoutingConflictRule(
        rule: const Rule(
          id: 31,
          ruleAction: RuleAction.DOMAIN,
          content: 'api.example.com',
          ruleTarget: '',
        ),
        source: QuickRoutingConflictSource.permanent,
        overwriteType: OverwriteType.standard,
      ),
      isFalse,
    );
  });
}
