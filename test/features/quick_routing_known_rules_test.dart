import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/features/features.dart';
import 'package:fl_clash/models/models.dart';
import 'package:test/test.dart';

void main() {
  Rule rule(int id, String content) {
    return Rule(
      id: id,
      ruleAction: RuleAction.DOMAIN,
      content: content,
      ruleTarget: 'DIRECT',
    );
  }

  final runtime = rule(1, 'runtime.example');
  final added = rule(2, 'added.example');
  final custom = rule(3, 'custom.example');
  final base = rule(4, 'base.example');

  test('standard explanation follows runtime, added and base order', () {
    expect(
      buildQuickRoutingKnownRules(
        overwriteType: OverwriteType.standard,
        runtimeRules: [runtime],
        baseRules: [base],
        addedRules: [added],
        customRules: [custom],
      ),
      [runtime, added, base],
    );
  });

  test('explicit custom rules replace base rules in explanation', () {
    expect(
      buildQuickRoutingKnownRules(
        overwriteType: OverwriteType.custom,
        runtimeRules: [runtime],
        baseRules: [base],
        addedRules: [added],
        customRules: [custom],
      ),
      [runtime, custom],
    );
  });

  test('empty custom rules preserve base rules', () {
    expect(
      buildQuickRoutingKnownRules(
        overwriteType: OverwriteType.custom,
        runtimeRules: [runtime],
        baseRules: [base],
        addedRules: [added],
        customRules: const [],
      ),
      [runtime, base],
    );
  });

  test('script explanation keeps runtime rules before the raw base', () {
    expect(
      buildQuickRoutingKnownRules(
        overwriteType: OverwriteType.script,
        runtimeRules: [runtime],
        baseRules: [base],
        addedRules: [added],
        customRules: [custom],
      ),
      [runtime, base],
    );
  });
}
