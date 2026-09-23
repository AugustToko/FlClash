part of '../quick_routing.dart';

@immutable
class QuickRoutingCandidate {
  final RuleAction ruleAction;
  final String content;
  final bool noResolve;

  const QuickRoutingCandidate({
    required this.ruleAction,
    required this.content,
    this.noResolve = false,
  });

  String get label => '${ruleAction.value} · $content';

  Rule buildRule({required String target, required int id, String? order}) {
    return Rule(
      id: id,
      ruleAction: ruleAction,
      content: content,
      ruleTarget: target,
      noResolve: noResolve,
      order: order,
    );
  }
}

@immutable
class QuickRoutingImpact {
  final int requestCount;
  final List<String> hosts;
  final List<String> processes;

  const QuickRoutingImpact({
    required this.requestCount,
    required this.hosts,
    required this.processes,
  });
}

@immutable
class QuickRoutingRuleAnalysis {
  final Rule? equivalentRule;
  final int matchingKnownRuleCount;
  final bool targetAlreadyInChain;

  const QuickRoutingRuleAnalysis({
    required this.equivalentRule,
    required this.matchingKnownRuleCount,
    required this.targetAlreadyInChain,
  });

  bool get replacesEquivalentRule =>
      equivalentRule != null && equivalentRule!.ruleTarget != null;

  bool targetMatchesEquivalentRule(String target) =>
      equivalentRule?.ruleTarget == target;
}

@immutable
class QuickRoutingSelection {
  final QuickRoutingCandidate candidate;
  final String target;
  final QuickRoutingLifetime lifetime;

  const QuickRoutingSelection({
    required this.candidate,
    required this.target,
    required this.lifetime,
  });
}

extension _QuickRoutingApplyResultExt on _QuickRoutingApplyResult {
  String get rawValue => rule.rawValue;
}
