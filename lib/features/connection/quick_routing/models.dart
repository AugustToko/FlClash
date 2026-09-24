part of '../quick_routing.dart';

enum QuickRoutingGroupOverrideMode {
  unchanged,
  automatic,
  fixed,
}

enum QuickRoutingValidationIssue {
  emptyContent,
  emptyTarget,
  unsupportedAction,
  invalidDomain,
  invalidCidr,
  invalidPort,
  invalidUid,
  invalidNetwork,
  invalidAsn,
  invalidGroupOverride,
}

@immutable
class QuickRoutingCandidate {
  final RuleAction ruleAction;
  final String content;
  final bool noResolve;
  final String scopeHint;

  const QuickRoutingCandidate({
    required this.ruleAction,
    required this.content,
    this.noResolve = false,
    this.scopeHint = '',
  });

  String get label => [
        ruleAction.value,
        content,
        if (scopeHint.isNotEmpty) scopeHint,
      ].join(' · ');

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
  final Rule? firstKnownMatch;
  final int firstKnownMatchIndex;
  final int matchingKnownRuleCount;
  final int unknownKnownRuleCount;
  final int unknownRuleCountBeforeFirstMatch;
  final bool targetAlreadyInChain;

  const QuickRoutingRuleAnalysis({
    required this.equivalentRule,
    required this.firstKnownMatch,
    required this.firstKnownMatchIndex,
    required this.matchingKnownRuleCount,
    required this.unknownKnownRuleCount,
    required this.unknownRuleCountBeforeFirstMatch,
    required this.targetAlreadyInChain,
  });

  bool get replacesEquivalentRule =>
      equivalentRule != null && equivalentRule!.ruleTarget != null;

  bool targetMatchesEquivalentRule(String target) =>
      equivalentRule?.ruleTarget == target;

  bool get firstKnownMatchIsCertain =>
      firstKnownMatch != null && unknownRuleCountBeforeFirstMatch == 0;
}

@immutable
class QuickRoutingValidation {
  final List<QuickRoutingValidationIssue> issues;

  const QuickRoutingValidation({required this.issues});

  bool get isValid => issues.isEmpty;
}

@immutable
class QuickRoutingSelection {
  final QuickRoutingCandidate candidate;
  final String target;
  final QuickRoutingLifetime lifetime;
  final QuickRoutingGroupOverride? groupOverride;

  const QuickRoutingSelection({
    required this.candidate,
    required this.target,
    required this.lifetime,
    this.groupOverride,
  });
}
