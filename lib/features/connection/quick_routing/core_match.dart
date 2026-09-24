part of '../quick_routing.dart';

class QuickRoutingPolicyChainPreview {
  final List<String> nodes;
  final bool complete;
  final bool automatic;

  QuickRoutingPolicyChainPreview({
    required Iterable<String> nodes,
    required this.complete,
    this.automatic = false,
  }) : nodes = List.unmodifiable(nodes);

  List<String> displayNodes(String automaticLabel) {
    return List.unmodifiable([
      ...nodes,
      if (automatic) automaticLabel,
    ]);
  }
}

List<String> normalizeQuickRoutingHistoricalPolicyChain(
  Iterable<String> values,
) {
  final nodes = values
      .map((value) => value.trim())
      .where((value) => value.isNotEmpty)
      .toList(growable: false);
  return List.unmodifiable(nodes.reversed);
}

QuickRoutingPolicyChainPreview buildQuickRoutingPolicyChainPreview({
  required String target,
  required Iterable<Group> groups,
  Map<String, String> fixedStates = const {},
  QuickRoutingGroupOverride? groupOverride,
}) {
  final groupsByName = <String, Group>{
    for (final group in groups) group.name: group,
  };
  final nodes = <String>[];
  final visited = <String>{};
  var current = target.trim();

  for (var depth = 0; current.isNotEmpty && depth < 32; depth++) {
    if (!visited.add(current)) {
      return QuickRoutingPolicyChainPreview(
        nodes: nodes,
        complete: false,
      );
    }
    nodes.add(current);
    final group = groupsByName[current];
    if (group == null) {
      return QuickRoutingPolicyChainPreview(
        nodes: nodes,
        complete: true,
      );
    }
    if (group.type == GroupType.LoadBalance ||
        group.type == GroupType.Relay) {
      return QuickRoutingPolicyChainPreview(
        nodes: nodes,
        complete: false,
      );
    }

    final override = groupOverride != null &&
            groupOverride.groupName == group.name &&
            groupOverride.changes
        ? groupOverride
        : null;
    if (override != null) {
      final desired = override.desiredFixed.trim();
      if (desired.isEmpty) {
        return QuickRoutingPolicyChainPreview(
          nodes: nodes,
          complete: false,
          automatic: true,
        );
      }
      current = desired;
      continue;
    }

    if (group.type.isComputedSelected) {
      if (!fixedStates.containsKey(group.name)) {
        return QuickRoutingPolicyChainPreview(
          nodes: nodes,
          complete: false,
        );
      }
      final fixed = fixedStates[group.name]?.trim() ?? '';
      if (fixed.isEmpty) {
        return QuickRoutingPolicyChainPreview(
          nodes: nodes,
          complete: false,
          automatic: true,
        );
      }
      current = fixed;
      continue;
    }

    current = group.now?.trim() ?? '';
    if (current.isEmpty) {
      return QuickRoutingPolicyChainPreview(
        nodes: nodes,
        complete: false,
      );
    }
  }

  return QuickRoutingPolicyChainPreview(
    nodes: nodes,
    complete: false,
  );
}

Future<CoreRuleMatchResult?> _readCoreQuickRoutingMatch(
  WidgetRef ref,
  TrackerInfo trackerInfo,
) async {
  if (ref.read(coreStatusProvider) != CoreStatus.connected) {
    return null;
  }
  try {
    return await ref.read(coreHandlerProvider).matchRule(trackerInfo.metadata);
  } catch (error, stackTrace) {
    commonPrint.log(
      'quick routing core match unavailable: '
      '${compactError(error)}, $stackTrace',
      logLevel: LogLevel.warning,
    );
    return null;
  }
}

String _quickRoutingCoreWarningLabel(
  BuildContext context,
  String warning,
) {
  final appLocalizations = context.appLocalizations;
  return switch (warning) {
    'missing-inbound-port' =>
      '${appLocalizations.unknown}: IN-PORT',
    'missing-inbound-name' =>
      '${appLocalizations.unknown}: IN-NAME',
    'missing-inbound-user' =>
      '${appLocalizations.unknown}: IN-USER',
    'missing-inbound-type' =>
      '${appLocalizations.unknown}: IN-TYPE',
    'missing-dscp' => '${appLocalizations.unknown}: DSCP',
    'sub-rule-context-unavailable' ||
    'special-rules-not-expanded' ||
    'sub-rule-target-unavailable' =>
      '${appLocalizations.unknown}: SUB-RULE',
    'compound-rule-context-partial' =>
      '${appLocalizations.unknown}: AND / OR / NOT',
    'process-lookup-source-unavailable' ||
    'process-lookup-failed' =>
      '${appLocalizations.unknown}: ${appLocalizations.application}',
    'dns-resolution-failed' =>
      '${appLocalizations.unknown}: DNS',
    'matched-target-unavailable' =>
      '${appLocalizations.unknown}: ${appLocalizations.ruleTarget}',
    'rematch-target-not-expanded' ||
    'rematch-cycle' ||
    'rematch-chain-truncated' ||
    'rematch-metadata-update-failed' =>
      '${appLocalizations.unknown}: REMATCH',
    'policy-chain-cycle' ||
    'policy-chain-truncated' ||
    'policy-chain-unresolved' ||
    'policy-chain-target-mismatch' ||
    'policy-chain-invalid-continuation' =>
      '${appLocalizations.unknown}: ${appLocalizations.proxyChains}',
    'policy-target-empty' ||
    'policy-proxy-unavailable' ||
    'policy-chain-member-unavailable' =>
      '${appLocalizations.unknown}: ${appLocalizations.ruleTarget}',
    'policy-config-unavailable' =>
      '${appLocalizations.unknown}: ${appLocalizations.proxyGroup} config',
    'policy-selection-state-changed' =>
      '${appLocalizations.unknown}: ${appLocalizations.status} changed',
    'policy-strategy-state-hidden' =>
      '${appLocalizations.unknown}: runtime strategy state',
    'legacy-relay-unavailable' =>
      '${appLocalizations.unknown}: legacy Relay',
    _ => warning,
  };
}

String _quickRoutingCoreRuleScopeLabel(
  BuildContext context,
  String scope,
) {
  if (scope == 'default') {
    return context.appLocalizations.defaultText;
  }
  return scope;
}

String _quickRoutingCoreTraceMarker(String outcome) {
  return switch (outcome) {
    'final' => '✓',
    'rematch' => '↻',
    'pass' => '↪',
    _ => '≈',
  };
}

String _quickRoutingCoreTraceOutcomeLabel(String outcome) {
  return switch (outcome) {
    'final' => '',
    'rematch' => 'REMATCH',
    'pass' => 'PASS',
    'udp-unsupported' => 'UDP ×',
    'target-unavailable' => 'TARGET ?',
    'rematch-cycle' => 'REMATCH CYCLE',
    'rematch-truncated' => 'REMATCH LIMIT',
    'rematch-error' => 'REMATCH ERROR',
    _ => outcome.toUpperCase(),
  };
}

String _quickRoutingCoreTraceText(
  BuildContext context,
  CoreRuleMatchTraceStep step,
) {
  final marker = _quickRoutingCoreTraceMarker(step.outcome);
  final scope = _quickRoutingCoreRuleScopeLabel(context, step.ruleScope);
  final index = step.ruleIndex >= 0 ? '#${step.ruleIndex + 1} ' : '';
  final outcome = _quickRoutingCoreTraceOutcomeLabel(step.outcome);
  final outcomeSuffix = outcome.isEmpty ? '' : ' · $outcome';
  return '$marker [$scope] $index${step.ruleText} → '
      '${step.target}$outcomeSuffix';
}

String _quickRoutingCoreRematchTransition(
  CoreRuleMatchTraceStep step,
) {
  final values = <String>[
    if (step.rematchName.isNotEmpty)
      'REMATCH-NAME=${step.rematchName}',
    if (step.subRule.isNotEmpty) 'SUB-RULE=${step.subRule}',
  ];
  return values.join(' · ');
}

List<Widget> _buildCoreQuickRoutingTrace(
  BuildContext context,
  CoreRuleMatchResult result,
) {
  final appLocalizations = context.appLocalizations;
  final shouldShow = result.ruleTrace.length > 1 ||
      result.ruleTrace.any((step) => step.outcome != 'final');
  if (!shouldShow) {
    return const [];
  }

  return [
    const SizedBox(height: 6),
    Text(
      appLocalizations.rules,
      style: context.textTheme.bodySmall,
    ),
    for (final step in result.ruleTrace) ...[
      Text(
        _quickRoutingCoreTraceText(context, step),
        maxLines: 2,
        overflow: TextOverflow.ellipsis,
      ),
      if (step.policyChain.length > 1)
        Text(
          '  ${appLocalizations.proxyChains}: ${step.policyText}',
          maxLines: 2,
          overflow: TextOverflow.ellipsis,
          style: context.textTheme.bodySmall,
        ),
      if (step.outcome.startsWith('rematch') &&
          (step.rematchName.isNotEmpty || step.subRule.isNotEmpty))
        Text(
          '  ↳ ${_quickRoutingCoreRematchTransition(step)}',
          maxLines: 2,
          overflow: TextOverflow.ellipsis,
          style: context.textTheme.bodySmall,
        ),
    ],
  ];
}

String _quickRoutingPolicyReasonLabel(
  BuildContext context,
  CorePolicyExplainStep step,
) {
  final appLocalizations = context.appLocalizations;
  return switch (step.reason) {
    'leaf' => appLocalizations.selected,
    'manual-selection' => appLocalizations.selected,
    'manual-selection-state-changed' =>
      '${appLocalizations.selected} · state changed',
    'fixed-selection' => '${appLocalizations.selected} · FIXED',
    'fixed-unavailable-fallback' => 'FIXED unavailable · fallback',
    'first-alive' => 'first alive',
    'no-alive-first-member' => 'no alive · first member',
    'lowest-delay' => 'lowest delay',
    'tolerance-hold' => 'tolerance hold',
    'cached-selection-state-changed' => 'cached selection · state changed',
    'consistent-hash' => 'consistent-hashing',
    'consistent-hash-state-changed' =>
      'consistent-hashing · state changed',
    'round-robin-current-cursor' => 'round-robin · current cursor',
    'sticky-session-cache' => 'sticky-sessions · cache',
    'load-balance-config-unavailable' => 'load-balance · config unavailable',
    'selected-member-unavailable' => 'member unavailable',
    'proxy-unavailable' => 'proxy unavailable',
    'non-group-chain-continuation' => 'invalid continuation',
    'legacy-relay-unavailable' => 'legacy Relay unavailable',
    'unsupported-policy-group' => 'unsupported group',
    _ => step.reason,
  };
}

List<String> _quickRoutingPolicyStepDetails(
  CorePolicyExplainStep step,
) {
  return [
    if (step.strategy.isNotEmpty) step.strategy,
    if (step.selectedIndex >= 0 && step.candidateCount > 0)
      '${step.selectedIndex + 1}/${step.candidateCount}',
    if (step.key.isNotEmpty) '${step.keySource}: ${step.key}',
    if (step.bucket >= 0) 'bucket ${step.bucket + 1}',
    if (step.retry > 0) 'retry ${step.retry}',
    if (step.hasSelectedDelay) '${step.selectedDelay} ms',
    if (step.hasFastestDelay && step.fastest != step.selected)
      'fastest ${step.fastest} ${step.fastestDelay} ms',
    if (step.tolerance > 0) 'tolerance ${step.tolerance} ms',
    if (step.healthKnown) step.selectedAlive ? 'alive' : 'dead',
  ];
}

List<Widget> _buildCorePolicyExplanation(
  BuildContext context,
  CoreRuleMatchResult result,
) {
  final explanation = result.policyExplanation;
  if (explanation == null) {
    return const [];
  }
  final groupSteps = explanation.steps
      .where((step) => step.selected.isNotEmpty)
      .toList(growable: false);
  if (groupSteps.isEmpty) {
    return const [];
  }
  final appLocalizations = context.appLocalizations;
  return [
    const SizedBox(height: 6),
    Text(
      appLocalizations.proxyGroup,
      style: context.textTheme.bodySmall,
    ),
    for (final step in groupSteps) ...[
      Text(
        '${step.complete ? '✓' : '≈'} ${step.name} [${step.type}] '
        '→ ${step.selected} · '
        '${_quickRoutingPolicyReasonLabel(context, step)}',
        maxLines: 2,
        overflow: TextOverflow.ellipsis,
      ),
      if (_quickRoutingPolicyStepDetails(step).isNotEmpty)
        Text(
          '  ${_quickRoutingPolicyStepDetails(step).join(' · ')}',
          maxLines: 2,
          overflow: TextOverflow.ellipsis,
          style: context.textTheme.bodySmall,
        ),
    ],
  ];
}

List<Widget> _buildCoreQuickRoutingMatchPreview(
  BuildContext context,
  CoreRuleMatchResult result,
) {
  final appLocalizations = context.appLocalizations;
  final policyExplanation = result.policyExplanation;
  final isComplete =
      result.complete && (policyExplanation?.complete ?? true);
  final marker = isComplete ? '✓' : '≈';
  final ruleIndex = result.ruleIndex >= 0 ? '#${result.ruleIndex + 1} ' : '';
  final scope = result.ruleScope.isEmpty
      ? ''
      : '[${_quickRoutingCoreRuleScopeLabel(context, result.ruleScope)}] ';
  final summary = result.matched
      ? '$scope$ruleIndex${result.ruleText} → ${result.target}'
      : '${result.mode.toUpperCase()} → ${result.target}';
  final warningLabels = <String>{
    ...result.warnings,
    ...?policyExplanation?.warnings,
  }
      .map((warning) => _quickRoutingCoreWarningLabel(context, warning))
      .toSet()
      .toList(growable: false);
  return [
    Text('$marker ${appLocalizations.core}: $summary'),
    if (result.policyChain.isNotEmpty)
      Text(
        '${appLocalizations.proxyChains}: ${result.policyText}',
        maxLines: 2,
        overflow: TextOverflow.ellipsis,
      ),
    ..._buildCorePolicyExplanation(context, result),
    ..._buildCoreQuickRoutingTrace(context, result),
    if (result.providerNames.isNotEmpty)
      Text(
        '${appLocalizations.providers}: '
        '${result.providerNames.join(', ')}',
        maxLines: 2,
        overflow: TextOverflow.ellipsis,
      ),
    if (result.resolvedIP.isNotEmpty) Text('IP: ${result.resolvedIP}'),
    if (warningLabels.isNotEmpty)
      Text(
        warningLabels.join(' · '),
        maxLines: 3,
        overflow: TextOverflow.ellipsis,
        style: context.textTheme.bodySmall?.copyWith(
          color: context.colorScheme.tertiary,
        ),
      ),
  ];
}
