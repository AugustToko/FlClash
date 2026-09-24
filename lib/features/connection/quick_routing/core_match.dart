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
    'policy-chain-unresolved' =>
      '${appLocalizations.unknown}: ${appLocalizations.proxyChains}',
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

List<Widget> _buildCoreQuickRoutingMatchPreview(
  BuildContext context,
  CoreRuleMatchResult result,
) {
  final appLocalizations = context.appLocalizations;
  final marker = result.complete ? '✓' : '≈';
  final ruleIndex = result.ruleIndex >= 0 ? '#${result.ruleIndex + 1} ' : '';
  final scope = result.ruleScope.isEmpty
      ? ''
      : '[${_quickRoutingCoreRuleScopeLabel(context, result.ruleScope)}] ';
  final summary = result.matched
      ? '$scope$ruleIndex${result.ruleText} → ${result.target}'
      : '${result.mode.toUpperCase()} → ${result.target}';
  return [
    Text('$marker ${appLocalizations.core}: $summary'),
    if (result.policyChain.isNotEmpty)
      Text(
        '${appLocalizations.proxyChains}: ${result.policyText}',
        maxLines: 2,
        overflow: TextOverflow.ellipsis,
      ),
    ..._buildCoreQuickRoutingTrace(context, result),
    if (result.providerNames.isNotEmpty)
      Text(
        '${appLocalizations.providers}: '
        '${result.providerNames.join(', ')}',
        maxLines: 2,
        overflow: TextOverflow.ellipsis,
      ),
    if (result.resolvedIP.isNotEmpty) Text('IP: ${result.resolvedIP}'),
    if (result.warnings.isNotEmpty)
      Text(
        result.warnings
            .map((warning) => _quickRoutingCoreWarningLabel(context, warning))
            .join(' · '),
        maxLines: 3,
        overflow: TextOverflow.ellipsis,
        style: context.textTheme.bodySmall?.copyWith(
          color: context.colorScheme.tertiary,
        ),
      ),
  ];
}
