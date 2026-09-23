part of '../quick_routing.dart';

typedef _QuickRoutingUndo = Future<bool> Function();

class _QuickRoutingApplyResult {
  final Rule rule;
  final _QuickRoutingUndo undo;
  final QuickRoutingGroupOverride? groupOverride;

  const _QuickRoutingApplyResult({
    required this.rule,
    required this.undo,
    this.groupOverride,
  });
}

String _quickRoutingLifetimeLabel(
  BuildContext context,
  QuickRoutingLifetime lifetime,
) {
  final appLocalizations = context.appLocalizations;
  return switch (lifetime) {
    QuickRoutingLifetime.session => appLocalizations.start,
    QuickRoutingLifetime.tenMinutes => '10m',
    QuickRoutingLifetime.oneHour => '1h',
    QuickRoutingLifetime.network => appLocalizations.network,
    QuickRoutingLifetime.permanent => appLocalizations.save,
  };
}

String _trackerRuleText(TrackerInfo trackerInfo) {
  final payload = trackerInfo.rulePayload.trim();
  if (payload.isEmpty) {
    return trackerInfo.rule;
  }
  return '${trackerInfo.rule}($payload)';
}

void _ensureQuickRoutingRuleIsValid(
  QuickRoutingCandidate candidate,
  String target,
) {
  final validation = validateQuickRoutingSelection(
    candidate: candidate,
    target: target,
  );
  if (!validation.isValid) {
    throw StateError(
      'Invalid quick routing rule: '
      '${validation.issues.map((issue) => issue.name).join(', ')}',
    );
  }
}

Future<List<Rule>> _readPermanentRules(
  int profileId,
  OverwriteType overwriteType,
) {
  return switch (overwriteType) {
    OverwriteType.standard =>
      database.rulesDao.queryProfileAddedRules(profileId).get(),
    OverwriteType.custom =>
      database.rulesDao.queryProfileCustomRules(profileId).get(),
    OverwriteType.script => Future<List<Rule>>.error(
      StateError('Script overwrite does not support permanent quick rules'),
    ),
  };
}

Rule? _findExistingQuickRoutingRule(
  List<Rule> rules,
  QuickRoutingCandidate candidate,
) {
  for (final rule in rules) {
    if (rule.ruleAction == candidate.ruleAction &&
        rule.content == candidate.content &&
        rule.noResolve == candidate.noResolve &&
        !rule.src) {
      return rule;
    }
  }
  return null;
}

Rule? _findRuleById(List<Rule> rules, int ruleId) {
  for (final rule in rules) {
    if (rule.id == ruleId) {
      return rule;
    }
  }
  return null;
}

Future<void> _writePermanentQuickRoutingRule(
  int profileId,
  OverwriteType overwriteType,
  Rule rule,
) async {
  switch (overwriteType) {
    case OverwriteType.standard:
      await database.rulesDao.putProfileAddedRule(profileId, rule);
      return;
    case OverwriteType.custom:
      await database.rulesDao.putProfileCustomRule(profileId, rule);
      return;
    case OverwriteType.script:
      throw StateError(
        'Script overwrite does not support permanent quick rules',
      );
  }
}

void _invalidatePermanentQuickRoutingState(
  WidgetRef ref,
  int profileId,
  OverwriteType overwriteType,
) {
  ref.invalidate(setupStateProvider(profileId));
  switch (overwriteType) {
    case OverwriteType.standard:
      ref.invalidate(profileAddedRulesProvider(profileId));
      return;
    case OverwriteType.custom:
      ref.invalidate(profileCustomRulesProvider(profileId));
      return;
    case OverwriteType.script:
      return;
  }
}

Future<void> _rollbackPermanentQuickRoutingRule({
  required WidgetRef ref,
  required int profileId,
  required OverwriteType overwriteType,
  required Rule rule,
  required Rule? previous,
}) async {
  try {
    if (previous != null) {
      await _writePermanentQuickRoutingRule(
        profileId,
        overwriteType,
        previous,
      );
    } else {
      await database.rulesDao.delRules([rule.id]);
    }
    _invalidatePermanentQuickRoutingState(
      ref,
      profileId,
      overwriteType,
    );
    await ref
        .read(setupActionProvider.notifier)
        .applyProfile(force: true, silence: true);
  } catch (error, stackTrace) {
    commonPrint.log(
      'quick routing permanent rollback failed: '
      '${compactError(error)}, $stackTrace',
      logLevel: LogLevel.error,
    );
  }
}

Future<bool> _undoPermanentQuickRoutingRule({
  required WidgetRef ref,
  required int profileId,
  required OverwriteType overwriteType,
  required Rule appliedRule,
  required Rule? previous,
}) async {
  final rules = await _readPermanentRules(profileId, overwriteType);
  final current = _findRuleById(rules, appliedRule.id);
  if (current != appliedRule) {
    return false;
  }

  var restored = false;
  try {
    if (previous != null) {
      await _writePermanentQuickRoutingRule(
        profileId,
        overwriteType,
        previous,
      );
    } else {
      await database.rulesDao.delRules([appliedRule.id]);
    }
    restored = true;
    _invalidatePermanentQuickRoutingState(ref, profileId, overwriteType);
    final applied = await ref
        .read(setupActionProvider.notifier)
        .applyProfile(force: true);
    if (!applied) {
      throw StateError('Failed to undo permanent quick routing rule');
    }
    return true;
  } catch (error, stackTrace) {
    if (restored) {
      try {
        await _writePermanentQuickRoutingRule(
          profileId,
          overwriteType,
          appliedRule,
        );
        _invalidatePermanentQuickRoutingState(
          ref,
          profileId,
          overwriteType,
        );
        await ref
            .read(setupActionProvider.notifier)
            .applyProfile(force: true, silence: true);
      } catch (rollbackError, rollbackStackTrace) {
        commonPrint.log(
          'quick routing permanent undo rollback failed: '
          '${compactError(rollbackError)}, $rollbackStackTrace',
          logLevel: LogLevel.error,
        );
      }
    }
    Error.throwWithStackTrace(error, stackTrace);
  }
}

Future<_QuickRoutingApplyResult> _saveAndApplyPermanentQuickRoutingRule({
  required WidgetRef ref,
  required int profileId,
  required OverwriteType overwriteType,
  required QuickRoutingCandidate candidate,
  required String target,
}) async {
  _ensureQuickRoutingRuleIsValid(candidate, target);
  final rules = await _readPermanentRules(profileId, overwriteType);
  final previous = _findExistingQuickRoutingRule(rules, candidate);
  var rule = candidate.buildRule(
    target: target,
    id: previous?.id ?? snowflake.id,
    order: previous?.order,
  );
  if (previous == null) {
    rule = rule.autoOrder(
      rule,
      null,
      rules.isEmpty ? null : rules.first.order,
    );
  }

  var persisted = false;
  try {
    await _writePermanentQuickRoutingRule(profileId, overwriteType, rule);
    persisted = true;
    _invalidatePermanentQuickRoutingState(ref, profileId, overwriteType);
    final applied = await ref
        .read(setupActionProvider.notifier)
        .applyProfile(force: true);
    if (!applied) {
      throw StateError('Failed to apply permanent quick routing rule');
    }
    final appliedRule = rule;
    return _QuickRoutingApplyResult(
      rule: appliedRule,
      undo: () => _undoPermanentQuickRoutingRule(
        ref: ref,
        profileId: profileId,
        overwriteType: overwriteType,
        appliedRule: appliedRule,
        previous: previous,
      ),
    );
  } catch (error, stackTrace) {
    if (persisted) {
      await _rollbackPermanentQuickRoutingRule(
        ref: ref,
        profileId: profileId,
        overwriteType: overwriteType,
        rule: rule,
        previous: previous,
      );
    }
    Error.throwWithStackTrace(error, stackTrace);
  }
}

Future<bool> _undoRuntimeQuickRoutingRule({
  required WidgetRef ref,
  required List<QuickRoutingRuleEntry> expected,
  required List<QuickRoutingRuleEntry> previous,
}) async {
  final notifier = ref.read(quickRoutingRulesProvider.notifier);
  final restored = notifier.replaceAllIfCurrent(
    expected: expected,
    entries: previous,
  );
  if (restored == null) {
    return false;
  }
  try {
    final applied = await ref
        .read(setupActionProvider.notifier)
        .applyProfile(force: true);
    if (!applied) {
      throw StateError('Failed to undo runtime quick routing rule');
    }
    return true;
  } catch (error, stackTrace) {
    final rolledBack = notifier.replaceAllIfCurrent(
      expected: restored,
      entries: expected,
    );
    if (rolledBack != null) {
      try {
        await ref
            .read(setupActionProvider.notifier)
            .applyProfile(force: true, silence: true);
      } catch (rollbackError, rollbackStackTrace) {
        commonPrint.log(
          'quick routing runtime undo rollback failed: '
          '${compactError(rollbackError)}, $rollbackStackTrace',
          logLevel: LogLevel.error,
        );
      }
    }
    Error.throwWithStackTrace(error, stackTrace);
  }
}

Future<_QuickRoutingApplyResult> _saveAndApplyRuntimeQuickRoutingRule({
  required WidgetRef ref,
  required int profileId,
  required QuickRoutingSelection selection,
  required TrackerInfo trackerInfo,
}) async {
  _ensureQuickRoutingRuleIsValid(selection.candidate, selection.target);
  final snapshot = ref.read(quickRoutingRulesProvider);
  final notifier = ref.read(quickRoutingRulesProvider.notifier);
  final entry = notifier.put(
    profileId: profileId,
    rule: selection.candidate.buildRule(
      target: selection.target,
      id: snowflake.id,
    ),
    lifetime: selection.lifetime,
    sourceId: trackerInfo.id,
    sourceDesc: trackerInfo.desc,
    previousRule: _trackerRuleText(trackerInfo),
    previousChains: trackerInfo.chains,
    groupOverride: selection.groupOverride,
  );
  final appliedState = ref.read(quickRoutingRulesProvider);
  try {
    final applied = await ref
        .read(setupActionProvider.notifier)
        .applyProfile(force: true);
    if (!applied) {
      throw StateError('Failed to apply runtime quick routing rule');
    }
    return _QuickRoutingApplyResult(
      rule: entry.rule,
      groupOverride: entry.groupOverride,
      undo: () => _undoRuntimeQuickRoutingRule(
        ref: ref,
        expected: appliedState,
        previous: snapshot,
      ),
    );
  } catch (error, stackTrace) {
    notifier.replaceAll(snapshot);
    try {
      await ref
          .read(setupActionProvider.notifier)
          .applyProfile(force: true, silence: true);
    } catch (rollbackError, rollbackStackTrace) {
      commonPrint.log(
        'quick routing runtime rollback failed: '
        '${compactError(rollbackError)}, $rollbackStackTrace',
        logLevel: LogLevel.error,
      );
    }
    Error.throwWithStackTrace(error, stackTrace);
  }
}

Future<void> _setQuickRoutingGroupFixedState({
  required WidgetRef ref,
  required String groupName,
  required String fixedProxy,
}) async {
  final message = await ref.read(coreHandlerProvider).changeProxy(
        ChangeProxyParams(
          groupName: groupName,
          proxyName: fixedProxy,
        ),
      );
  if (message.isNotEmpty) {
    throw MessageException(message);
  }
  await ref.read(proxiesActionProvider.notifier).updateGroups();
}

Future<bool> _undoQuickRoutingGroupOverride({
  required WidgetRef ref,
  required _QuickRoutingApplyResult baseResult,
  required QuickRoutingGroupOverride override,
}) async {
  final current = await ref
      .read(coreHandlerProvider)
      .getProxyGroupFixedStates();
  if (current[override.groupName] != override.desiredFixed) {
    return false;
  }

  var restoredGroup = false;
  try {
    await _setQuickRoutingGroupFixedState(
      ref: ref,
      groupName: override.groupName,
      fixedProxy: override.expectedFixed,
    );
    restoredGroup = true;
    final undoneRule = await baseResult.undo();
    if (undoneRule) {
      return true;
    }
    await _setQuickRoutingGroupFixedState(
      ref: ref,
      groupName: override.groupName,
      fixedProxy: override.desiredFixed,
    );
    return false;
  } catch (error, stackTrace) {
    if (restoredGroup) {
      try {
        await _setQuickRoutingGroupFixedState(
          ref: ref,
          groupName: override.groupName,
          fixedProxy: override.desiredFixed,
        );
      } catch (rollbackError, rollbackStackTrace) {
        commonPrint.log(
          'quick routing group override undo rollback failed: '
          '${compactError(rollbackError)}, $rollbackStackTrace',
          logLevel: LogLevel.error,
        );
      }
    }
    Error.throwWithStackTrace(error, stackTrace);
  }
}

Future<_QuickRoutingApplyResult> _applyQuickRoutingGroupOverride({
  required WidgetRef ref,
  required _QuickRoutingApplyResult baseResult,
  required QuickRoutingSelection selection,
}) async {
  final override = baseResult.groupOverride ?? selection.groupOverride;
  if (override == null) {
    return baseResult;
  }
  if (!selection.lifetime.isRuntime) {
    final undone = await baseResult.undo();
    if (!undone) {
      commonPrint.log(
        'permanent quick routing group override could not undo its rule',
        logLevel: LogLevel.error,
      );
    }
    throw StateError('Automatic group overrides require a runtime lifetime');
  }
  final validation = validateQuickRoutingSelection(
    candidate: selection.candidate,
    target: selection.target,
    groupOverride: override,
    groups: ref.read(groupsProvider),
  );
  if (!validation.isValid) {
    final undone = await baseResult.undo();
    if (!undone) {
      commonPrint.log(
        'invalid quick routing group override could not undo its rule',
        logLevel: LogLevel.error,
      );
    }
    throw StateError(
      'Invalid quick routing group override: '
      '${validation.issues.map((issue) => issue.name).join(', ')}',
    );
  }

  try {
    final current = await ref
        .read(coreHandlerProvider)
        .getProxyGroupFixedStates();
    final currentFixed = current[override.groupName];
    if (currentFixed == null) {
      throw StateError('Automatic group no longer exposes fixed state');
    }
    if (currentFixed != override.expectedFixed &&
        currentFixed != override.desiredFixed) {
      throw StateError('Automatic group fixed state changed while editing');
    }
    if (currentFixed != override.desiredFixed) {
      await _setQuickRoutingGroupFixedState(
        ref: ref,
        groupName: override.groupName,
        fixedProxy: override.desiredFixed,
      );
    }
  } catch (error, stackTrace) {
    try {
      final undone = await baseResult.undo();
      if (!undone) {
        commonPrint.log(
          'quick routing group override failure left a stale rule',
          logLevel: LogLevel.error,
        );
      }
    } catch (rollbackError, rollbackStackTrace) {
      commonPrint.log(
        'quick routing group override rule rollback failed: '
        '${compactError(rollbackError)}, $rollbackStackTrace',
        logLevel: LogLevel.error,
      );
    }
    Error.throwWithStackTrace(error, stackTrace);
  }

  return _QuickRoutingApplyResult(
    rule: baseResult.rule,
    groupOverride: override,
    undo: () => _undoQuickRoutingGroupOverride(
      ref: ref,
      baseResult: baseResult,
      override: override,
    ),
  );
}

typedef _RuntimeQuickRoutingMutation = bool Function(
  QuickRoutingRules notifier,
);

Future<bool> _applyRuntimeQuickRoutingMutation({
  required WidgetRef ref,
  required _RuntimeQuickRoutingMutation mutation,
}) async {
  final snapshot = ref.read(quickRoutingRulesProvider);
  final notifier = ref.read(quickRoutingRulesProvider.notifier);
  final changed = mutation(notifier);
  if (!changed) {
    return false;
  }
  try {
    final applied = await ref
        .read(setupActionProvider.notifier)
        .applyProfile(force: true);
    if (!applied) {
      throw StateError('Failed to apply runtime quick routing mutation');
    }
    return true;
  } catch (error, stackTrace) {
    notifier.replaceAll(snapshot);
    try {
      await ref
          .read(setupActionProvider.notifier)
          .applyProfile(force: true, silence: true);
    } catch (rollbackError, rollbackStackTrace) {
      commonPrint.log(
        'quick routing mutation rollback failed: '
        '${compactError(rollbackError)}, $rollbackStackTrace',
        logLevel: LogLevel.error,
      );
    }
    Error.throwWithStackTrace(error, stackTrace);
  }
}
