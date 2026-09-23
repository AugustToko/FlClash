part of '../quick_routing.dart';

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

Future<Rule> _saveAndApplyPermanentQuickRoutingRule({
  required WidgetRef ref,
  required int profileId,
  required OverwriteType overwriteType,
  required QuickRoutingCandidate candidate,
  required String target,
}) async {
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
    return rule;
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

Future<Rule> _saveAndApplyRuntimeQuickRoutingRule({
  required WidgetRef ref,
  required int profileId,
  required QuickRoutingSelection selection,
  required TrackerInfo trackerInfo,
}) async {
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
  );
  try {
    final applied = await ref
        .read(setupActionProvider.notifier)
        .applyProfile(force: true);
    if (!applied) {
      throw StateError('Failed to apply runtime quick routing rule');
    }
    return entry.rule;
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
