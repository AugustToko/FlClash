part of '../quick_routing.dart';

enum QuickRoutingConflictSource { runtime, permanent, readOnly }

bool quickRoutingConflictRuleIdentityMatches(Rule first, Rule second) {
  return first.id == second.id &&
      quickRoutingRulesHaveSameMatcher(first, second);
}

QuickRoutingConflictSource classifyQuickRoutingConflictSource({
  required Rule rule,
  required Iterable<Rule> runtimeRules,
  required Iterable<Rule> permanentRules,
}) {
  if (runtimeRules.any(
    (candidate) => quickRoutingConflictRuleIdentityMatches(candidate, rule),
  )) {
    return QuickRoutingConflictSource.runtime;
  }
  if (permanentRules.any(
    (candidate) => quickRoutingConflictRuleIdentityMatches(candidate, rule),
  )) {
    return QuickRoutingConflictSource.permanent;
  }
  return QuickRoutingConflictSource.readOnly;
}

bool canEditQuickRoutingConflictRule({
  required Rule rule,
  required QuickRoutingConflictSource source,
  required OverwriteType overwriteType,
}) {
  if (source != QuickRoutingConflictSource.permanent ||
      overwriteType == OverwriteType.script) {
    return false;
  }
  if (!RuleAction.addedRuleActions.contains(rule.ruleAction) ||
      rule.ruleProvider != null ||
      rule.subRule != null) {
    return false;
  }
  return (rule.content?.trim().isNotEmpty ?? false) &&
      (rule.ruleTarget?.trim().isNotEmpty ?? false);
}

class _QuickRoutingConflictDetailsPage extends ConsumerStatefulWidget {
  final int profileId;
  final int recordId;

  const _QuickRoutingConflictDetailsPage({
    required this.profileId,
    required this.recordId,
  });

  @override
  ConsumerState<_QuickRoutingConflictDetailsPage> createState() =>
      _QuickRoutingConflictDetailsPageState();
}

class _QuickRoutingConflictDetailsPageState
    extends ConsumerState<_QuickRoutingConflictDetailsPage> {
  List<Rule> _knownRules = const [];
  List<Rule> _runtimeRules = const [];
  List<Rule> _permanentRules = const [];
  OverwriteType _overwriteType = OverwriteType.standard;
  bool _loadingRules = true;
  bool _rechecking = false;
  final _editingRuleIds = <int>{};

  @override
  void initState() {
    super.initState();
    unawaited(_refreshRules());
  }

  bool _profileIsActive() {
    return ref.read(currentProfileIdProvider) == widget.profileId;
  }

  void _showInactiveProfile() {
    dialogs.showNotifier(
      currentAppLocalizations.invalidPolicy(currentAppLocalizations.profile),
      level: MessageLevel.warning,
    );
  }

  Future<void> _refreshRules() async {
    if (mounted) {
      setState(() {
        _loadingRules = true;
      });
    }
    try {
      final overwriteType = ref.read(overwriteTypeProvider(widget.profileId));
      final runtimeRules = ref
          .read(quickRoutingRulesProvider.notifier)
          .activeRulesFor(widget.profileId);
      final permanentRules = overwriteType == OverwriteType.script
          ? const <Rule>[]
          : await _readPermanentRules(widget.profileId, overwriteType);
      final knownRules = await _readEffectiveQuickRoutingRules(
        ref: ref,
        profileId: widget.profileId,
        overwriteType: overwriteType,
      );
      if (mounted) {
        setState(() {
          _overwriteType = overwriteType;
          _runtimeRules = List.unmodifiable(runtimeRules);
          _permanentRules = List.unmodifiable(permanentRules);
          _knownRules = List.unmodifiable(knownRules);
        });
      }
    } catch (error, stackTrace) {
      commonPrint.log(
        'quick routing conflict source scan failed: '
        '${compactError(error)}, $stackTrace',
        logLevel: LogLevel.warning,
      );
    } finally {
      if (mounted) {
        setState(() {
          _loadingRules = false;
        });
      }
    }
  }

  Future<void> _recheck(
    QuickRoutingVerificationRecord record, {
    bool notify = true,
  }) async {
    if (_rechecking) {
      return;
    }
    if (!_profileIsActive()) {
      _showInactiveProfile();
      return;
    }
    setState(() {
      _rechecking = true;
    });
    try {
      final verification = await _verifyAppliedQuickRoutingRule(
        ref: ref,
        trackerInfo: record.trackerInfo,
        selection: record.selection,
        profileId: widget.profileId,
      );
      await _refreshRules();
      if (mounted && notify) {
        dialogs.showNotifier(
          _quickRoutingVerificationSummary(context, verification),
          level: verification.messageLevel,
        );
      }
    } finally {
      if (mounted) {
        setState(() {
          _rechecking = false;
        });
      }
    }
  }

  void _openRuntimeManager() {
    unawaited(
      dialogs.showCommonDialog<void>(
        child: _QuickRoutingRuleManagerDialog(profileId: widget.profileId),
      ),
    );
  }

  Future<void> _editPermanentRule(
    Rule rule,
    QuickRoutingVerificationRecord record,
  ) async {
    if (_editingRuleIds.contains(rule.id)) {
      return;
    }
    if (!_profileIsActive()) {
      _showInactiveProfile();
      return;
    }
    final source = classifyQuickRoutingConflictSource(
      rule: rule,
      runtimeRules: _runtimeRules,
      permanentRules: _permanentRules,
    );
    if (!canEditQuickRoutingConflictRule(
      rule: rule,
      source: source,
      overwriteType: _overwriteType,
    )) {
      dialogs.showNotifier(
        currentAppLocalizations.invalidPolicy(currentAppLocalizations.rule),
        level: MessageLevel.warning,
      );
      return;
    }

    final edited = await dialogs.showCommonDialog<Rule>(
      child: AddOrEditRuleDialog(rule: rule),
    );
    if (edited == null || !mounted) {
      return;
    }
    final normalized = edited.copyWith(
      id: rule.id,
      order: rule.order,
      ruleProvider: rule.ruleProvider,
      subRule: rule.subRule,
    );

    setState(() {
      _editingRuleIds.add(rule.id);
    });
    var persisted = false;
    try {
      await _writePermanentQuickRoutingRule(
        widget.profileId,
        _overwriteType,
        normalized,
      );
      persisted = true;
      _invalidatePermanentQuickRoutingState(
        ref,
        widget.profileId,
        _overwriteType,
      );
      final applied = await ref
          .read(setupActionProvider.notifier)
          .applyProfile(force: true);
      if (!applied) {
        throw StateError('Failed to apply edited routing conflict');
      }
      final verification = await _verifyAppliedQuickRoutingRule(
        ref: ref,
        trackerInfo: record.trackerInfo,
        selection: record.selection,
        profileId: widget.profileId,
      );
      await _refreshRules();
      if (mounted) {
        dialogs.showNotifier(
          '${currentAppLocalizations.update}: ${normalized.rawValue}\n'
          '${_quickRoutingVerificationSummary(context, verification)}',
          level: verification.messageLevel,
        );
      }
    } catch (error, stackTrace) {
      if (persisted) {
        try {
          await _writePermanentQuickRoutingRule(
            widget.profileId,
            _overwriteType,
            rule,
          );
          _invalidatePermanentQuickRoutingState(
            ref,
            widget.profileId,
            _overwriteType,
          );
          await ref
              .read(setupActionProvider.notifier)
              .applyProfile(force: true, silence: true);
        } catch (rollbackError, rollbackStackTrace) {
          commonPrint.log(
            'quick routing conflict edit rollback failed: '
            '${compactError(rollbackError)}, $rollbackStackTrace',
            logLevel: LogLevel.error,
          );
        }
      }
      commonPrint.log(
        'quick routing conflict edit failed: '
        '${compactError(error)}, $stackTrace',
        logLevel: LogLevel.warning,
      );
      if (mounted) {
        dialogs.showNotifier(
          currentAppLocalizations.databaseWriteFailedTip,
          level: MessageLevel.error,
        );
      }
    } finally {
      if (mounted) {
        setState(() {
          _editingRuleIds.remove(rule.id);
        });
      }
    }
  }

  String _issueLabel(BuildContext context, String issue) {
    final appLocalizations = context.appLocalizations;
    return switch (issue) {
      'core-unavailable' =>
        '${appLocalizations.core}: ${appLocalizations.unknown}',
      'profile-not-active' =>
        '${appLocalizations.profile}: ${appLocalizations.unknown}',
      'rule-not-matched' =>
        '${appLocalizations.rule}: ${appLocalizations.noData}',
      'rule-type-mismatch' =>
        '${appLocalizations.ruleName}: ${appLocalizations.unknown}',
      'rule-payload-mismatch' =>
        '${appLocalizations.content}: ${appLocalizations.unknown}',
      'target-mismatch' =>
        '${appLocalizations.ruleTarget}: ${appLocalizations.unknown}',
      'fixed-policy-mismatch' =>
        '${appLocalizations.proxyGroup}: ${appLocalizations.unknown}',
      'core-result-incomplete' =>
        '${appLocalizations.core}: ${appLocalizations.unknown}',
      _ => issue,
    };
  }

  String _conflictKindLabel(
    BuildContext context,
    QuickRoutingConflictKind kind,
  ) {
    final appLocalizations = context.appLocalizations;
    return switch (kind) {
      QuickRoutingConflictKind.equivalent => appLocalizations.selected,
      QuickRoutingConflictKind.competing => appLocalizations.update,
      QuickRoutingConflictKind.opaque => appLocalizations.unknown,
    };
  }

  String _sourceLabel(BuildContext context, QuickRoutingConflictSource source) {
    final appLocalizations = context.appLocalizations;
    return switch (source) {
      QuickRoutingConflictSource.runtime => appLocalizations.expireTime,
      QuickRoutingConflictSource.permanent => appLocalizations.save,
      QuickRoutingConflictSource.readOnly => appLocalizations.view,
    };
  }

  Widget _section({
    required BuildContext context,
    required String title,
    required List<Widget> children,
  }) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(title, style: context.textTheme.titleMedium),
            const SizedBox(height: 10),
            ...children,
          ],
        ),
      ),
    );
  }

  Widget? _conflictAction(
    BuildContext context,
    QuickRoutingConflictEntry conflict,
    QuickRoutingVerificationRecord record,
  ) {
    final source = classifyQuickRoutingConflictSource(
      rule: conflict.rule,
      runtimeRules: _runtimeRules,
      permanentRules: _permanentRules,
    );
    if (source == QuickRoutingConflictSource.runtime) {
      return IconButton(
        tooltip: context.appLocalizations.edit,
        onPressed: _openRuntimeManager,
        icon: const Icon(Icons.tune),
      );
    }
    if (canEditQuickRoutingConflictRule(
      rule: conflict.rule,
      source: source,
      overwriteType: _overwriteType,
    )) {
      final busy = _editingRuleIds.contains(conflict.rule.id);
      return IconButton(
        tooltip: context.appLocalizations.edit,
        onPressed: busy
            ? null
            : () => _editPermanentRule(conflict.rule, record),
        icon: busy
            ? const SizedBox.square(
                dimension: 18,
                child: CircularProgressIndicator(strokeWidth: 2),
              )
            : const Icon(Icons.edit_outlined),
      );
    }
    return Tooltip(
      message: context.appLocalizations.view,
      child: const Icon(Icons.lock_outline),
    );
  }

  @override
  Widget build(BuildContext context) {
    final record = ref.watch(
      quickRoutingVerificationHistoryProvider.select((entries) {
        for (final entry in entries) {
          if (entry.id == widget.recordId &&
              entry.profileId == widget.profileId) {
            return entry;
          }
        }
        return null;
      }),
    );
    final appLocalizations = context.appLocalizations;

    if (record == null) {
      return Scaffold(
        appBar: AppBar(
          title: Text(appLocalizations.details(appLocalizations.rule)),
        ),
        body: Center(child: Text(appLocalizations.noData)),
      );
    }

    final conflicts = buildQuickRoutingConflictEntries(
      selection: record.selection,
      trackerInfo: record.trackerInfo,
      knownRules: _knownRules,
    );
    final result = record.verification.result;
    final profileActive =
        ref.watch(currentProfileIdProvider) == widget.profileId;

    return Scaffold(
      appBar: AppBar(
        title: Text(appLocalizations.details(appLocalizations.rule)),
        actions: [
          IconButton(
            tooltip: appLocalizations.update,
            onPressed: _rechecking || !profileActive
                ? null
                : () => _recheck(record),
            icon: _rechecking
                ? const SizedBox.square(
                    dimension: 20,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Icon(Icons.refresh),
          ),
          IconButton(
            tooltip: appLocalizations.delete,
            onPressed: () {
              ref
                  .read(quickRoutingVerificationHistoryProvider.notifier)
                  .remove(record.id);
              Navigator.of(context).pop();
            },
            icon: const Icon(Icons.delete_outline),
          ),
        ],
      ),
      body: RefreshIndicator(
        onRefresh: () async {
          await _recheck(record);
        },
        child: ListView(
          padding: const EdgeInsets.all(12),
          children: [
            if (!profileActive)
              Card(
                color: context.colorScheme.tertiaryContainer,
                child: ListTile(
                  leading: const Icon(Icons.warning_amber_outlined),
                  title: Text(
                    appLocalizations.invalidPolicy(appLocalizations.profile),
                  ),
                ),
              ),
            _section(
              context: context,
              title: appLocalizations.preview,
              children: [
                Text(record.appliedRule.rawValue),
                Text(
                  '${appLocalizations.expireTime}: '
                  '${_quickRoutingLifetimeLabel(context, record.selection.lifetime)}',
                ),
                Text('${appLocalizations.time}: ${record.checkedAt.showFull}'),
                Text(
                  '${appLocalizations.status}: '
                  '${record.verification.marker} '
                  '${record.verification.status.name}',
                ),
              ],
            ),
            if (result != null)
              _section(
                context: context,
                title: appLocalizations.core,
                children: _buildCoreQuickRoutingMatchPreview(context, result),
              ),
            if (record.verification.issues.isNotEmpty)
              _section(
                context: context,
                title: appLocalizations.status,
                children: [
                  for (final issue in record.verification.issues)
                    Text('• ${_issueLabel(context, issue)}'),
                ],
              ),
            _section(
              context: context,
              title:
                  '${appLocalizations.rules} · '
                  '${appLocalizations.search}',
              children: [
                if (_loadingRules)
                  const Center(
                    child: Padding(
                      padding: EdgeInsets.all(12),
                      child: CircularProgressIndicator(),
                    ),
                  )
                else if (conflicts.isEmpty)
                  Text(appLocalizations.noData)
                else
                  for (final conflict in conflicts)
                    Builder(
                      builder: (context) {
                        final source = classifyQuickRoutingConflictSource(
                          rule: conflict.rule,
                          runtimeRules: _runtimeRules,
                          permanentRules: _permanentRules,
                        );
                        return ListTile(
                          contentPadding: EdgeInsets.zero,
                          leading: CircleAvatar(
                            child: Text('${conflict.index + 1}'),
                          ),
                          title: Text(
                            conflict.rule.rawValue,
                            maxLines: 2,
                            overflow: TextOverflow.ellipsis,
                          ),
                          subtitle: Text(
                            '${_conflictKindLabel(context, conflict.kind)} · '
                            '${_sourceLabel(context, source)}',
                          ),
                          trailing: _conflictAction(context, conflict, record),
                        );
                      },
                    ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
