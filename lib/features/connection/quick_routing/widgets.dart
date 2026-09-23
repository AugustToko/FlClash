part of '../quick_routing.dart';

class QuickRoutingButton extends ConsumerStatefulWidget {
  final TrackerInfo trackerInfo;
  final Future<void> Function()? onRuleApplied;

  const QuickRoutingButton({
    super.key,
    required this.trackerInfo,
    this.onRuleApplied,
  });

  @override
  ConsumerState<QuickRoutingButton> createState() => _QuickRoutingButtonState();
}

class _QuickRoutingButtonState extends ConsumerState<QuickRoutingButton> {
  bool _busy = false;

  Future<void> _handlePressed() async {
    final profileId = ref.read(currentProfileIdProvider);
    if (profileId == null) {
      dialogs.showNotifier(
        currentAppLocalizations.nullProfileDesc,
        level: MessageLevel.warning,
      );
      return;
    }

    final candidates = buildQuickRoutingCandidates(widget.trackerInfo);
    if (candidates.isEmpty) {
      dialogs.showNotifier(
        currentAppLocalizations.nullTip(currentAppLocalizations.rule),
        level: MessageLevel.warning,
      );
      return;
    }

    final targets = buildQuickRoutingTargets(ref.read(groupsProvider));
    final overwriteType = ref.read(overwriteTypeProvider(profileId));
    final lifetimes = QuickRoutingLifetime.values
        .where(
          (lifetime) =>
              overwriteType != OverwriteType.script || lifetime.isRuntime,
        )
        .toList(growable: false);
    final selection = await dialogs.showCommonDialog<QuickRoutingSelection>(
      child: _QuickRoutingDialog(
        trackerInfo: widget.trackerInfo,
        candidates: candidates,
        targets: targets,
        lifetimes: lifetimes,
        recentRequests: ref.read(requestsProvider).list,
        initialTarget: pickQuickRoutingTarget(widget.trackerInfo, targets),
      ),
    );
    if (selection == null || !mounted) {
      return;
    }

    setState(() {
      _busy = true;
    });
    try {
      final rule = selection.lifetime.isRuntime
          ? await _saveAndApplyRuntimeQuickRoutingRule(
              ref: ref,
              profileId: profileId,
              selection: selection,
              trackerInfo: widget.trackerInfo,
            )
          : await _saveAndApplyPermanentQuickRoutingRule(
              ref: ref,
              profileId: profileId,
              overwriteType: overwriteType,
              candidate: selection.candidate,
              target: selection.target,
            );
      final onRuleApplied = widget.onRuleApplied;
      if (onRuleApplied != null) {
        try {
          await onRuleApplied();
        } catch (error, stackTrace) {
          commonPrint.log(
            'quick routing post-apply action failed: '
            '${compactError(error)}, $stackTrace',
            logLevel: LogLevel.warning,
          );
        }
      }
      dialogs.showNotifier(
        '${currentAppLocalizations.addRule}: ${rule.rawValue}',
        level: MessageLevel.success,
      );
    } catch (error, stackTrace) {
      commonPrint.log(
        'quick routing failed: ${compactError(error)}, $stackTrace',
        logLevel: LogLevel.warning,
      );
      dialogs.showNotifier(
        currentAppLocalizations.databaseWriteFailedTip,
        level: MessageLevel.error,
      );
    } finally {
      if (mounted) {
        setState(() {
          _busy = false;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return IconButton(
      tooltip: context.appLocalizations.addRule,
      visualDensity: VisualDensity.compact,
      onPressed: _busy ? null : _handlePressed,
      icon: _busy
          ? const SizedBox.square(
              dimension: 18,
              child: CircularProgressIndicator(strokeWidth: 2),
            )
          : const Icon(Icons.alt_route, size: 20),
    );
  }
}

class QuickRoutingRulesButton extends ConsumerWidget {
  const QuickRoutingRulesButton({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final profileId = ref.watch(currentProfileIdProvider);
    final count = ref.watch(
      quickRoutingRulesProvider.select(
        (entries) => profileId == null
            ? 0
            : entries
                  .where(
                    (entry) =>
                        entry.profileId == profileId && !entry.isExpired(),
                  )
                  .length,
      ),
    );
    return IconButton(
      tooltip: '${context.appLocalizations.rules} ($count)',
      onPressed: () {
        if (profileId == null) {
          dialogs.showNotifier(
            currentAppLocalizations.nullProfileDesc,
            level: MessageLevel.warning,
          );
          return;
        }
        unawaited(
          dialogs.showCommonDialog<void>(
            child: _QuickRoutingRulesDialog(profileId: profileId),
          ),
        );
      },
      icon: count == 0
          ? const Icon(Icons.rule_folder_outlined)
          : Badge.count(
              count: count,
              child: const Icon(Icons.rule_folder_outlined),
            ),
    );
  }
}

class _QuickRoutingDialog extends StatefulWidget {
  final TrackerInfo trackerInfo;
  final List<QuickRoutingCandidate> candidates;
  final List<String> targets;
  final List<QuickRoutingLifetime> lifetimes;
  final List<TrackerInfo> recentRequests;
  final String initialTarget;

  const _QuickRoutingDialog({
    required this.trackerInfo,
    required this.candidates,
    required this.targets,
    required this.lifetimes,
    required this.recentRequests,
    required this.initialTarget,
  });

  @override
  State<_QuickRoutingDialog> createState() => _QuickRoutingDialogState();
}

class _QuickRoutingDialogState extends State<_QuickRoutingDialog> {
  late QuickRoutingCandidate _candidate;
  late String _target;
  late QuickRoutingLifetime _lifetime;

  @override
  void initState() {
    super.initState();
    _candidate = widget.candidates.first;
    _target = widget.targets.contains(widget.initialTarget)
        ? widget.initialTarget
        : widget.targets.first;
    _lifetime = widget.lifetimes.first;
  }

  void _handleSubmit() {
    Navigator.of(context).pop(
      QuickRoutingSelection(
        candidate: _candidate,
        target: _target,
        lifetime: _lifetime,
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final appLocalizations = context.appLocalizations;
    final impact = buildQuickRoutingImpact(
      _candidate,
      widget.recentRequests,
    );
    final nextRule = _candidate.buildRule(
      target: _target,
      id: -1,
    );
    return CommonDialog(
      title: appLocalizations.addRule,
      actions: [
        TextButton(
          onPressed: _handleSubmit,
          child: Text(appLocalizations.confirm),
        ),
      ],
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          DropdownMenu<QuickRoutingCandidate>(
            width: 280,
            menuHeight: 300,
            initialSelection: _candidate,
            label: Text(appLocalizations.ruleName),
            dropdownMenuEntries: [
              for (final candidate in widget.candidates)
                DropdownMenuEntry(value: candidate, label: candidate.label),
            ],
            onSelected: (candidate) {
              if (candidate == null) {
                return;
              }
              setState(() {
                _candidate = candidate;
              });
            },
          ),
          const SizedBox(height: 20),
          DropdownMenu<String>(
            width: 280,
            menuHeight: 300,
            initialSelection: _target,
            enableFilter: true,
            enableSearch: true,
            label: Text(appLocalizations.ruleTarget),
            dropdownMenuEntries: [
              for (final target in widget.targets)
                DropdownMenuEntry(value: target, label: target),
            ],
            onSelected: (target) {
              if (target == null) {
                return;
              }
              setState(() {
                _target = target;
              });
            },
          ),
          const SizedBox(height: 20),
          Text(appLocalizations.expireTime),
          const SizedBox(height: 8),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              for (final lifetime in widget.lifetimes)
                ChoiceChip(
                  label: Text(_quickRoutingLifetimeLabel(context, lifetime)),
                  selected: _lifetime == lifetime,
                  onSelected: (_) {
                    setState(() {
                      _lifetime = lifetime;
                    });
                  },
                ),
            ],
          ),
          const SizedBox(height: 20),
          Card(
            margin: EdgeInsets.zero,
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    appLocalizations.preview,
                    style: context.textTheme.titleSmall,
                  ),
                  const SizedBox(height: 10),
                  Text(
                    '${appLocalizations.rule}: '
                    '${_trackerRuleText(widget.trackerInfo)}',
                  ),
                  Text(
                    '${appLocalizations.proxyChains}: '
                    '${widget.trackerInfo.chains.join(' → ')}',
                  ),
                  const Divider(),
                  Text('→ ${nextRule.rawValue}'),
                  Text(
                    '${appLocalizations.requests}: ${impact.requestCount}',
                  ),
                  if (impact.hosts.isNotEmpty)
                    Text(
                      '${appLocalizations.domain}: '
                      '${impact.hosts.take(3).join(', ')}',
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis,
                    ),
                  if (impact.processes.isNotEmpty)
                    Text(
                      '${appLocalizations.application}: '
                      '${impact.processes.take(3).join(', ')}',
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis,
                    ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _QuickRoutingRulesDialog extends ConsumerStatefulWidget {
  final int profileId;

  const _QuickRoutingRulesDialog({required this.profileId});

  @override
  ConsumerState<_QuickRoutingRulesDialog> createState() =>
      _QuickRoutingRulesDialogState();
}

class _QuickRoutingRulesDialogState
    extends ConsumerState<_QuickRoutingRulesDialog> {
  final _busyRuleIds = <int>{};
  bool _clearing = false;

  Future<void> _remove(QuickRoutingRuleEntry entry) async {
    setState(() {
      _busyRuleIds.add(entry.rule.id);
    });
    try {
      await _applyRuntimeQuickRoutingMutation(
        ref: ref,
        mutation: (notifier) => notifier.remove(
          entry.profileId,
          entry.rule.id,
        ),
      );
    } catch (_) {
      dialogs.showNotifier(
        currentAppLocalizations.databaseWriteFailedTip,
        level: MessageLevel.error,
      );
    } finally {
      if (mounted) {
        setState(() {
          _busyRuleIds.remove(entry.rule.id);
        });
      }
    }
  }

  Future<void> _clear() async {
    setState(() {
      _clearing = true;
    });
    try {
      await _applyRuntimeQuickRoutingMutation(
        ref: ref,
        mutation: (notifier) => notifier.clearProfile(widget.profileId),
      );
    } catch (_) {
      dialogs.showNotifier(
        currentAppLocalizations.databaseWriteFailedTip,
        level: MessageLevel.error,
      );
    } finally {
      if (mounted) {
        setState(() {
          _clearing = false;
        });
      }
    }
  }

  Future<void> _makePermanent(QuickRoutingRuleEntry entry) async {
    final overwriteType = ref.read(overwriteTypeProvider(widget.profileId));
    if (overwriteType == OverwriteType.script) {
      dialogs.showNotifier(
        currentAppLocalizations.invalidPolicy(overwriteType.name),
        level: MessageLevel.warning,
      );
      return;
    }
    final content = entry.rule.content;
    final target = entry.rule.ruleTarget;
    if (content == null || content.isEmpty || target == null || target.isEmpty) {
      return;
    }
    setState(() {
      _busyRuleIds.add(entry.rule.id);
    });
    final snapshot = ref.read(quickRoutingRulesProvider);
    ref
        .read(quickRoutingRulesProvider.notifier)
        .remove(entry.profileId, entry.rule.id);
    try {
      final rule = await _saveAndApplyPermanentQuickRoutingRule(
        ref: ref,
        profileId: widget.profileId,
        overwriteType: overwriteType,
        candidate: QuickRoutingCandidate(
          ruleAction: entry.rule.ruleAction,
          content: content,
          noResolve: entry.rule.noResolve,
        ),
        target: target,
      );
      dialogs.showNotifier(
        '${currentAppLocalizations.save}: ${rule.rawValue}',
        level: MessageLevel.success,
      );
    } catch (error, stackTrace) {
      ref.read(quickRoutingRulesProvider.notifier).replaceAll(snapshot);
      try {
        await ref
            .read(setupActionProvider.notifier)
            .applyProfile(force: true, silence: true);
      } catch (rollbackError, rollbackStackTrace) {
        commonPrint.log(
          'quick routing conversion rollback failed: '
          '${compactError(rollbackError)}, $rollbackStackTrace',
          logLevel: LogLevel.error,
        );
      }
      commonPrint.log(
        'quick routing conversion failed: '
        '${compactError(error)}, $stackTrace',
        logLevel: LogLevel.warning,
      );
      dialogs.showNotifier(
        currentAppLocalizations.databaseWriteFailedTip,
        level: MessageLevel.error,
      );
    } finally {
      if (mounted) {
        setState(() {
          _busyRuleIds.remove(entry.rule.id);
        });
      }
    }
  }

  Widget _buildEntry(
    BuildContext context,
    QuickRoutingRuleEntry entry, {
    required bool canPersist,
  }) {
    final busy = _busyRuleIds.contains(entry.rule.id);
    final expiration = entry.expiresAt?.showFull;
    final lifetime = _quickRoutingLifetimeLabel(context, entry.lifetime);
    final previousPath = [
      entry.previousRule,
      ...entry.previousChains,
    ].where((value) => value.isNotEmpty).join(' → ');
    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      child: ListTile(
        title: Text(
          entry.rule.rawValue,
          maxLines: 2,
          overflow: TextOverflow.ellipsis,
        ),
        subtitle: Text(
          [
            if (entry.sourceDesc.isNotEmpty) entry.sourceDesc,
            if (previousPath.isNotEmpty) previousPath,
            expiration == null ? lifetime : '$lifetime · $expiration',
          ].join('\n'),
          maxLines: 4,
          overflow: TextOverflow.ellipsis,
        ),
        trailing: busy
            ? const SizedBox.square(
                dimension: 20,
                child: CircularProgressIndicator(strokeWidth: 2),
              )
            : Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  if (canPersist)
                    IconButton(
                      tooltip: context.appLocalizations.save,
                      onPressed: () => _makePermanent(entry),
                      icon: const Icon(Icons.save_outlined),
                    ),
                  IconButton(
                    tooltip: context.appLocalizations.delete,
                    onPressed: () => _remove(entry),
                    icon: const Icon(Icons.delete_outline),
                  ),
                ],
              ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final entries = ref.watch(
      quickRoutingRulesProvider.select(
        (entries) => entries
            .where(
              (entry) =>
                  entry.profileId == widget.profileId && !entry.isExpired(),
            )
            .toList(growable: false),
      ),
    );
    final overwriteType = ref.watch(overwriteTypeProvider(widget.profileId));
    final appLocalizations = context.appLocalizations;
    return CommonDialog(
      title: appLocalizations.rules,
      actions: [
        if (entries.isNotEmpty)
          TextButton(
            onPressed: _clearing ? null : _clear,
            child: Text(appLocalizations.delete),
          ),
      ],
      child: entries.isEmpty
          ? Padding(
              padding: const EdgeInsets.symmetric(vertical: 24),
              child: Center(child: Text(appLocalizations.noData)),
            )
          : Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                for (final entry in entries)
                  _buildEntry(
                    context,
                    entry,
                    canPersist: overwriteType != OverwriteType.script,
                  ),
              ],
            ),
    );
  }
}
