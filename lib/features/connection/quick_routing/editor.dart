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

  void _setBusy(bool value) {
    if (!mounted || _busy == value) {
      return;
    }
    setState(() {
      _busy = value;
    });
  }

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

    final groups = ref.read(groupsProvider);
    final targets = buildQuickRoutingTargets(groups);
    final overwriteType = ref.read(overwriteTypeProvider(profileId));
    final lifetimes = QuickRoutingLifetime.values
        .where(
          (lifetime) =>
              overwriteType != OverwriteType.script || lifetime.isRuntime,
        )
        .toList(growable: false);

    _setBusy(true);
    final knownRules = await _readEffectiveQuickRoutingRules(
      ref: ref,
      profileId: profileId,
      overwriteType: overwriteType,
    );
    _setBusy(false);
    if (!mounted) {
      return;
    }

    final selection = await dialogs.showCommonDialog<QuickRoutingSelection>(
      child: _QuickRoutingDialog(
        trackerInfo: widget.trackerInfo,
        candidates: candidates,
        targets: targets,
        lifetimes: lifetimes,
        knownRules: knownRules,
        recentRequests: ref.read(requestsProvider).list,
        initialTarget: pickQuickRoutingTarget(
          widget.trackerInfo,
          targets,
          preferredTargets: groups.map((group) => group.name),
        ),
      ),
    );
    if (selection == null || !mounted) {
      return;
    }

    _setBusy(true);
    try {
      final result = selection.lifetime.isRuntime
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
        '${currentAppLocalizations.addRule}: ${result.rule.rawValue}',
        level: MessageLevel.success,
        actionState: MessageActionState(
          actionText: currentAppLocalizations.undo,
          action: () {
            if (mounted) {
              unawaited(_handleUndo(result));
            }
          },
        ),
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
      _setBusy(false);
    }
  }

  Future<void> _handleUndo(_QuickRoutingApplyResult result) async {
    if (_busy) {
      return;
    }
    _setBusy(true);
    try {
      final undone = await result.undo();
      if (!mounted) {
        return;
      }
      dialogs.showNotifier(
        undone
            ? '${currentAppLocalizations.undo}: ${result.rule.rawValue}'
            : '${currentAppLocalizations.undo}: '
                  '${currentAppLocalizations.noData}',
        level: undone ? MessageLevel.success : MessageLevel.warning,
      );
    } catch (error, stackTrace) {
      commonPrint.log(
        'quick routing undo failed: ${compactError(error)}, $stackTrace',
        logLevel: LogLevel.warning,
      );
      dialogs.showNotifier(
        currentAppLocalizations.databaseWriteFailedTip,
        level: MessageLevel.error,
      );
    } finally {
      _setBusy(false);
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

class _QuickRoutingDialog extends StatefulWidget {
  final TrackerInfo trackerInfo;
  final List<QuickRoutingCandidate> candidates;
  final List<String> targets;
  final List<QuickRoutingLifetime> lifetimes;
  final List<Rule> knownRules;
  final List<TrackerInfo> recentRequests;
  final String initialTarget;

  const _QuickRoutingDialog({
    required this.trackerInfo,
    required this.candidates,
    required this.targets,
    required this.lifetimes,
    required this.knownRules,
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
      buildQuickRoutingImpactSource(
        widget.trackerInfo,
        widget.recentRequests,
      ),
    );
    final analysis = buildQuickRoutingRuleAnalysis(
      candidate: _candidate,
      target: _target,
      trackerInfo: widget.trackerInfo,
      knownRules: widget.knownRules,
    );
    final nextRule = _candidate.buildRule(target: _target, id: -1);
    final equivalentRule = analysis.equivalentRule;
    final equivalentRuleIndex = equivalentRule == null
        ? -1
        : widget.knownRules.indexOf(equivalentRule);
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
              if (candidate != null) {
                setState(() {
                  _candidate = candidate;
                });
              }
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
              if (target != null) {
                setState(() {
                  _target = target;
                });
              }
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
                  if (equivalentRule != null)
                    Text(
                      '${appLocalizations.edit} '
                      '#${equivalentRuleIndex + 1}: '
                      '${equivalentRule.rawValue}',
                    ),
                  if (equivalentRule != null)
                    Text(
                      equivalentRule.ruleTarget == _target
                          ? '${appLocalizations.selected}: $_target'
                          : '${appLocalizations.update}: '
                                '${equivalentRule.ruleTarget ?? ''} → $_target',
                    ),
                  if (analysis.matchingKnownRuleCount > 0)
                    Text(
                      '${appLocalizations.rules}: '
                      '${analysis.matchingKnownRuleCount}',
                    ),
                  if (analysis.targetAlreadyInChain &&
                      equivalentRule?.ruleTarget != _target)
                    Text('${appLocalizations.selected}: $_target'),
                  Text('${appLocalizations.requests}: ${impact.requestCount}'),
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
