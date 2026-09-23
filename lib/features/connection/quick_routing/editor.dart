part of '../quick_routing.dart';

String _quickRoutingValidationIssueLabel(
  BuildContext context,
  QuickRoutingValidationIssue issue,
) {
  final appLocalizations = context.appLocalizations;
  return switch (issue) {
    QuickRoutingValidationIssue.emptyContent =>
      '${appLocalizations.ruleName}: ${appLocalizations.noData}',
    QuickRoutingValidationIssue.emptyTarget =>
      '${appLocalizations.ruleTarget}: ${appLocalizations.noData}',
    QuickRoutingValidationIssue.unsupportedAction =>
      appLocalizations.invalidPolicy(appLocalizations.rule),
    QuickRoutingValidationIssue.invalidDomain =>
      appLocalizations.invalidPolicy(appLocalizations.domain),
    QuickRoutingValidationIssue.invalidCidr =>
      appLocalizations.invalidPolicy(appLocalizations.ipcidr),
    QuickRoutingValidationIssue.invalidPort =>
      appLocalizations.invalidPolicy(appLocalizations.port),
    QuickRoutingValidationIssue.invalidUid =>
      appLocalizations.invalidPolicy('UID'),
    QuickRoutingValidationIssue.invalidNetwork =>
      appLocalizations.invalidPolicy(appLocalizations.network),
    QuickRoutingValidationIssue.invalidAsn =>
      appLocalizations.invalidPolicy('ASN'),
    QuickRoutingValidationIssue.invalidGroupOverride =>
      appLocalizations.invalidPolicy(appLocalizations.proxyGroup),
  };
}

String _quickRoutingGroupOverrideModeLabel(
  BuildContext context,
  QuickRoutingGroupOverrideMode mode,
) {
  final appLocalizations = context.appLocalizations;
  return switch (mode) {
    QuickRoutingGroupOverrideMode.unchanged => appLocalizations.defaultText,
    QuickRoutingGroupOverrideMode.automatic => appLocalizations.auto,
    QuickRoutingGroupOverrideMode.fixed => appLocalizations.selected,
  };
}

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
    final (knownRules, fixedStates, coreMatch) = await (
      _readEffectiveQuickRoutingRules(
        ref: ref,
        profileId: profileId,
        overwriteType: overwriteType,
      ),
      _readQuickRoutingGroupFixedStates(ref),
      _readCoreQuickRoutingMatch(ref, widget.trackerInfo),
    ).wait;
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
        groups: groups,
        fixedStates: fixedStates,
        knownRules: knownRules,
        coreMatch: coreMatch,
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
      var result = selection.lifetime.isRuntime
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
      result = await _applyQuickRoutingGroupOverride(
        ref: ref,
        baseResult: result,
        selection: selection,
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
  final List<Group> groups;
  final Map<String, String> fixedStates;
  final List<Rule> knownRules;
  final CoreRuleMatchResult? coreMatch;
  final List<TrackerInfo> recentRequests;
  final String initialTarget;

  const _QuickRoutingDialog({
    required this.trackerInfo,
    required this.candidates,
    required this.targets,
    required this.lifetimes,
    required this.groups,
    required this.fixedStates,
    required this.knownRules,
    required this.coreMatch,
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
  QuickRoutingGroupOverrideMode _groupOverrideMode =
      QuickRoutingGroupOverrideMode.unchanged;
  String? _fixedProxy;

  @override
  void initState() {
    super.initState();
    _candidate = widget.candidates.first;
    _target = widget.targets.contains(widget.initialTarget)
        ? widget.initialTarget
        : widget.targets.first;
    _lifetime = widget.lifetimes.first;
    _resetGroupOverride();
  }

  Group? _computedGroupForTarget() {
    if (!_lifetime.isRuntime) {
      return null;
    }
    for (final group in widget.groups) {
      if (group.name == _target &&
          group.type.isComputedSelected &&
          widget.fixedStates.containsKey(group.name)) {
        return group;
      }
    }
    return null;
  }

  String? _defaultFixedProxy(Group? group) {
    if (group == null || group.all.isEmpty) {
      return null;
    }
    final currentFixed = widget.fixedStates[group.name] ?? '';
    if (currentFixed.isNotEmpty &&
        group.all.any((proxy) => proxy.name == currentFixed)) {
      return currentFixed;
    }
    final current = group.now?.trim() ?? '';
    if (current.isNotEmpty &&
        group.all.any((proxy) => proxy.name == current)) {
      return current;
    }
    return group.all.first.name;
  }

  void _resetGroupOverride() {
    _groupOverrideMode = QuickRoutingGroupOverrideMode.unchanged;
    _fixedProxy = _defaultFixedProxy(_computedGroupForTarget());
  }

  QuickRoutingGroupOverride? _buildGroupOverride() {
    final group = _computedGroupForTarget();
    if (group == null ||
        _groupOverrideMode == QuickRoutingGroupOverrideMode.unchanged) {
      return null;
    }
    final currentFixed = widget.fixedStates[group.name] ?? '';
    final desired = switch (_groupOverrideMode) {
      QuickRoutingGroupOverrideMode.automatic => '',
      QuickRoutingGroupOverrideMode.fixed => _fixedProxy?.trim() ?? '',
      QuickRoutingGroupOverrideMode.unchanged => '',
    };
    return QuickRoutingGroupOverride(
      groupName: group.name,
      previousFixed: currentFixed,
      expectedFixed: currentFixed,
      desiredFixed: desired,
    );
  }

  void _handleSubmit() {
    final groupOverride = _buildGroupOverride();
    final validation = validateQuickRoutingSelection(
      candidate: _candidate,
      target: _target,
      groupOverride: groupOverride,
      groups: widget.groups,
    );
    if (!validation.isValid) {
      return;
    }
    Navigator.of(context).pop(
      QuickRoutingSelection(
        candidate: _candidate,
        target: _target,
        lifetime: _lifetime,
        groupOverride: groupOverride,
      ),
    );
  }

  Widget _buildGroupOverrideCard(BuildContext context, Group group) {
    final appLocalizations = context.appLocalizations;
    final currentFixed = widget.fixedStates[group.name] ?? '';
    return Card(
      margin: EdgeInsets.zero,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              '${appLocalizations.proxyGroup}: ${group.name}',
              style: context.textTheme.titleSmall,
            ),
            const SizedBox(height: 6),
            Text(
              '${appLocalizations.status}: '
              '${currentFixed.isEmpty ? appLocalizations.auto : currentFixed}',
            ),
            const SizedBox(height: 10),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                for (final mode in QuickRoutingGroupOverrideMode.values)
                  ChoiceChip(
                    label: Text(
                      _quickRoutingGroupOverrideModeLabel(context, mode),
                    ),
                    selected: _groupOverrideMode == mode,
                    onSelected: (_) {
                      setState(() {
                        _groupOverrideMode = mode;
                        _fixedProxy ??= _defaultFixedProxy(group);
                      });
                    },
                  ),
              ],
            ),
            if (_groupOverrideMode == QuickRoutingGroupOverrideMode.fixed &&
                group.all.isNotEmpty) ...[
              const SizedBox(height: 12),
              DropdownMenu<String>(
                width: 280,
                menuHeight: 300,
                initialSelection: _fixedProxy,
                enableFilter: true,
                enableSearch: true,
                label: Text(appLocalizations.proxies),
                dropdownMenuEntries: [
                  for (final proxy in group.all)
                    DropdownMenuEntry(
                      value: proxy.name,
                      label: proxy.name,
                    ),
                ],
                onSelected: (proxy) {
                  if (proxy != null) {
                    setState(() {
                      _fixedProxy = proxy;
                    });
                  }
                },
              ),
            ],
          ],
        ),
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
    final groupOverride = _buildGroupOverride();
    final validation = validateQuickRoutingSelection(
      candidate: _candidate,
      target: _target,
      groupOverride: groupOverride,
      groups: widget.groups,
    );
    final nextRule = _candidate.buildRule(target: _target, id: -1);
    final equivalentRule = analysis.equivalentRule;
    final equivalentRuleIndex = equivalentRule == null
        ? -1
        : widget.knownRules.indexOf(equivalentRule);
    final firstKnownMatch = analysis.firstKnownMatch;
    final computedGroup = _computedGroupForTarget();
    final historicalPolicyChain = normalizeQuickRoutingHistoricalPolicyChain(
      widget.trackerInfo.chains,
    );
    final proposedPolicyChain = buildQuickRoutingPolicyChainPreview(
      target: _target,
      groups: widget.groups,
      fixedStates: widget.fixedStates,
      groupOverride: groupOverride,
    );
    final proposedPolicyNodes = proposedPolicyChain.displayNodes(
      appLocalizations.auto,
    );
    return CommonDialog(
      title: appLocalizations.addRule,
      actions: [
        TextButton(
          onPressed: validation.isValid ? _handleSubmit : null,
          child: Text(appLocalizations.confirm),
        ),
      ],
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 360, maxHeight: 620),
        child: SingleChildScrollView(
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
                    DropdownMenuEntry(
                      value: candidate,
                      label: candidate.label,
                    ),
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
                      _resetGroupOverride();
                    });
                  }
                },
              ),
              if (computedGroup != null) ...[
                const SizedBox(height: 16),
                _buildGroupOverrideCard(context, computedGroup),
              ],
              const SizedBox(height: 20),
              Text(appLocalizations.expireTime),
              const SizedBox(height: 8),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  for (final lifetime in widget.lifetimes)
                    ChoiceChip(
                      label: Text(
                        _quickRoutingLifetimeLabel(context, lifetime),
                      ),
                      selected: _lifetime == lifetime,
                      onSelected: (_) {
                        setState(() {
                          _lifetime = lifetime;
                          _resetGroupOverride();
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
                        '↶ ${appLocalizations.proxyChains}: '
                        '${historicalPolicyChain.isEmpty ? appLocalizations.noData : historicalPolicyChain.join(' → ')}',
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                      ),
                      if (widget.coreMatch != null) ...[
                        const SizedBox(height: 6),
                        ..._buildCoreQuickRoutingMatchPreview(
                          context,
                          widget.coreMatch!,
                        ),
                      ],
                      const Divider(),
                      Text('→ ${nextRule.rawValue}'),
                      if (proposedPolicyNodes.isNotEmpty)
                        Text(
                          '${proposedPolicyChain.complete ? '✓' : '≈'} '
                          '${appLocalizations.proxyChains}: '
                          '${proposedPolicyNodes.join(' → ')}',
                          maxLines: 2,
                          overflow: TextOverflow.ellipsis,
                        ),
                      if (groupOverride != null)
                        Text(
                          '${appLocalizations.proxyGroup}: '
                          '${groupOverride.groupName} · '
                          '${groupOverride.expectedFixed.isEmpty ? appLocalizations.auto : groupOverride.expectedFixed}'
                          ' → '
                          '${groupOverride.desiredFixed.isEmpty ? appLocalizations.auto : groupOverride.desiredFixed}',
                        ),
                      if (firstKnownMatch != null)
                        Text(
                          '${analysis.firstKnownMatchIsCertain ? '✓' : '≈'} '
                          '${appLocalizations.rule} '
                          '#${analysis.firstKnownMatchIndex + 1}: '
                          '${firstKnownMatch.rawValue}',
                        ),
                      if (analysis.unknownRuleCountBeforeFirstMatch > 0)
                        Text(
                          '≈ ${appLocalizations.unknown}: '
                          '${analysis.unknownRuleCountBeforeFirstMatch}',
                        ),
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
              if (!validation.isValid) ...[
                const SizedBox(height: 12),
                Text(
                  validation.issues
                      .map((issue) => _quickRoutingValidationIssueLabel(
                            context,
                            issue,
                          ))
                      .join('\n'),
                  style: context.textTheme.bodySmall?.copyWith(
                    color: context.colorScheme.error,
                  ),
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }
}
