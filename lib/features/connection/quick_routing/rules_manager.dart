part of '../quick_routing.dart';

enum _QuickRoutingRuleManagerAction { moveUp, moveDown, makePermanent, delete }

class _QuickRoutingRuleManagerDialog extends ConsumerStatefulWidget {
  final int profileId;

  const _QuickRoutingRuleManagerDialog({required this.profileId});

  @override
  ConsumerState<_QuickRoutingRuleManagerDialog> createState() =>
      _QuickRoutingRuleManagerDialogState();
}

class _QuickRoutingRuleManagerDialogState
    extends ConsumerState<_QuickRoutingRuleManagerDialog> {
  final _busyRuleIds = <int>{};
  bool _clearing = false;

  Future<void> _runForRule(
    QuickRoutingRuleEntry entry,
    Future<void> Function() action,
  ) async {
    if (_busyRuleIds.contains(entry.rule.id)) {
      return;
    }
    setState(() {
      _busyRuleIds.add(entry.rule.id);
    });
    try {
      await action();
    } catch (error, stackTrace) {
      commonPrint.log(
        'quick routing manager action failed: '
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

  Future<void> _move(QuickRoutingRuleEntry entry, int offset) {
    return _runForRule(entry, () async {
      await _applyRuntimeQuickRoutingMutation(
        ref: ref,
        mutation: (notifier) =>
            notifier.move(entry.profileId, entry.rule.id, offset),
      );
    });
  }

  Future<void> _remove(QuickRoutingRuleEntry entry) {
    return _runForRule(entry, () async {
      await _applyRuntimeQuickRoutingMutation(
        ref: ref,
        mutation: (notifier) => notifier.remove(entry.profileId, entry.rule.id),
      );
    });
  }

  Future<void> _makePermanent(QuickRoutingRuleEntry entry) {
    return _runForRule(entry, () async {
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
      if (content == null ||
          content.isEmpty ||
          target == null ||
          target.isEmpty) {
        return;
      }
      final snapshot = ref.read(quickRoutingRulesProvider);
      final notifier = ref.read(quickRoutingRulesProvider.notifier);
      if (!notifier.remove(entry.profileId, entry.rule.id)) {
        return;
      }
      try {
        final result = await _saveAndApplyPermanentQuickRoutingRule(
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
          '${currentAppLocalizations.save}: ${result.rule.rawValue}',
          level: MessageLevel.success,
        );
      } catch (error, stackTrace) {
        notifier.replaceAll(snapshot);
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
        Error.throwWithStackTrace(error, stackTrace);
      }
    });
  }

  Future<void> _clear() async {
    if (_clearing) {
      return;
    }
    setState(() {
      _clearing = true;
    });
    try {
      await _applyRuntimeQuickRoutingMutation(
        ref: ref,
        mutation: (notifier) => notifier.clearProfile(widget.profileId),
      );
    } catch (error, stackTrace) {
      commonPrint.log(
        'quick routing clear failed: ${compactError(error)}, $stackTrace',
        logLevel: LogLevel.warning,
      );
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

  void _handleAction(
    QuickRoutingRuleEntry entry,
    _QuickRoutingRuleManagerAction action,
  ) {
    switch (action) {
      case _QuickRoutingRuleManagerAction.moveUp:
        unawaited(_move(entry, -1));
        return;
      case _QuickRoutingRuleManagerAction.moveDown:
        unawaited(_move(entry, 1));
        return;
      case _QuickRoutingRuleManagerAction.makePermanent:
        unawaited(_makePermanent(entry));
        return;
      case _QuickRoutingRuleManagerAction.delete:
        unawaited(_remove(entry));
        return;
    }
  }

  PopupMenuItem<_QuickRoutingRuleManagerAction> _menuItem({
    required _QuickRoutingRuleManagerAction value,
    required IconData icon,
    required String label,
  }) {
    return PopupMenuItem(
      value: value,
      child: Row(
        children: [
          Icon(icon, size: 20),
          const SizedBox(width: 12),
          Flexible(child: Text(label)),
        ],
      ),
    );
  }

  Widget _buildEntry(
    BuildContext context,
    QuickRoutingRuleEntry entry, {
    required int index,
    required int length,
    required bool canPersist,
  }) {
    final busy = _busyRuleIds.contains(entry.rule.id);
    final expiration = entry.expiresAt?.showFull;
    final lifetime = _quickRoutingLifetimeLabel(context, entry.lifetime);
    final previousPath = [
      entry.previousRule,
      ...entry.previousChains,
    ].where((value) => value.isNotEmpty).join(' → ');
    final widgetLocalizations = WidgetsLocalizations.of(context);
    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      child: ListTile(
        leading: CircleAvatar(child: Text('${index + 1}')),
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
            : PopupMenuButton<_QuickRoutingRuleManagerAction>(
                tooltip: context.appLocalizations.more,
                onSelected: (action) => _handleAction(entry, action),
                itemBuilder: (_) => [
                  if (index > 0)
                    _menuItem(
                      value: _QuickRoutingRuleManagerAction.moveUp,
                      icon: Icons.arrow_upward,
                      label: widgetLocalizations.reorderItemUp,
                    ),
                  if (index + 1 < length)
                    _menuItem(
                      value: _QuickRoutingRuleManagerAction.moveDown,
                      icon: Icons.arrow_downward,
                      label: widgetLocalizations.reorderItemDown,
                    ),
                  if (canPersist)
                    _menuItem(
                      value: _QuickRoutingRuleManagerAction.makePermanent,
                      icon: Icons.save_outlined,
                      label: context.appLocalizations.save,
                    ),
                  _menuItem(
                    value: _QuickRoutingRuleManagerAction.delete,
                    icon: Icons.delete_outline,
                    label: context.appLocalizations.delete,
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
                for (var index = 0; index < entries.length; index++)
                  _buildEntry(
                    context,
                    entries[index],
                    index: index,
                    length: entries.length,
                    canPersist: overwriteType != OverwriteType.script,
                  ),
              ],
            ),
    );
  }
}
