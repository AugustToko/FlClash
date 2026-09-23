import 'dart:io';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/database/database.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/providers.dart';
import 'package:fl_clash/widgets/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

@immutable
class QuickRoutingCandidate {
  final RuleAction ruleAction;
  final String content;
  final bool noResolve;

  const QuickRoutingCandidate({
    required this.ruleAction,
    required this.content,
    this.noResolve = false,
  });

  String get label => '${ruleAction.value} · $content';

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
class QuickRoutingSelection {
  final QuickRoutingCandidate candidate;
  final String target;

  const QuickRoutingSelection({required this.candidate, required this.target});
}

List<QuickRoutingCandidate> buildQuickRoutingCandidates(
  TrackerInfo trackerInfo,
) {
  final candidates = <QuickRoutingCandidate>[];
  final keys = <String>{};

  void add(
    RuleAction ruleAction,
    String? rawContent, {
    bool noResolve = false,
  }) {
    final content = rawContent?.trim() ?? '';
    if (content.isEmpty) {
      return;
    }
    final key = '${ruleAction.name}\u0000$content\u0000$noResolve';
    if (!keys.add(key)) {
      return;
    }
    candidates.add(
      QuickRoutingCandidate(
        ruleAction: ruleAction,
        content: content,
        noResolve: noResolve,
      ),
    );
  }

  void addIp(String rawIp) {
    final ip = _normalizeHost(rawIp);
    final address = InternetAddress.tryParse(ip);
    if (address == null) {
      return;
    }
    final action = address.type == InternetAddressType.IPv6
        ? RuleAction.IP_CIDR6
        : RuleAction.IP_CIDR;
    final prefix = address.type == InternetAddressType.IPv6 ? 128 : 32;
    add(action, '${address.address}/$prefix', noResolve: true);
  }

  final metadata = trackerInfo.metadata;
  final host = _normalizeHost(metadata.host);
  if (host.isNotEmpty) {
    if (InternetAddress.tryParse(host) != null) {
      addIp(host);
    } else {
      final normalizedDomain = host.toLowerCase();
      add(RuleAction.DOMAIN, normalizedDomain);
      add(RuleAction.DOMAIN_SUFFIX, normalizedDomain);
    }
  }

  addIp(metadata.destinationIP);
  add(RuleAction.PROCESS_NAME, metadata.process);
  add(RuleAction.PROCESS_PATH, metadata.processPath);
  if (metadata.uid > 0) {
    add(RuleAction.UID, metadata.uid.toString());
  }
  add(RuleAction.DST_PORT, metadata.destinationPort);

  return List.unmodifiable(candidates);
}

List<String> buildQuickRoutingTargets(Iterable<Group> groups) {
  final targets = <String>[];
  final seen = <String>{};

  void add(String value) {
    final target = value.trim();
    if (target.isNotEmpty && seen.add(target)) {
      targets.add(target);
    }
  }

  for (final target in RuleTarget.baseTargetNames) {
    add(target);
  }
  for (final group in groups) {
    add(group.name);
  }
  return List.unmodifiable(targets);
}

String pickQuickRoutingTarget(TrackerInfo trackerInfo, List<String> targets) {
  for (final chain in trackerInfo.chains) {
    if (targets.contains(chain)) {
      return chain;
    }
  }
  if (targets.contains(RuleTarget.DIRECT.name)) {
    return RuleTarget.DIRECT.name;
  }
  return targets.first;
}

String _normalizeHost(String value) {
  var host = value.trim();
  if (host.isEmpty) {
    return host;
  }
  if (host.startsWith('[')) {
    final closingBracket = host.indexOf(']');
    if (closingBracket > 1) {
      host = host.substring(1, closingBracket);
    }
  } else {
    final firstColon = host.indexOf(':');
    final lastColon = host.lastIndexOf(':');
    if (firstColon > 0 && firstColon == lastColon) {
      final port = host.substring(lastColon + 1);
      if (int.tryParse(port) != null) {
        host = host.substring(0, lastColon);
      }
    }
  }
  while (host.endsWith('.')) {
    host = host.substring(0, host.length - 1);
  }
  return host;
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

  Future<void> _handlePressed() async {
    final profileId = ref.read(currentProfileIdProvider);
    if (profileId == null) {
      dialogs.showNotifier(
        currentAppLocalizations.nullProfileDesc,
        level: MessageLevel.warning,
      );
      return;
    }

    final overwriteType = ref.read(overwriteTypeProvider(profileId));
    if (overwriteType == OverwriteType.script) {
      dialogs.showNotifier(
        '${currentAppLocalizations.addRule}: '
        '${currentAppLocalizations.invalidPolicy(overwriteType.name)}',
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
    final selection = await dialogs.showCommonDialog<QuickRoutingSelection>(
      child: _QuickRoutingDialog(
        candidates: candidates,
        targets: targets,
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
      final rule = await _saveAndApplyRule(
        profileId: profileId,
        overwriteType: overwriteType,
        selection: selection,
      );
      final onRuleApplied = widget.onRuleApplied;
      if (onRuleApplied != null) {
        await onRuleApplied();
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

  Future<Rule> _saveAndApplyRule({
    required int profileId,
    required OverwriteType overwriteType,
    required QuickRoutingSelection selection,
  }) async {
    final rules = await _readRules(profileId, overwriteType);
    final previous = _findExistingRule(rules, selection.candidate);
    var rule = selection.candidate.buildRule(
      target: selection.target,
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
      await _writeRule(profileId, overwriteType, rule);
      persisted = true;
      _invalidateRuleState(profileId, overwriteType);
      final applied = await ref
          .read(setupActionProvider.notifier)
          .applyProfile(force: true);
      if (!applied) {
        throw StateError('Failed to apply quick routing rule');
      }
      return rule;
    } catch (error, stackTrace) {
      if (persisted) {
        await _rollbackRule(
          profileId: profileId,
          overwriteType: overwriteType,
          rule: rule,
          previous: previous,
        );
      }
      Error.throwWithStackTrace(error, stackTrace);
    }
  }

  Future<List<Rule>> _readRules(int profileId, OverwriteType overwriteType) {
    return switch (overwriteType) {
      OverwriteType.standard =>
        database.rulesDao.queryProfileAddedRules(profileId).get(),
      OverwriteType.custom =>
        database.rulesDao.queryProfileCustomRules(profileId).get(),
      OverwriteType.script => Future<List<Rule>>.error(
        StateError('Script overwrite does not support quick routing rules'),
      ),
    };
  }

  Rule? _findExistingRule(List<Rule> rules, QuickRoutingCandidate candidate) {
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

  Future<void> _writeRule(
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
          'Script overwrite does not support quick routing rules',
        );
    }
  }

  Future<void> _rollbackRule({
    required int profileId,
    required OverwriteType overwriteType,
    required Rule rule,
    required Rule? previous,
  }) async {
    try {
      if (previous != null) {
        await _writeRule(profileId, overwriteType, previous);
      } else {
        await database.rulesDao.delRules([rule.id]);
      }
      _invalidateRuleState(profileId, overwriteType);
      await ref.read(setupActionProvider.notifier).applyProfile(force: true);
    } catch (error, stackTrace) {
      commonPrint.log(
        'quick routing rollback failed: ${compactError(error)}, $stackTrace',
        logLevel: LogLevel.error,
      );
    }
  }

  void _invalidateRuleState(int profileId, OverwriteType overwriteType) {
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
  final List<QuickRoutingCandidate> candidates;
  final List<String> targets;
  final String initialTarget;

  const _QuickRoutingDialog({
    required this.candidates,
    required this.targets,
    required this.initialTarget,
  });

  @override
  State<_QuickRoutingDialog> createState() => _QuickRoutingDialogState();
}

class _QuickRoutingDialogState extends State<_QuickRoutingDialog> {
  late QuickRoutingCandidate _candidate;
  late String _target;

  @override
  void initState() {
    super.initState();
    _candidate = widget.candidates.first;
    _target = widget.targets.contains(widget.initialTarget)
        ? widget.initialTarget
        : widget.targets.first;
  }

  void _handleSubmit() {
    Navigator.of(
      context,
    ).pop(QuickRoutingSelection(candidate: _candidate, target: _target));
  }

  @override
  Widget build(BuildContext context) {
    final appLocalizations = context.appLocalizations;
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
        ],
      ),
    );
  }
}
