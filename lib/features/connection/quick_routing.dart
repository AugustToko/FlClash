import 'dart:async';
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
class QuickRoutingImpact {
  final int requestCount;
  final List<String> hosts;
  final List<String> processes;

  const QuickRoutingImpact({
    required this.requestCount,
    required this.hosts,
    required this.processes,
  });
}

@immutable
class QuickRoutingSelection {
  final QuickRoutingCandidate candidate;
  final String target;
  final QuickRoutingLifetime lifetime;

  const QuickRoutingSelection({
    required this.candidate,
    required this.target,
    required this.lifetime,
  });
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

  void addIp(String rawIp, {required bool source}) {
    final ip = _normalizeHost(rawIp);
    final address = InternetAddress.tryParse(ip);
    if (address == null) {
      return;
    }
    final prefix = address.type == InternetAddressType.IPv6 ? 128 : 32;
    final action = switch ((source, address.type)) {
      (true, _) => RuleAction.SRC_IP_CIDR,
      (false, InternetAddressType.IPv6) => RuleAction.IP_CIDR6,
      _ => RuleAction.IP_CIDR,
    };
    add(
      action,
      '${address.address}/$prefix',
      noResolve: !source,
    );
  }

  final metadata = trackerInfo.metadata;
  final host = _normalizeHost(metadata.host);
  if (host.isNotEmpty) {
    if (InternetAddress.tryParse(host) != null) {
      addIp(host, source: false);
    } else {
      final normalizedDomain = host.toLowerCase();
      add(RuleAction.DOMAIN, normalizedDomain);
      add(RuleAction.DOMAIN_SUFFIX, normalizedDomain);
    }
  }

  addIp(metadata.destinationIP, source: false);
  addIp(metadata.sourceIP, source: true);
  for (final country in metadata.destinationGeoIP) {
    add(RuleAction.GEOIP, country.toUpperCase());
  }
  for (final country in metadata.sourceGeoIP) {
    add(RuleAction.SRC_GEOIP, country.toUpperCase());
  }
  add(RuleAction.IP_ASN, _normalizeAsn(metadata.destinationIPASN));
  add(RuleAction.SRC_IP_ASN, _normalizeAsn(metadata.sourceIPASN));
  add(RuleAction.PROCESS_NAME, metadata.process);
  add(RuleAction.PROCESS_PATH, metadata.processPath);
  if (metadata.uid > 0) {
    add(RuleAction.UID, metadata.uid.toString());
  }
  add(RuleAction.NETWORK, metadata.network.toUpperCase());
  add(RuleAction.DST_PORT, metadata.destinationPort);
  add(RuleAction.SRC_PORT, metadata.sourcePort);

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
  for (final group in groups) {
    for (final proxy in group.all) {
      add(proxy.name);
    }
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

QuickRoutingImpact buildQuickRoutingImpact(
  QuickRoutingCandidate candidate,
  Iterable<TrackerInfo> trackerInfos,
) {
  final hosts = <String>{};
  final processes = <String>{};
  var requestCount = 0;
  for (final trackerInfo in trackerInfos) {
    if (!_matchesQuickRoutingCandidate(candidate, trackerInfo)) {
      continue;
    }
    requestCount++;
    final host = _normalizeHost(trackerInfo.metadata.host);
    if (host.isNotEmpty) {
      hosts.add(host);
    }
    final process = trackerInfo.metadata.process.trim();
    if (process.isNotEmpty) {
      processes.add(process);
    }
  }
  final sortedHosts = hosts.toList()..sort();
  final sortedProcesses = processes.toList()..sort();
  return QuickRoutingImpact(
    requestCount: requestCount,
    hosts: List.unmodifiable(sortedHosts),
    processes: List.unmodifiable(sortedProcesses),
  );
}

bool _matchesQuickRoutingCandidate(
  QuickRoutingCandidate candidate,
  TrackerInfo trackerInfo,
) {
  final metadata = trackerInfo.metadata;
  final content = candidate.content;
  switch (candidate.ruleAction) {
    case RuleAction.DOMAIN:
      return _normalizeHost(metadata.host).toLowerCase() ==
          content.toLowerCase();
    case RuleAction.DOMAIN_SUFFIX:
      final host = _normalizeHost(metadata.host).toLowerCase();
      final suffix = content.toLowerCase();
      return host == suffix || host.endsWith('.$suffix');
    case RuleAction.IP_CIDR:
    case RuleAction.IP_CIDR6:
      return _matchesAddress(content, [metadata.destinationIP, metadata.host]);
    case RuleAction.SRC_IP_CIDR:
      return _matchesAddress(content, [metadata.sourceIP]);
    case RuleAction.GEOIP:
      return _containsIgnoreCase(metadata.destinationGeoIP, content);
    case RuleAction.SRC_GEOIP:
      return _containsIgnoreCase(metadata.sourceGeoIP, content);
    case RuleAction.IP_ASN:
      return _normalizeAsn(metadata.destinationIPASN) ==
          _normalizeAsn(content);
    case RuleAction.SRC_IP_ASN:
      return _normalizeAsn(metadata.sourceIPASN) == _normalizeAsn(content);
    case RuleAction.PROCESS_NAME:
      return metadata.process.toLowerCase() == content.toLowerCase();
    case RuleAction.PROCESS_PATH:
      return metadata.processPath.toLowerCase() == content.toLowerCase();
    case RuleAction.UID:
      return metadata.uid.toString() == content;
    case RuleAction.NETWORK:
      return metadata.network.toLowerCase() == content.toLowerCase();
    case RuleAction.DST_PORT:
      return metadata.destinationPort == content;
    case RuleAction.SRC_PORT:
      return metadata.sourcePort == content;
    default:
      return false;
  }
}

bool _matchesAddress(String cidr, Iterable<String> values) {
  final expected = cidr.split('/').first;
  return values.any((value) => _normalizeHost(value) == expected);
}

bool _containsIgnoreCase(Iterable<String> values, String expected) {
  final normalized = expected.toLowerCase();
  return values.any((value) => value.toLowerCase() == normalized);
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

String _normalizeAsn(String value) {
  final normalized = value.trim().toUpperCase();
  if (normalized.startsWith('AS')) {
    return normalized.substring(2);
  }
  return normalized;
}

String _trackerRuleText(TrackerInfo trackerInfo) {
  final payload = trackerInfo.rulePayload.trim();
  if (payload.isEmpty) {
    return trackerInfo.rule;
  }
  return '${trackerInfo.rule}($payload)';
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

Rule? _findExistingRule(
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

Future<void> _writePermanentRule(
  int profileId,
  OverwriteType overwriteType,
  Rule rule,
) async {
  switch (overwriteType) {
    case OverwriteType.standard:
      await database.rulesDao.putProfileAddedRule(profileId, rule);
    case OverwriteType.custom:
      await database.rulesDao.putProfileCustomRule(profileId, rule);
    case OverwriteType.script:
      throw StateError(
        'Script overwrite does not support permanent quick rules',
      );
  }
}

void _invalidatePermanentRuleState(
  WidgetRef ref,
  int profileId,
  OverwriteType overwriteType,
) {
  ref.invalidate(setupStateProvider(profileId));
  switch (overwriteType) {
    case OverwriteType.standard:
      ref.invalidate(profileAddedRulesProvider(profileId));
    case OverwriteType.custom:
      ref.invalidate(profileCustomRulesProvider(profileId));
    case OverwriteType.script:
      break;
  }
}

Future<void> _rollbackPermanentRule({
  required WidgetRef ref,
  required int profileId,
  required OverwriteType overwriteType,
  required Rule rule,
  required Rule? previous,
}) async {
  try {
    if (previous != null) {
      await _writePermanentRule(profileId, overwriteType, previous);
    } else {
      await database.rulesDao.delRules([rule.id]);
    }
    _invalidatePermanentRuleState(ref, profileId, overwriteType);
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

Future<Rule> _saveAndApplyPermanentRule({
  required WidgetRef ref,
  required int profileId,
  required OverwriteType overwriteType,
  required QuickRoutingCandidate candidate,
  required String target,
}) async {
  final rules = await _readPermanentRules(profileId, overwriteType);
  final previous = _findExistingRule(rules, candidate);
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
    await _writePermanentRule(profileId, overwriteType, rule);
    persisted = true;
    _invalidatePermanentRuleState(ref, profileId, overwriteType);
    final applied = await ref
        .read(setupActionProvider.notifier)
        .applyProfile(force: true);
    if (!applied) {
      throw StateError('Failed to apply permanent quick routing rule');
    }
    return rule;
  } catch (error, stackTrace) {
    if (persisted) {
      await _rollbackPermanentRule(
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

Future<Rule> _saveAndApplyRuntimeRule({
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

typedef _RuntimeRuleMutation = bool Function(QuickRoutingRules notifier);

Future<bool> _applyRuntimeRuleMutation({
  required WidgetRef ref,
  required _RuntimeRuleMutation mutation,
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
          ? await _saveAndApplyRuntimeRule(
              ref: ref,
              profileId: profileId,
              selection: selection,
              trackerInfo: widget.trackerInfo,
            )
          : await _saveAndApplyPermanentRule(
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
                  Text('${appLocalizations.proxyChains}: '
                      '${widget.trackerInfo.chains.join(' → ')}'),
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
      await _applyRuntimeRuleMutation(
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
      await _applyRuntimeRuleMutation(
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
      await _saveAndApplyPermanentRule(
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
    } catch (_) {
      ref.read(quickRoutingRulesProvider.notifier).replaceAll(snapshot);
      try {
        await ref
            .read(setupActionProvider.notifier)
            .applyProfile(force: true, silence: true);
      } catch (_) {}
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

  Widget _buildEntry(BuildContext context, QuickRoutingRuleEntry entry) {
    final busy = _busyRuleIds.contains(entry.rule.id);
    final expiration = entry.expiresAt?.showFull;
    final lifetime = _quickRoutingLifetimeLabel(context, entry.lifetime);
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
            expiration == null ? lifetime : '$lifetime · $expiration',
          ].join('\n'),
          maxLines: 3,
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
                for (final entry in entries) _buildEntry(context, entry),
              ],
            ),
    );
  }
}
