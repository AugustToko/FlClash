part of '../quick_routing.dart';

@immutable
class QuickRoutingVerificationRecord {
  final int id;
  final int profileId;
  final DateTime createdAt;
  final DateTime checkedAt;
  final TrackerInfo trackerInfo;
  final QuickRoutingSelection selection;
  final Rule appliedRule;
  final QuickRoutingVerification verification;

  const QuickRoutingVerificationRecord({
    required this.id,
    required this.profileId,
    required this.createdAt,
    required this.checkedAt,
    required this.trackerInfo,
    required this.selection,
    required this.appliedRule,
    required this.verification,
  });

  QuickRoutingVerificationRecord copyWith({
    DateTime? checkedAt,
    QuickRoutingVerification? verification,
  }) {
    return QuickRoutingVerificationRecord(
      id: id,
      profileId: profileId,
      createdAt: createdAt,
      checkedAt: checkedAt ?? this.checkedAt,
      trackerInfo: trackerInfo,
      selection: selection,
      appliedRule: appliedRule,
      verification: verification ?? this.verification,
    );
  }
}

class QuickRoutingVerificationHistory
    extends Notifier<List<QuickRoutingVerificationRecord>> {
  static const maxEntries = 100;

  @override
  List<QuickRoutingVerificationRecord> build() => const [];

  QuickRoutingVerificationRecord upsert({
    required int profileId,
    required TrackerInfo trackerInfo,
    required QuickRoutingSelection selection,
    required Rule appliedRule,
    required QuickRoutingVerification verification,
    DateTime? now,
    int? id,
  }) {
    final checkedAt = now ?? DateTime.now();
    final existingIndex = state.indexWhere(
      (entry) =>
          entry.profileId == profileId &&
          entry.trackerInfo.id == trackerInfo.id &&
          quickRoutingRulesHaveSameMatcher(
            entry.appliedRule,
            appliedRule,
          ) &&
          entry.selection.target == selection.target,
    );
    if (existingIndex != -1) {
      final current = state[existingIndex];
      final updated = QuickRoutingVerificationRecord(
        id: current.id,
        profileId: profileId,
        createdAt: current.createdAt,
        checkedAt: checkedAt,
        trackerInfo: trackerInfo,
        selection: selection,
        appliedRule: appliedRule,
        verification: verification,
      );
      final next = List<QuickRoutingVerificationRecord>.from(state)
        ..removeAt(existingIndex)
        ..insert(0, updated);
      state = List.unmodifiable(next);
      return updated;
    }

    final entry = QuickRoutingVerificationRecord(
      id: id ?? snowflake.id,
      profileId: profileId,
      createdAt: checkedAt,
      checkedAt: checkedAt,
      trackerInfo: trackerInfo,
      selection: selection,
      appliedRule: appliedRule,
      verification: verification,
    );
    state = List.unmodifiable(
      <QuickRoutingVerificationRecord>[entry, ...state].take(maxEntries),
    );
    return entry;
  }

  bool updateVerification(
    int id,
    QuickRoutingVerification verification, {
    DateTime? now,
  }) {
    final index = state.indexWhere((entry) => entry.id == id);
    if (index == -1) {
      return false;
    }
    final next = List<QuickRoutingVerificationRecord>.from(state);
    next[index] = next[index].copyWith(
      checkedAt: now ?? DateTime.now(),
      verification: verification,
    );
    state = List.unmodifiable(next);
    return true;
  }

  bool remove(int id) {
    final next = state.where((entry) => entry.id != id).toList(growable: false);
    if (next.length == state.length) {
      return false;
    }
    state = List.unmodifiable(next);
    return true;
  }

  bool clearProfile(int profileId) {
    final next = state
        .where((entry) => entry.profileId != profileId)
        .toList(growable: false);
    if (next.length == state.length) {
      return false;
    }
    state = List.unmodifiable(next);
    return true;
  }
}

final quickRoutingVerificationHistoryProvider = NotifierProvider<
    QuickRoutingVerificationHistory,
    List<QuickRoutingVerificationRecord>>(
  QuickRoutingVerificationHistory.new,
);

void _recordQuickRoutingVerification({
  required WidgetRef ref,
  required TrackerInfo trackerInfo,
  required QuickRoutingSelection selection,
  required QuickRoutingVerification verification,
}) {
  final profileId = ref.read(currentProfileIdProvider);
  if (profileId == null) {
    return;
  }
  ref.read(quickRoutingVerificationHistoryProvider.notifier).upsert(
        profileId: profileId,
        trackerInfo: trackerInfo,
        selection: selection,
        appliedRule: selection.candidate.buildRule(
          target: selection.target,
          id: -1,
        ),
        verification: verification,
      );
}

enum QuickRoutingConflictKind {
  equivalent,
  competing,
  opaque,
}

@immutable
class QuickRoutingConflictEntry {
  final int index;
  final Rule rule;
  final QuickRoutingConflictKind kind;

  const QuickRoutingConflictEntry({
    required this.index,
    required this.rule,
    required this.kind,
  });
}

List<QuickRoutingConflictEntry> buildQuickRoutingConflictEntries({
  required QuickRoutingSelection selection,
  required TrackerInfo trackerInfo,
  required Iterable<Rule> knownRules,
}) {
  final rules = knownRules.toList(growable: false);
  final proposed = selection.candidate.buildRule(
    target: selection.target,
    id: -1,
  );
  final matches = <_QuickRoutingKnownRuleMatch>[];
  var firstDefiniteMatch = -1;

  for (var index = 0; index < rules.length; index++) {
    final match = _matchKnownQuickRoutingRule(rules[index], trackerInfo);
    matches.add(match);
    if (firstDefiniteMatch == -1 &&
        match == _QuickRoutingKnownRuleMatch.match) {
      firstDefiniteMatch = index;
    }
  }

  final entries = <QuickRoutingConflictEntry>[];
  for (var index = 0; index < rules.length; index++) {
    final rule = rules[index];
    if (quickRoutingRulesHaveSameMatcher(rule, proposed)) {
      entries.add(
        QuickRoutingConflictEntry(
          index: index,
          rule: rule,
          kind: QuickRoutingConflictKind.equivalent,
        ),
      );
      continue;
    }

    final match = matches[index];
    if (match == _QuickRoutingKnownRuleMatch.match &&
        rule.ruleTarget != selection.target) {
      entries.add(
        QuickRoutingConflictEntry(
          index: index,
          rule: rule,
          kind: QuickRoutingConflictKind.competing,
        ),
      );
      continue;
    }

    if (match == _QuickRoutingKnownRuleMatch.unknown &&
        (firstDefiniteMatch == -1 || index < firstDefiniteMatch)) {
      entries.add(
        QuickRoutingConflictEntry(
          index: index,
          rule: rule,
          kind: QuickRoutingConflictKind.opaque,
        ),
      );
    }
  }
  return List.unmodifiable(entries);
}

class QuickRoutingWorkbenchButton extends ConsumerWidget {
  const QuickRoutingWorkbenchButton({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final profileId = ref.watch(currentProfileIdProvider);
    final activeRuleCount = ref.watch(
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
    final mismatchCount = ref.watch(
      quickRoutingVerificationHistoryProvider.select(
        (entries) => profileId == null
            ? 0
            : entries
                .where(
                  (entry) =>
                      entry.profileId == profileId &&
                      entry.verification.status ==
                          QuickRoutingVerificationStatus.mismatch,
                )
                .length,
      ),
    );
    final badgeCount = activeRuleCount + mismatchCount;

    return IconButton(
      tooltip: '${context.appLocalizations.rules} · '
          '${context.appLocalizations.core}',
      onPressed: () {
        if (profileId == null) {
          dialogs.showNotifier(
            currentAppLocalizations.nullProfileDesc,
            level: MessageLevel.warning,
          );
          return;
        }
        unawaited(
          Navigator.of(context).push<void>(
            MaterialPageRoute(
              builder: (_) => QuickRoutingWorkbenchPage(
                profileId: profileId,
              ),
            ),
          ),
        );
      },
      icon: badgeCount == 0
          ? const Icon(Icons.manage_search)
          : Badge.count(
              count: badgeCount,
              child: const Icon(Icons.manage_search),
            ),
    );
  }
}

class QuickRoutingWorkbenchPage extends ConsumerWidget {
  final int profileId;

  const QuickRoutingWorkbenchPage({
    super.key,
    required this.profileId,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final historyCount = ref.watch(
      quickRoutingVerificationHistoryProvider.select(
        (entries) =>
            entries.where((entry) => entry.profileId == profileId).length,
      ),
    );
    final appLocalizations = context.appLocalizations;

    return DefaultTabController(
      length: 2,
      child: Scaffold(
        appBar: AppBar(
          title: Text(
            '${appLocalizations.rules} · ${appLocalizations.core}',
          ),
          actions: [
            IconButton(
              tooltip: appLocalizations.delete,
              onPressed: historyCount == 0
                  ? null
                  : () {
                      ref
                          .read(
                            quickRoutingVerificationHistoryProvider.notifier,
                          )
                          .clearProfile(profileId);
                    },
              icon: const Icon(Icons.delete_sweep_outlined),
            ),
          ],
          bottom: TabBar(
            tabs: [
              Tab(
                icon: const Icon(Icons.fact_check_outlined),
                text: '${appLocalizations.status} ($historyCount)',
              ),
              Tab(
                icon: const Icon(Icons.rule_folder_outlined),
                text: appLocalizations.rules,
              ),
            ],
          ),
        ),
        body: TabBarView(
          children: [
            _QuickRoutingVerificationHistoryPanel(profileId: profileId),
            _QuickRoutingRuntimeRulesPanel(profileId: profileId),
          ],
        ),
      ),
    );
  }
}

class _QuickRoutingVerificationHistoryPanel
    extends ConsumerStatefulWidget {
  final int profileId;

  const _QuickRoutingVerificationHistoryPanel({
    required this.profileId,
  });

  @override
  ConsumerState<_QuickRoutingVerificationHistoryPanel> createState() =>
      _QuickRoutingVerificationHistoryPanelState();
}

class _QuickRoutingVerificationHistoryPanelState
    extends ConsumerState<_QuickRoutingVerificationHistoryPanel> {
  final _busyIds = <int>{};

  Future<void> _recheck(
    QuickRoutingVerificationRecord record,
  ) async {
    if (_busyIds.contains(record.id)) {
      return;
    }
    setState(() {
      _busyIds.add(record.id);
    });
    final verification = await _verifyAppliedQuickRoutingRule(
      ref: ref,
      trackerInfo: record.trackerInfo,
      selection: record.selection,
    );
    if (mounted) {
      dialogs.showNotifier(
        _quickRoutingVerificationSummary(context, verification),
        level: verification.messageLevel,
      );
      setState(() {
        _busyIds.remove(record.id);
      });
    }
  }

  void _openDetails(QuickRoutingVerificationRecord record) {
    unawaited(
      Navigator.of(context).push<void>(
        MaterialPageRoute(
          builder: (_) => _QuickRoutingVerificationDetailsPage(
            profileId: widget.profileId,
            recordId: record.id,
          ),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final records = ref.watch(
      quickRoutingVerificationHistoryProvider.select(
        (entries) => entries
            .where((entry) => entry.profileId == widget.profileId)
            .toList(growable: false),
      ),
    );
    final appLocalizations = context.appLocalizations;

    if (records.isEmpty) {
      return Center(child: Text(appLocalizations.noData));
    }

    return ListView.builder(
      padding: const EdgeInsets.all(12),
      itemCount: records.length,
      itemBuilder: (context, index) {
        final record = records[index];
        final result = record.verification.result;
        final busy = _busyIds.contains(record.id);
        final destination = [
          record.trackerInfo.metadata.host,
          record.trackerInfo.metadata.destinationIP,
        ].firstWhere(
          (value) => value.trim().isNotEmpty,
          orElse: () => record.trackerInfo.desc,
        );
        final actual = result == null
            ? '${appLocalizations.core}: ${appLocalizations.unknown}'
            : '${result.ruleText.isEmpty ? result.mode.toUpperCase() : result.ruleText}'
                ' → ${result.target}';

        return Card(
          margin: const EdgeInsets.only(bottom: 8),
          child: ListTile(
            onTap: () => _openDetails(record),
            leading: CircleAvatar(
              child: Text(record.verification.marker),
            ),
            title: Text(
              record.appliedRule.rawValue,
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
            ),
            subtitle: Text(
              [
                record.checkedAt.showFull,
                if (destination.isNotEmpty) destination,
                actual,
              ].join('\n'),
              maxLines: 4,
              overflow: TextOverflow.ellipsis,
            ),
            trailing: busy
                ? const SizedBox.square(
                    dimension: 20,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : IconButton(
                    tooltip: appLocalizations.update,
                    onPressed: () => _recheck(record),
                    icon: const Icon(Icons.refresh),
                  ),
          ),
        );
      },
    );
  }
}

class _QuickRoutingRuntimeRulesPanel extends ConsumerWidget {
  final int profileId;

  const _QuickRoutingRuntimeRulesPanel({
    required this.profileId,
  });

  void _openManager(BuildContext context) {
    unawaited(
      dialogs.showCommonDialog<void>(
        child: _QuickRoutingRuleManagerDialog(profileId: profileId),
      ),
    );
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final entries = ref.watch(
      quickRoutingRulesProvider.select(
        (entries) => entries
            .where(
              (entry) =>
                  entry.profileId == profileId && !entry.isExpired(),
            )
            .toList(growable: false),
      ),
    );
    final appLocalizations = context.appLocalizations;

    return ListView(
      padding: const EdgeInsets.all(12),
      children: [
        Card(
          child: ListTile(
            leading: const Icon(Icons.rule_folder_outlined),
            title: Text('${appLocalizations.rules}: ${entries.length}'),
            subtitle: Text(appLocalizations.expireTime),
            trailing: TextButton(
              onPressed: () => _openManager(context),
              child: Text(appLocalizations.edit),
            ),
          ),
        ),
        const SizedBox(height: 4),
        if (entries.isEmpty)
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 32),
            child: Center(child: Text(appLocalizations.noData)),
          )
        else
          for (var index = 0; index < entries.length; index++)
            Card(
              margin: const EdgeInsets.only(bottom: 8),
              child: ListTile(
                onTap: () => _openManager(context),
                leading: CircleAvatar(child: Text('${index + 1}')),
                title: Text(
                  entries[index].rule.rawValue,
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                ),
                subtitle: Text(
                  [
                    _quickRoutingLifetimeLabel(
                      context,
                      entries[index].lifetime,
                    ),
                    if (entries[index].expiresAt != null)
                      entries[index].expiresAt!.showFull,
                    if (entries[index].sourceDesc.isNotEmpty)
                      entries[index].sourceDesc,
                  ].join(' · '),
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                ),
                trailing: const Icon(Icons.chevron_right),
              ),
            ),
      ],
    );
  }
}

class _QuickRoutingVerificationDetailsPage
    extends ConsumerStatefulWidget {
  final int profileId;
  final int recordId;

  const _QuickRoutingVerificationDetailsPage({
    required this.profileId,
    required this.recordId,
  });

  @override
  ConsumerState<_QuickRoutingVerificationDetailsPage> createState() =>
      _QuickRoutingVerificationDetailsPageState();
}

class _QuickRoutingVerificationDetailsPageState
    extends ConsumerState<_QuickRoutingVerificationDetailsPage> {
  List<Rule> _knownRules = const [];
  bool _loadingRules = true;
  bool _rechecking = false;

  @override
  void initState() {
    super.initState();
    unawaited(_refreshRules());
  }

  Future<void> _refreshRules() async {
    if (mounted) {
      setState(() {
        _loadingRules = true;
      });
    }
    try {
      final overwriteType = ref.read(
        overwriteTypeProvider(widget.profileId),
      );
      final rules = await _readEffectiveQuickRoutingRules(
        ref: ref,
        profileId: widget.profileId,
        overwriteType: overwriteType,
      );
      if (mounted) {
        setState(() {
          _knownRules = rules;
        });
      }
    } catch (error, stackTrace) {
      commonPrint.log(
        'quick routing conflict scan failed: '
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
    QuickRoutingVerificationRecord record,
  ) async {
    if (_rechecking) {
      return;
    }
    setState(() {
      _rechecking = true;
    });
    await _verifyAppliedQuickRoutingRule(
      ref: ref,
      trackerInfo: record.trackerInfo,
      selection: record.selection,
    );
    await _refreshRules();
    if (mounted) {
      setState(() {
        _rechecking = false;
      });
    }
  }

  String _issueLabel(BuildContext context, String issue) {
    final appLocalizations = context.appLocalizations;
    return switch (issue) {
      'core-unavailable' =>
        '${appLocalizations.core}: ${appLocalizations.unknown}',
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

  String _conflictLabel(
    BuildContext context,
    QuickRoutingConflictKind kind,
  ) {
    final appLocalizations = context.appLocalizations;
    return switch (kind) {
      QuickRoutingConflictKind.equivalent =>
        appLocalizations.selected,
      QuickRoutingConflictKind.competing =>
        appLocalizations.update,
      QuickRoutingConflictKind.opaque =>
        appLocalizations.unknown,
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

  @override
  Widget build(BuildContext context) {
    final record = ref.watch(
      quickRoutingVerificationHistoryProvider.select(
        (entries) {
          for (final entry in entries) {
            if (entry.id == widget.recordId) {
              return entry;
            }
          }
          return null;
        },
      ),
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

    return Scaffold(
      appBar: AppBar(
        title: Text(appLocalizations.details(appLocalizations.rule)),
        actions: [
          IconButton(
            tooltip: appLocalizations.update,
            onPressed: _rechecking ? null : () => _recheck(record),
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
            _section(
              context: context,
              title: appLocalizations.preview,
              children: [
                Text(record.appliedRule.rawValue),
                Text(
                  '${appLocalizations.expireTime}: '
                  '${_quickRoutingLifetimeLabel(context, record.selection.lifetime)}',
                ),
                Text(
                  '${appLocalizations.time}: ${record.checkedAt.showFull}',
                ),
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
                children: _buildCoreQuickRoutingMatchPreview(
                  context,
                  result,
                ),
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
              title: '${appLocalizations.rules} · '
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
                    ListTile(
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
                        _conflictLabel(context, conflict.kind),
                      ),
                    ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
