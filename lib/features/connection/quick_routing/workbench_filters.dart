part of '../quick_routing.dart';

enum QuickRoutingVerificationFilter {
  all,
  attention,
  verified,
  approximate,
  mismatch,
  unavailable,
}

bool quickRoutingVerificationFilterMatches(
  QuickRoutingVerificationFilter filter,
  QuickRoutingVerificationStatus status,
) {
  return switch (filter) {
    QuickRoutingVerificationFilter.all => true,
    QuickRoutingVerificationFilter.attention =>
      status != QuickRoutingVerificationStatus.verified,
    QuickRoutingVerificationFilter.verified =>
      status == QuickRoutingVerificationStatus.verified,
    QuickRoutingVerificationFilter.approximate =>
      status == QuickRoutingVerificationStatus.approximate,
    QuickRoutingVerificationFilter.mismatch =>
      status == QuickRoutingVerificationStatus.mismatch,
    QuickRoutingVerificationFilter.unavailable =>
      status == QuickRoutingVerificationStatus.unavailable,
  };
}

Map<QuickRoutingVerificationStatus, int> countQuickRoutingVerificationStatuses(
  Iterable<QuickRoutingVerificationRecord> records,
) {
  final counts = <QuickRoutingVerificationStatus, int>{
    for (final status in QuickRoutingVerificationStatus.values) status: 0,
  };
  for (final record in records) {
    final status = record.verification.status;
    counts[status] = (counts[status] ?? 0) + 1;
  }
  return Map.unmodifiable(counts);
}

String quickRoutingVerificationSearchText(
  QuickRoutingVerificationRecord record,
) {
  final metadata = record.trackerInfo.metadata;
  final result = record.verification.result;
  return [
    record.appliedRule.rawValue,
    record.selection.target,
    record.selection.lifetime.name,
    record.verification.status.name,
    ...record.verification.issues,
    record.trackerInfo.id,
    record.trackerInfo.desc,
    metadata.host,
    metadata.sourceIP,
    metadata.sourcePort,
    metadata.destinationIP,
    metadata.destinationPort,
    metadata.process,
    metadata.processPath,
    metadata.network,
    metadata.sourceIPASN,
    metadata.destinationIPASN,
    if (result != null) ...[
      result.mode,
      result.ruleText,
      result.target,
      result.policyText,
      result.resolvedIP,
      ...result.providerNames,
      ...result.warnings,
    ],
  ].where((value) => value.trim().isNotEmpty).join('\n').toLowerCase();
}

List<QuickRoutingVerificationRecord> filterQuickRoutingVerificationRecords(
  Iterable<QuickRoutingVerificationRecord> records, {
  QuickRoutingVerificationFilter filter = QuickRoutingVerificationFilter.all,
  String query = '',
}) {
  final terms = query
      .trim()
      .toLowerCase()
      .split(RegExp(r'\s+'))
      .where((term) => term.isNotEmpty)
      .toList(growable: false);
  return List.unmodifiable(
    records.where((record) {
      if (!quickRoutingVerificationFilterMatches(
        filter,
        record.verification.status,
      )) {
        return false;
      }
      if (terms.isEmpty) {
        return true;
      }
      final text = quickRoutingVerificationSearchText(record);
      return terms.every(text.contains);
    }),
  );
}

String _quickRoutingVerificationFilterLabel(
  QuickRoutingVerificationFilter filter,
  int count,
) {
  final prefix = switch (filter) {
    QuickRoutingVerificationFilter.all => 'ALL',
    QuickRoutingVerificationFilter.attention => '!',
    QuickRoutingVerificationFilter.verified => '✓',
    QuickRoutingVerificationFilter.approximate => '≈',
    QuickRoutingVerificationFilter.mismatch => '⚠',
    QuickRoutingVerificationFilter.unavailable => '?',
  };
  return '$prefix $count';
}

int _quickRoutingVerificationFilterCount(
  QuickRoutingVerificationFilter filter,
  int total,
  Map<QuickRoutingVerificationStatus, int> counts,
) {
  return switch (filter) {
    QuickRoutingVerificationFilter.all => total,
    QuickRoutingVerificationFilter.attention =>
      total - (counts[QuickRoutingVerificationStatus.verified] ?? 0),
    QuickRoutingVerificationFilter.verified =>
      counts[QuickRoutingVerificationStatus.verified] ?? 0,
    QuickRoutingVerificationFilter.approximate =>
      counts[QuickRoutingVerificationStatus.approximate] ?? 0,
    QuickRoutingVerificationFilter.mismatch =>
      counts[QuickRoutingVerificationStatus.mismatch] ?? 0,
    QuickRoutingVerificationFilter.unavailable =>
      counts[QuickRoutingVerificationStatus.unavailable] ?? 0,
  };
}

class QuickRoutingDiagnosticsButton extends ConsumerWidget {
  const QuickRoutingDiagnosticsButton({super.key});

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
    final attentionCount = ref.watch(
      quickRoutingVerificationHistoryProvider.select(
        (entries) => profileId == null
            ? 0
            : entries
                  .where(
                    (entry) =>
                        entry.profileId == profileId &&
                        entry.verification.status !=
                            QuickRoutingVerificationStatus.verified,
                  )
                  .length,
      ),
    );
    final badgeCount = activeRuleCount + attentionCount;

    return IconButton(
      tooltip:
          '${context.appLocalizations.rules} · '
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
              builder: (_) => QuickRoutingDiagnosticsPage(profileId: profileId),
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

class QuickRoutingDiagnosticsPage extends ConsumerWidget {
  final int profileId;

  const QuickRoutingDiagnosticsPage({super.key, required this.profileId});

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
          title: Text('${appLocalizations.rules} · ${appLocalizations.core}'),
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
            _QuickRoutingFilteredHistoryPanel(profileId: profileId),
            _QuickRoutingRuntimeRulesPanel(profileId: profileId),
          ],
        ),
      ),
    );
  }
}

class _QuickRoutingFilteredHistoryPanel extends ConsumerStatefulWidget {
  final int profileId;

  const _QuickRoutingFilteredHistoryPanel({required this.profileId});

  @override
  ConsumerState<_QuickRoutingFilteredHistoryPanel> createState() =>
      _QuickRoutingFilteredHistoryPanelState();
}

class _QuickRoutingFilteredHistoryPanelState
    extends ConsumerState<_QuickRoutingFilteredHistoryPanel> {
  final _queryController = TextEditingController();
  final _busyIds = <int>{};
  QuickRoutingVerificationFilter _filter = QuickRoutingVerificationFilter.all;
  String _query = '';
  bool _batchBusy = false;
  int _batchDone = 0;
  int _batchTotal = 0;

  @override
  void dispose() {
    _queryController.dispose();
    super.dispose();
  }

  bool _ensureProfileActive() {
    if (ref.read(currentProfileIdProvider) == widget.profileId) {
      return true;
    }
    dialogs.showNotifier(
      currentAppLocalizations.invalidPolicy(currentAppLocalizations.profile),
      level: MessageLevel.warning,
    );
    return false;
  }

  Future<QuickRoutingVerification?> _recheck(
    QuickRoutingVerificationRecord record, {
    bool notify = true,
  }) async {
    if (_busyIds.contains(record.id) || !_ensureProfileActive()) {
      return null;
    }
    setState(() {
      _busyIds.add(record.id);
    });
    try {
      final verification = await _verifyAppliedQuickRoutingRule(
        ref: ref,
        trackerInfo: record.trackerInfo,
        selection: record.selection,
        profileId: widget.profileId,
      );
      if (mounted && notify) {
        dialogs.showNotifier(
          _quickRoutingVerificationSummary(context, verification),
          level: verification.messageLevel,
        );
      }
      return verification;
    } finally {
      if (mounted) {
        setState(() {
          _busyIds.remove(record.id);
        });
      }
    }
  }

  Future<void> _recheckBatch(
    List<QuickRoutingVerificationRecord> records,
  ) async {
    if (_batchBusy || records.isEmpty || !_ensureProfileActive()) {
      return;
    }
    final snapshot = List<QuickRoutingVerificationRecord>.of(records);
    final results = <QuickRoutingVerification>[];
    setState(() {
      _batchBusy = true;
      _batchDone = 0;
      _batchTotal = snapshot.length;
    });
    try {
      for (final record in snapshot) {
        if (!mounted || !_ensureProfileActive()) {
          break;
        }
        final verification = await _recheck(record, notify: false);
        if (verification != null) {
          results.add(verification);
        }
        if (mounted) {
          setState(() {
            _batchDone++;
          });
        }
      }
      if (!mounted) {
        return;
      }
      final verified = results
          .where(
            (item) => item.status == QuickRoutingVerificationStatus.verified,
          )
          .length;
      final approximate = results
          .where(
            (item) => item.status == QuickRoutingVerificationStatus.approximate,
          )
          .length;
      final mismatch = results
          .where(
            (item) => item.status == QuickRoutingVerificationStatus.mismatch,
          )
          .length;
      final unavailable = results
          .where(
            (item) => item.status == QuickRoutingVerificationStatus.unavailable,
          )
          .length;
      dialogs.showNotifier(
        '${context.appLocalizations.update}: '
        '✓ $verified · ≈ $approximate · ⚠ $mismatch · ? $unavailable',
        level: mismatch > 0
            ? MessageLevel.error
            : approximate > 0 || unavailable > 0
            ? MessageLevel.warning
            : MessageLevel.success,
      );
    } finally {
      if (mounted) {
        setState(() {
          _batchBusy = false;
          _batchDone = 0;
          _batchTotal = 0;
        });
      }
    }
  }

  void _openDetails(QuickRoutingVerificationRecord record) {
    unawaited(
      Navigator.of(context).push<void>(
        MaterialPageRoute(
          builder: (_) => _QuickRoutingConflictDetailsPage(
            profileId: widget.profileId,
            recordId: record.id,
          ),
        ),
      ),
    );
  }

  Widget _buildControls(
    BuildContext context,
    List<QuickRoutingVerificationRecord> allRecords,
    List<QuickRoutingVerificationRecord> visibleRecords,
  ) {
    final counts = countQuickRoutingVerificationStatuses(allRecords);
    final appLocalizations = context.appLocalizations;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        TextField(
          controller: _queryController,
          decoration: InputDecoration(
            prefixIcon: const Icon(Icons.search),
            hintText: appLocalizations.search,
            suffixIcon: _query.isEmpty
                ? null
                : IconButton(
                    tooltip: appLocalizations.delete,
                    onPressed: () {
                      _queryController.clear();
                      setState(() {
                        _query = '';
                      });
                    },
                    icon: const Icon(Icons.clear),
                  ),
          ),
          onChanged: (value) {
            setState(() {
              _query = value;
            });
          },
        ),
        const SizedBox(height: 10),
        SingleChildScrollView(
          scrollDirection: Axis.horizontal,
          child: Row(
            children: [
              for (final filter in QuickRoutingVerificationFilter.values) ...[
                ChoiceChip(
                  label: Text(
                    _quickRoutingVerificationFilterLabel(
                      filter,
                      _quickRoutingVerificationFilterCount(
                        filter,
                        allRecords.length,
                        counts,
                      ),
                    ),
                  ),
                  selected: _filter == filter,
                  onSelected: (_) {
                    setState(() {
                      _filter = filter;
                    });
                  },
                ),
                const SizedBox(width: 8),
              ],
            ],
          ),
        ),
        const SizedBox(height: 8),
        Wrap(
          alignment: WrapAlignment.spaceBetween,
          crossAxisAlignment: WrapCrossAlignment.center,
          spacing: 12,
          runSpacing: 8,
          children: [
            Text(
              '${appLocalizations.status}: '
              '${visibleRecords.length}/${allRecords.length}',
            ),
            if (_batchBusy) Text('$_batchDone/$_batchTotal'),
            FilledButton.tonalIcon(
              onPressed: _batchBusy || visibleRecords.isEmpty
                  ? null
                  : () => _recheckBatch(visibleRecords),
              icon: _batchBusy
                  ? const SizedBox.square(
                      dimension: 18,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.refresh),
              label: Text(appLocalizations.update),
            ),
          ],
        ),
        if (_batchBusy) ...[
          const SizedBox(height: 8),
          LinearProgressIndicator(
            value: _batchTotal == 0 ? null : _batchDone / _batchTotal,
          ),
        ],
      ],
    );
  }

  @override
  Widget build(BuildContext context) {
    final allRecords = ref.watch(
      quickRoutingVerificationHistoryProvider.select(
        (entries) => entries
            .where((entry) => entry.profileId == widget.profileId)
            .toList(growable: false),
      ),
    );
    final records = filterQuickRoutingVerificationRecords(
      allRecords,
      filter: _filter,
      query: _query,
    );
    final appLocalizations = context.appLocalizations;

    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(12, 12, 12, 4),
          child: _buildControls(context, allRecords, records),
        ),
        const Divider(height: 16),
        Expanded(
          child: records.isEmpty
              ? Center(child: Text(appLocalizations.noData))
              : ListView.builder(
                  padding: const EdgeInsets.fromLTRB(12, 0, 12, 12),
                  itemCount: records.length,
                  itemBuilder: (context, index) {
                    final record = records[index];
                    final result = record.verification.result;
                    final busy = _busyIds.contains(record.id);
                    final destination =
                        [
                          record.trackerInfo.metadata.host,
                          record.trackerInfo.metadata.destinationIP,
                        ].firstWhere(
                          (value) => value.trim().isNotEmpty,
                          orElse: () => record.trackerInfo.desc,
                        );
                    final actual = result == null
                        ? '${appLocalizations.core}: '
                              '${appLocalizations.unknown}'
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
                                child: CircularProgressIndicator(
                                  strokeWidth: 2,
                                ),
                              )
                            : IconButton(
                                tooltip: appLocalizations.update,
                                onPressed: () => _recheck(record),
                                icon: const Icon(Icons.refresh),
                              ),
                      ),
                    );
                  },
                ),
        ),
      ],
    );
  }
}
