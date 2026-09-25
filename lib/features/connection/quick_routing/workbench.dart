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
    int? id,
    int? profileId,
    DateTime? createdAt,
    DateTime? checkedAt,
    TrackerInfo? trackerInfo,
    QuickRoutingSelection? selection,
    Rule? appliedRule,
    QuickRoutingVerification? verification,
  }) {
    return QuickRoutingVerificationRecord(
      id: id ?? this.id,
      profileId: profileId ?? this.profileId,
      createdAt: createdAt ?? this.createdAt,
      checkedAt: checkedAt ?? this.checkedAt,
      trackerInfo: trackerInfo ?? this.trackerInfo,
      selection: selection ?? this.selection,
      appliedRule: appliedRule ?? this.appliedRule,
      verification: verification ?? this.verification,
    );
  }
}

class QuickRoutingVerificationHistory
    extends Notifier<List<QuickRoutingVerificationRecord>> {
  static const maxEntries = 100;

  @override
  List<QuickRoutingVerificationRecord> build() {
    ref.listen<int?>(currentProfileIdProvider, (_, profileId) {
      if (profileId == null) {
        return;
      }
      unawaited(
        ref
            .read(quickRoutingDiagnosticsCoordinatorProvider)
            .hydrate(this, profileId),
      );
    }, fireImmediately: true);
    return const [];
  }

  Future<void> _persistMutation(
    Future<void> mutation,
    String action,
  ) async {
    try {
      await mutation;
    } catch (error, stackTrace) {
      commonPrint.log(
        'quick routing diagnostic $action failed: '
        '${compactError(error)}, $stackTrace',
        logLevel: LogLevel.warning,
      );
    }
  }

  List<QuickRoutingVerificationRecord> _bounded(
    Iterable<QuickRoutingVerificationRecord> entries,
  ) {
    final sorted = entries.toList(growable: false)
      ..sort((first, second) {
        final checked = second.checkedAt.compareTo(first.checkedAt);
        return checked != 0 ? checked : second.id.compareTo(first.id);
      });
    final counts = <int, int>{};
    final result = <QuickRoutingVerificationRecord>[];
    for (final entry in sorted) {
      final count = counts[entry.profileId] ?? 0;
      if (count >= maxEntries) {
        continue;
      }
      counts[entry.profileId] = count + 1;
      result.add(entry);
    }
    return List.unmodifiable(result);
  }

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
    final identity = quickRoutingVerificationRecordIdentityFor(
      profileId: profileId,
      trackerInfo: trackerInfo,
      appliedRule: appliedRule,
      target: selection.target,
    );
    QuickRoutingVerificationRecord? current;
    for (final entry in state) {
      if (quickRoutingVerificationRecordIdentity(entry) == identity) {
        current = entry;
        break;
      }
    }
    final entry = QuickRoutingVerificationRecord(
      id: current?.id ?? id ?? snowflake.id,
      profileId: profileId,
      createdAt: current?.createdAt ?? checkedAt,
      checkedAt: checkedAt,
      trackerInfo: trackerInfo,
      selection: selection,
      appliedRule: appliedRule,
      verification: verification,
    );
    return upsertRecord(entry);
  }

  QuickRoutingVerificationRecord upsertRecord(
    QuickRoutingVerificationRecord record,
  ) {
    final identity = quickRoutingVerificationRecordIdentity(record);
    final next = state
        .where(
          (entry) =>
              entry.id != record.id &&
              quickRoutingVerificationRecordIdentity(entry) != identity,
        )
        .toList(growable: true)
      ..add(record);
    state = _bounded(next);
    return record;
  }

  void mergePersisted(
    Iterable<QuickRoutingVerificationRecord> persisted,
  ) {
    final records = <String, QuickRoutingVerificationRecord>{};
    for (final record in persisted) {
      records[quickRoutingVerificationRecordIdentity(record)] = record;
    }
    // In-memory results may have been produced while the database was loading;
    // they are newer and must win over the persisted snapshot.
    for (final record in state) {
      records[quickRoutingVerificationRecordIdentity(record)] = record;
    }
    state = _bounded(records.values);
  }

  bool replaceRecord(QuickRoutingVerificationRecord record) {
    final identity = quickRoutingVerificationRecordIdentity(record);
    final index = state.indexWhere(
      (entry) =>
          entry.id == record.id ||
          quickRoutingVerificationRecordIdentity(entry) == identity,
    );
    if (index == -1) {
      return false;
    }
    final next = List<QuickRoutingVerificationRecord>.from(state);
    next[index] = record;
    state = _bounded(next);
    return true;
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
    return replaceRecord(
      state[index].copyWith(
        checkedAt: now ?? DateTime.now(),
        verification: verification,
      ),
    );
  }

  bool remove(int id, {bool persist = true}) {
    final next = state.where((entry) => entry.id != id).toList(growable: false);
    final changed = next.length != state.length;
    if (changed) {
      state = List.unmodifiable(next);
    }
    if (persist) {
      unawaited(
        _persistMutation(
          ref.read(quickRoutingDiagnosticsPersistenceProvider).remove(id),
          'delete',
        ),
      );
    }
    return changed;
  }

  bool clearProfile(int profileId, {bool persist = true}) {
    final next = state
        .where((entry) => entry.profileId != profileId)
        .toList(growable: false);
    final changed = next.length != state.length;
    if (changed) {
      state = List.unmodifiable(next);
    }
    if (persist) {
      unawaited(
        _persistMutation(
          ref
              .read(quickRoutingDiagnosticsPersistenceProvider)
              .clearProfile(profileId),
          'clear',
        ),
      );
    }
    return changed;
  }
}

final quickRoutingVerificationHistoryProvider = NotifierProvider<
    QuickRoutingVerificationHistory,
    List<QuickRoutingVerificationRecord>>(
  QuickRoutingVerificationHistory.new,
);

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

class _QuickRoutingRuntimeRulesPanel extends ConsumerWidget {
  final int profileId;

  const _QuickRoutingRuntimeRulesPanel({
    required this.profileId,
  });

  void _openManager(BuildContext context, WidgetRef ref) {
    if (ref.read(currentProfileIdProvider) != profileId) {
      dialogs.showNotifier(
        currentAppLocalizations.invalidPolicy(
          currentAppLocalizations.profile,
        ),
        level: MessageLevel.warning,
      );
      return;
    }
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
    final profileActive = ref.watch(currentProfileIdProvider) == profileId;

    return ListView(
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
        Card(
          child: ListTile(
            leading: const Icon(Icons.rule_folder_outlined),
            title: Text('${appLocalizations.rules}: ${entries.length}'),
            subtitle: Text(appLocalizations.expireTime),
            trailing: TextButton(
              onPressed: profileActive
                  ? () => _openManager(context, ref)
                  : null,
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
                onTap: profileActive
                    ? () => _openManager(context, ref)
                    : null,
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
                trailing: profileActive
                    ? const Icon(Icons.chevron_right)
                    : const Icon(Icons.lock_outline),
              ),
            ),
      ],
    );
  }
}
