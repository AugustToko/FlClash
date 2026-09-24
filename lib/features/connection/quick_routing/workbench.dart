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
