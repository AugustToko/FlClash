import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/models/models.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

enum QuickRoutingLifetime {
  session,
  tenMinutes,
  oneHour,
  network,
  permanent,
}

extension QuickRoutingLifetimeExt on QuickRoutingLifetime {
  Duration? get duration {
    return switch (this) {
      QuickRoutingLifetime.tenMinutes => const Duration(minutes: 10),
      QuickRoutingLifetime.oneHour => const Duration(hours: 1),
      QuickRoutingLifetime.session ||
      QuickRoutingLifetime.network ||
      QuickRoutingLifetime.permanent => null,
    };
  }

  bool get isRuntime => this != QuickRoutingLifetime.permanent;
}

class QuickRoutingGroupOverride {
  final String groupName;
  final String previousFixed;
  final String? _expectedFixed;
  final String desiredFixed;

  const QuickRoutingGroupOverride({
    required this.groupName,
    required this.previousFixed,
    String? expectedFixed,
    required this.desiredFixed,
  }) : _expectedFixed = expectedFixed;

  String get expectedFixed => _expectedFixed ?? previousFixed;
  bool get changes => expectedFixed != desiredFixed;
  bool get clearsFixed => desiredFixed.isEmpty;

  QuickRoutingGroupOverride copyWith({
    String? groupName,
    String? previousFixed,
    String? expectedFixed,
    String? desiredFixed,
  }) {
    return QuickRoutingGroupOverride(
      groupName: groupName ?? this.groupName,
      previousFixed: previousFixed ?? this.previousFixed,
      expectedFixed: expectedFixed ?? this.expectedFixed,
      desiredFixed: desiredFixed ?? this.desiredFixed,
    );
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        other is QuickRoutingGroupOverride &&
            groupName == other.groupName &&
            previousFixed == other.previousFixed &&
            expectedFixed == other.expectedFixed &&
            desiredFixed == other.desiredFixed;
  }

  @override
  int get hashCode => Object.hash(
    groupName,
    previousFixed,
    expectedFixed,
    desiredFixed,
  );
}

class QuickRoutingGroupOverrideTransition {
  final int profileId;
  final String groupName;
  final String expectedFixed;
  final String targetFixed;

  const QuickRoutingGroupOverrideTransition({
    required this.profileId,
    required this.groupName,
    required this.expectedFixed,
    required this.targetFixed,
  });

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        other is QuickRoutingGroupOverrideTransition &&
            profileId == other.profileId &&
            groupName == other.groupName &&
            expectedFixed == other.expectedFixed &&
            targetFixed == other.targetFixed;
  }

  @override
  int get hashCode => Object.hash(
    profileId,
    groupName,
    expectedFixed,
    targetFixed,
  );
}

class QuickRoutingRuleEntry {
  final int profileId;
  final Rule rule;
  final QuickRoutingLifetime lifetime;
  final DateTime createdAt;
  final DateTime? expiresAt;
  final String sourceId;
  final String sourceDesc;
  final String previousRule;
  final List<String> previousChains;
  final QuickRoutingGroupOverride? groupOverride;

  const QuickRoutingRuleEntry({
    required this.profileId,
    required this.rule,
    required this.lifetime,
    required this.createdAt,
    required this.expiresAt,
    required this.sourceId,
    required this.sourceDesc,
    required this.previousRule,
    required this.previousChains,
    this.groupOverride,
  });

  factory QuickRoutingRuleEntry.create({
    required int profileId,
    required Rule rule,
    required QuickRoutingLifetime lifetime,
    required String sourceId,
    required String sourceDesc,
    required String previousRule,
    required List<String> previousChains,
    QuickRoutingGroupOverride? groupOverride,
    DateTime? now,
  }) {
    if (!lifetime.isRuntime) {
      throw ArgumentError.value(lifetime, 'lifetime');
    }
    final createdAt = now ?? DateTime.now();
    final duration = lifetime.duration;
    return QuickRoutingRuleEntry(
      profileId: profileId,
      rule: rule,
      lifetime: lifetime,
      createdAt: createdAt,
      expiresAt: duration == null ? null : createdAt.add(duration),
      sourceId: sourceId,
      sourceDesc: sourceDesc,
      previousRule: previousRule,
      previousChains: List.unmodifiable(previousChains),
      groupOverride: groupOverride,
    );
  }

  QuickRoutingRuleEntry copyWithGroupOverride(
    QuickRoutingGroupOverride? value,
  ) {
    return QuickRoutingRuleEntry(
      profileId: profileId,
      rule: rule,
      lifetime: lifetime,
      createdAt: createdAt,
      expiresAt: expiresAt,
      sourceId: sourceId,
      sourceDesc: sourceDesc,
      previousRule: previousRule,
      previousChains: previousChains,
      groupOverride: value,
    );
  }

  bool isExpired([DateTime? value]) {
    final expiresAt = this.expiresAt;
    if (expiresAt == null) {
      return false;
    }
    final now = value ?? DateTime.now();
    return !expiresAt.isAfter(now);
  }
}

bool quickRoutingRulesHaveSameMatcher(Rule first, Rule second) {
  return first.ruleAction == second.ruleAction &&
      first.content == second.content &&
      first.ruleProvider == second.ruleProvider &&
      first.subRule == second.subRule &&
      first.noResolve == second.noResolve &&
      first.src == second.src;
}

({List<Rule> rules, List<Rule> addedRules}) mergeQuickRoutingRules({
  required OverwriteType overwriteType,
  required List<Rule> runtimeRules,
  required List<Rule> rules,
  required List<Rule> addedRules,
}) {
  if (runtimeRules.isEmpty) {
    return (rules: rules, addedRules: addedRules);
  }
  if (overwriteType == OverwriteType.custom && rules.isNotEmpty) {
    return (
      rules: [...runtimeRules, ...rules],
      addedRules: addedRules,
    );
  }
  return (
    rules: rules,
    addedRules: [...runtimeRules, ...addedRules],
  );
}

Map<(int, String), QuickRoutingGroupOverride> _quickRoutingGroupOverrides(
  Iterable<QuickRoutingRuleEntry> entries, {
  DateTime? now,
  bool includeExpired = true,
}) {
  final current = now ?? DateTime.now();
  final values = <(int, String), QuickRoutingGroupOverride>{};
  for (final entry in entries) {
    if (!includeExpired && entry.isExpired(current)) {
      continue;
    }
    final override = entry.groupOverride;
    if (override != null) {
      values.putIfAbsent(
        (entry.profileId, override.groupName),
        () => override,
      );
    }
  }
  return values;
}

List<QuickRoutingGroupOverrideTransition>
    buildQuickRoutingGroupOverrideTransitions({
  required Iterable<QuickRoutingRuleEntry> previous,
  required Iterable<QuickRoutingRuleEntry> next,
  DateTime? now,
}) {
  final previousOverrides = _quickRoutingGroupOverrides(previous);
  final nextOverrides = _quickRoutingGroupOverrides(
    next,
    now: now,
    includeExpired: false,
  );
  final keys = <(int, String)>{
    ...previousOverrides.keys,
    ...nextOverrides.keys,
  };
  final transitions = <QuickRoutingGroupOverrideTransition>[];
  for (final key in keys) {
    final before = previousOverrides[key];
    final after = nextOverrides[key];
    if (before == after) {
      continue;
    }
    final expected = before?.desiredFixed ?? after!.expectedFixed;
    final target = after?.desiredFixed ?? before!.previousFixed;
    if (expected == target) {
      continue;
    }
    transitions.add(
      QuickRoutingGroupOverrideTransition(
        profileId: key.$1,
        groupName: key.$2,
        expectedFixed: expected,
        targetFixed: target,
      ),
    );
  }
  return List.unmodifiable(transitions);
}

class QuickRoutingRules extends Notifier<List<QuickRoutingRuleEntry>> {
  @override
  List<QuickRoutingRuleEntry> build() => const [];

  List<QuickRoutingRuleEntry> activeEntriesFor(
    int profileId, {
    DateTime? now,
  }) {
    final current = now ?? DateTime.now();
    return state
        .where(
          (entry) =>
              entry.profileId == profileId && !entry.isExpired(current),
        )
        .toList(growable: false);
  }

  List<Rule> activeRulesFor(int profileId, {DateTime? now}) {
    return activeEntriesFor(
      profileId,
      now: now,
    ).map((entry) => entry.rule).toList(growable: false);
  }

  DateTime? get nextExpiry {
    DateTime? next;
    for (final entry in state) {
      final expiresAt = entry.expiresAt;
      if (expiresAt == null) {
        continue;
      }
      if (next == null || expiresAt.isBefore(next)) {
        next = expiresAt;
      }
    }
    return next;
  }

  QuickRoutingRuleEntry put({
    required int profileId,
    required Rule rule,
    required QuickRoutingLifetime lifetime,
    required String sourceId,
    required String sourceDesc,
    required String previousRule,
    required List<String> previousChains,
    QuickRoutingGroupOverride? groupOverride,
    DateTime? now,
  }) {
    final current = now ?? DateTime.now();
    final entries = state
        .where((entry) => !entry.isExpired(current))
        .toList(growable: true);
    final existingIndex = entries.indexWhere(
      (entry) =>
          entry.profileId == profileId &&
          quickRoutingRulesHaveSameMatcher(entry.rule, rule),
    );
    final normalizedRule = existingIndex == -1
        ? rule
        : rule.copyWith(id: entries[existingIndex].rule.id);

    var normalizedOverride = groupOverride;
    if (normalizedOverride != null) {
      for (var index = 0; index < entries.length; index++) {
        final existingEntry = entries[index];
        final existingOverride = existingEntry.groupOverride;
        if (existingEntry.profileId != profileId ||
            existingOverride?.groupName != normalizedOverride.groupName) {
          continue;
        }
        normalizedOverride = normalizedOverride.copyWith(
          previousFixed: existingOverride!.previousFixed,
        );
        entries[index] = existingEntry.copyWithGroupOverride(null);
      }
    }

    final entry = QuickRoutingRuleEntry.create(
      profileId: profileId,
      rule: normalizedRule,
      lifetime: lifetime,
      sourceId: sourceId,
      sourceDesc: sourceDesc,
      previousRule: previousRule,
      previousChains: previousChains,
      groupOverride: normalizedOverride,
      now: current,
    );
    if (existingIndex != -1) {
      entries.removeWhere(
        (value) =>
            value.profileId == profileId &&
            quickRoutingRulesHaveSameMatcher(value.rule, rule),
      );
    }
    entries.insert(0, entry);
    state = List.unmodifiable(entries);
    return entry;
  }

  bool move(int profileId, int ruleId, int offset, {DateTime? now}) {
    if (offset == 0) {
      return false;
    }
    final current = now ?? DateTime.now();
    final indexes = <int>[];
    for (var index = 0; index < state.length; index++) {
      final entry = state[index];
      if (entry.profileId == profileId && !entry.isExpired(current)) {
        indexes.add(index);
      }
    }
    final position = indexes.indexWhere(
      (index) => state[index].rule.id == ruleId,
    );
    if (position == -1) {
      return false;
    }
    final targetPosition = (position + offset)
        .clamp(0, indexes.length - 1)
        .toInt();
    if (targetPosition == position) {
      return false;
    }
    final sourceIndex = indexes[position];
    final targetIndex = indexes[targetPosition];
    final next = List<QuickRoutingRuleEntry>.from(state);
    final source = next[sourceIndex];
    next[sourceIndex] = next[targetIndex];
    next[targetIndex] = source;
    state = List.unmodifiable(next);
    return true;
  }

  bool remove(int profileId, int ruleId) {
    final next = state
        .where(
          (entry) =>
              entry.profileId != profileId || entry.rule.id != ruleId,
        )
        .toList(growable: false);
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

  bool clearNetworkBound() {
    final next = state
        .where((entry) => entry.lifetime != QuickRoutingLifetime.network)
        .toList(growable: false);
    if (next.length == state.length) {
      return false;
    }
    state = List.unmodifiable(next);
    return true;
  }

  bool purgeExpired({DateTime? now}) {
    final current = now ?? DateTime.now();
    final next = state
        .where((entry) => !entry.isExpired(current))
        .toList(growable: false);
    if (next.length == state.length) {
      return false;
    }
    state = List.unmodifiable(next);
    return true;
  }

  bool clearAll() {
    if (state.isEmpty) {
      return false;
    }
    state = const [];
    return true;
  }

  void replaceAll(List<QuickRoutingRuleEntry> entries) {
    state = List.unmodifiable(entries);
  }

  List<QuickRoutingRuleEntry>? replaceAllIfCurrent({
    required List<QuickRoutingRuleEntry> expected,
    required List<QuickRoutingRuleEntry> entries,
  }) {
    if (!identical(state, expected)) {
      return null;
    }
    state = List.unmodifiable(entries);
    return state;
  }
}

final quickRoutingRulesProvider =
    NotifierProvider<QuickRoutingRules, List<QuickRoutingRuleEntry>>(
      QuickRoutingRules.new,
    );
