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
  });

  factory QuickRoutingRuleEntry.create({
    required int profileId,
    required Rule rule,
    required QuickRoutingLifetime lifetime,
    required String sourceId,
    required String sourceDesc,
    required String previousRule,
    required List<String> previousChains,
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
    final entry = QuickRoutingRuleEntry.create(
      profileId: profileId,
      rule: normalizedRule,
      lifetime: lifetime,
      sourceId: sourceId,
      sourceDesc: sourceDesc,
      previousRule: previousRule,
      previousChains: previousChains,
      now: current,
    );
    if (existingIndex != -1) {
      entries.removeAt(existingIndex);
    }
    entries.insert(0, entry);
    state = List.unmodifiable(entries);
    return entry;
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
}

final quickRoutingRulesProvider =
    NotifierProvider<QuickRoutingRules, List<QuickRoutingRuleEntry>>(
      QuickRoutingRules.new,
    );
