part of '../quick_routing.dart';

List<Rule> buildQuickRoutingKnownRules({
  required OverwriteType overwriteType,
  required Iterable<Rule> runtimeRules,
  required Iterable<Rule> baseRules,
  required Iterable<Rule> addedRules,
  required Iterable<Rule> customRules,
}) {
  final runtime = runtimeRules.toList(growable: false);
  final base = baseRules.toList(growable: false);
  final added = addedRules.toList(growable: false);
  final custom = customRules.toList(growable: false);
  return List.unmodifiable(
    switch (overwriteType) {
      OverwriteType.standard => [...runtime, ...added, ...base],
      OverwriteType.custom => custom.isEmpty
          ? [...runtime, ...base]
          : [...runtime, ...custom],
      OverwriteType.script => [...runtime, ...base],
    },
  );
}

Future<List<Rule>> _readEffectiveQuickRoutingRules({
  required WidgetRef ref,
  required int profileId,
  required OverwriteType overwriteType,
}) async {
  final runtimeRules = ref
      .read(quickRoutingRulesProvider.notifier)
      .activeRulesFor(profileId);
  try {
    final setupState = await ref.read(setupStateProvider(profileId).future);
    final baseConfig = await ref.read(clashConfigProvider(profileId).future);
    return buildQuickRoutingKnownRules(
      overwriteType: overwriteType,
      runtimeRules: runtimeRules,
      baseRules: baseConfig.rules,
      addedRules: setupState.addedRules,
      customRules: setupState.rules,
    );
  } catch (error, stackTrace) {
    commonPrint.log(
      'quick routing effective rules unavailable: '
      '${compactError(error)}, $stackTrace',
      logLevel: LogLevel.warning,
    );
    if (overwriteType == OverwriteType.script) {
      return List.unmodifiable(runtimeRules);
    }
    try {
      final permanentRules = await _readPermanentRules(
        profileId,
        overwriteType,
      );
      return List.unmodifiable([...runtimeRules, ...permanentRules]);
    } catch (fallbackError, fallbackStackTrace) {
      commonPrint.log(
        'quick routing rule explanation fallback failed: '
        '${compactError(fallbackError)}, $fallbackStackTrace',
        logLevel: LogLevel.warning,
      );
      return List.unmodifiable(runtimeRules);
    }
  }
}
