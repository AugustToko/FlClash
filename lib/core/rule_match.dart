part of 'controller.dart';

class CoreRuleMatchTraceStep {
  final String ruleScope;
  final int ruleIndex;
  final String ruleType;
  final String payload;
  final String target;
  final List<String> policyChain;
  final String outcome;
  final String rematchName;
  final String subRule;

  const CoreRuleMatchTraceStep({
    required this.ruleScope,
    required this.ruleIndex,
    required this.ruleType,
    required this.payload,
    required this.target,
    required this.policyChain,
    required this.outcome,
    required this.rematchName,
    required this.subRule,
  });

  factory CoreRuleMatchTraceStep.fromJson(Map<String, dynamic> json) {
    return CoreRuleMatchTraceStep(
      ruleScope: json['ruleScope'] as String? ?? '',
      ruleIndex: (json['ruleIndex'] as num?)?.toInt() ?? -1,
      ruleType: json['ruleType'] as String? ?? '',
      payload: json['payload'] as String? ?? '',
      target: json['target'] as String? ?? '',
      policyChain: _coreRuleMatchStrings(json['policyChain']),
      outcome: json['outcome'] as String? ?? '',
      rematchName: json['rematchName'] as String? ?? '',
      subRule: json['subRule'] as String? ?? '',
    );
  }

  String get ruleText {
    if (ruleType.isEmpty) {
      return '';
    }
    if (payload.isEmpty) {
      return ruleType;
    }
    return '$ruleType($payload)';
  }

  String get policyText => policyChain.join(' → ');
}

class CorePolicyExplainStep {
  final String name;
  final String type;
  final String selected;
  final String reason;
  final String strategy;
  final String key;
  final String keySource;
  final String testURL;
  final String fastest;
  final int candidateCount;
  final int selectedIndex;
  final int bucket;
  final int retry;
  final int tolerance;
  final int selectedDelay;
  final int fastestDelay;
  final bool fixed;
  final bool healthKnown;
  final bool selectedAlive;
  final bool complete;

  const CorePolicyExplainStep({
    required this.name,
    required this.type,
    required this.selected,
    required this.reason,
    required this.strategy,
    required this.key,
    required this.keySource,
    required this.testURL,
    required this.fastest,
    required this.candidateCount,
    required this.selectedIndex,
    required this.bucket,
    required this.retry,
    required this.tolerance,
    required this.selectedDelay,
    required this.fastestDelay,
    required this.fixed,
    required this.healthKnown,
    required this.selectedAlive,
    required this.complete,
  });

  factory CorePolicyExplainStep.fromJson(Map<String, dynamic> json) {
    return CorePolicyExplainStep(
      name: json['name'] as String? ?? '',
      type: json['type'] as String? ?? '',
      selected: json['selected'] as String? ?? '',
      reason: json['reason'] as String? ?? '',
      strategy: json['strategy'] as String? ?? '',
      key: json['key'] as String? ?? '',
      keySource: json['keySource'] as String? ?? '',
      testURL: json['testURL'] as String? ?? '',
      fastest: json['fastest'] as String? ?? '',
      candidateCount: (json['candidateCount'] as num?)?.toInt() ?? 0,
      selectedIndex: (json['selectedIndex'] as num?)?.toInt() ?? -1,
      bucket: (json['bucket'] as num?)?.toInt() ?? -1,
      retry: (json['retry'] as num?)?.toInt() ?? -1,
      tolerance: (json['tolerance'] as num?)?.toInt() ?? 0,
      selectedDelay: (json['selectedDelay'] as num?)?.toInt() ?? 0,
      fastestDelay: (json['fastestDelay'] as num?)?.toInt() ?? 0,
      fixed: json['fixed'] as bool? ?? false,
      healthKnown: json['healthKnown'] as bool? ?? false,
      selectedAlive: json['selectedAlive'] as bool? ?? false,
      complete: json['complete'] as bool? ?? false,
    );
  }

  bool get hasSelectedDelay =>
      healthKnown && selectedDelay > 0 && selectedDelay < 0xffff;

  bool get hasFastestDelay =>
      fastest.isNotEmpty && fastestDelay > 0 && fastestDelay < 0xffff;
}

class CorePolicyExplanation {
  final String target;
  final List<String> policyChain;
  final List<CorePolicyExplainStep> steps;
  final bool complete;
  final List<String> warnings;

  const CorePolicyExplanation({
    required this.target,
    required this.policyChain,
    required this.steps,
    required this.complete,
    required this.warnings,
  });

  factory CorePolicyExplanation.fromJson(Map<String, dynamic> json) {
    final steps = <CorePolicyExplainStep>[];
    final rawSteps = json['steps'];
    if (rawSteps is List) {
      for (final value in rawSteps) {
        if (value is Map<Object?, Object?>) {
          steps.add(
            CorePolicyExplainStep.fromJson(
              Map<String, dynamic>.from(value),
            ),
          );
        }
      }
    }
    return CorePolicyExplanation(
      target: json['target'] as String? ?? '',
      policyChain: _coreRuleMatchStrings(json['policyChain']),
      steps: List.unmodifiable(steps),
      complete: json['complete'] as bool? ?? false,
      warnings: _coreRuleMatchStrings(json['warnings']),
    );
  }
}

class CoreRuleMatchResult {
  final String mode;
  final bool matched;
  final String ruleScope;
  final int ruleIndex;
  final String ruleType;
  final String payload;
  final String target;
  final List<String> policyChain;
  final List<CoreRuleMatchTraceStep> ruleTrace;
  final List<String> providerNames;
  final String resolvedIP;
  final bool complete;
  final List<String> warnings;
  final CorePolicyExplanation? policyExplanation;

  const CoreRuleMatchResult({
    required this.mode,
    required this.matched,
    required this.ruleScope,
    required this.ruleIndex,
    required this.ruleType,
    required this.payload,
    required this.target,
    required this.policyChain,
    required this.ruleTrace,
    required this.providerNames,
    required this.resolvedIP,
    required this.complete,
    required this.warnings,
    this.policyExplanation,
  });

  factory CoreRuleMatchResult.fromJson(Map<String, dynamic> json) {
    final trace = <CoreRuleMatchTraceStep>[];
    final traceJson = json['ruleTrace'];
    if (traceJson is List) {
      for (final value in traceJson) {
        if (value is Map<Object?, Object?>) {
          trace.add(
            CoreRuleMatchTraceStep.fromJson(
              Map<String, dynamic>.from(value),
            ),
          );
        }
      }
    }

    return CoreRuleMatchResult(
      mode: json['mode'] as String? ?? 'rule',
      matched: json['matched'] as bool? ?? false,
      ruleScope: json['ruleScope'] as String? ?? '',
      ruleIndex: (json['ruleIndex'] as num?)?.toInt() ?? -1,
      ruleType: json['ruleType'] as String? ?? '',
      payload: json['payload'] as String? ?? '',
      target: json['target'] as String? ?? '',
      policyChain: _coreRuleMatchStrings(json['policyChain']),
      ruleTrace: List.unmodifiable(trace),
      providerNames: _coreRuleMatchStrings(json['providerNames']),
      resolvedIP: json['resolvedIP'] as String? ?? '',
      complete: json['complete'] as bool? ?? false,
      warnings: _coreRuleMatchStrings(json['warnings']),
    );
  }

  CoreRuleMatchResult copyWith({
    CorePolicyExplanation? policyExplanation,
  }) {
    return CoreRuleMatchResult(
      mode: mode,
      matched: matched,
      ruleScope: ruleScope,
      ruleIndex: ruleIndex,
      ruleType: ruleType,
      payload: payload,
      target: target,
      policyChain: policyChain,
      ruleTrace: ruleTrace,
      providerNames: providerNames,
      resolvedIP: resolvedIP,
      complete: complete,
      warnings: warnings,
      policyExplanation: policyExplanation ?? this.policyExplanation,
    );
  }

  String get ruleText {
    if (ruleType.isEmpty) {
      return '';
    }
    if (payload.isEmpty) {
      return ruleType;
    }
    return '$ruleType($payload)';
  }

  String get policyText => policyChain.join(' → ');

  String get finalPolicy => policyChain.isEmpty ? target : policyChain.last;
}

List<String> _coreRuleMatchStrings(Object? value) {
  if (value is! List) {
    return const [];
  }
  return List.unmodifiable(value.whereType<String>());
}

extension CoreControllerRuleMatchExt on CoreController {
  Future<CoreRuleMatchResult> matchRule(Metadata metadata) async {
    final data = await _interface.invokeMethod<Map<String, dynamic>>(
      method: CoreMethod.matchRule,
      arguments: metadata.toJson(),
      timeout: const Duration(seconds: 10),
    );
    if (data == null) {
      throw const CoreMethodException(
        code: 'empty_result',
        message: 'Core returned an empty rule match result',
      );
    }
    final result = CoreRuleMatchResult.fromJson(data);
    if (result.target.isEmpty) {
      return result;
    }
    try {
      final explanationData =
          await _interface.invokeMethod<Map<String, dynamic>>(
        method: CoreMethod.explainPolicy,
        arguments: {
          'target': result.target,
          'policyChain': result.policyChain,
          'metadata': metadata.toJson(),
        },
        timeout: const Duration(seconds: 5),
      );
      if (explanationData == null) {
        return result;
      }
      return result.copyWith(
        policyExplanation: CorePolicyExplanation.fromJson(explanationData),
      );
    } catch (error, stackTrace) {
      commonPrint.log(
        'Core policy explanation unavailable: '
        '${compactError(error)}, $stackTrace',
        logLevel: error is CoreMethodException && error.code == 'not_implemented'
            ? LogLevel.debug
            : coreFailureLogLevel(error),
      );
      return result;
    }
  }
}
