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
    return CoreRuleMatchResult.fromJson(data);
  }
}
