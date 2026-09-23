part of 'controller.dart';

class CoreRuleMatchResult {
  final String mode;
  final bool matched;
  final int ruleIndex;
  final String ruleType;
  final String payload;
  final String target;
  final List<String> providerNames;
  final String resolvedIP;
  final bool complete;
  final List<String> warnings;

  const CoreRuleMatchResult({
    required this.mode,
    required this.matched,
    required this.ruleIndex,
    required this.ruleType,
    required this.payload,
    required this.target,
    required this.providerNames,
    required this.resolvedIP,
    required this.complete,
    required this.warnings,
  });

  factory CoreRuleMatchResult.fromJson(Map<String, dynamic> json) {
    List<String> strings(Object? value) {
      if (value is! List) {
        return const [];
      }
      return List.unmodifiable(value.whereType<String>());
    }

    return CoreRuleMatchResult(
      mode: json['mode'] as String? ?? 'rule',
      matched: json['matched'] as bool? ?? false,
      ruleIndex: (json['ruleIndex'] as num?)?.toInt() ?? -1,
      ruleType: json['ruleType'] as String? ?? '',
      payload: json['payload'] as String? ?? '',
      target: json['target'] as String? ?? '',
      providerNames: strings(json['providerNames']),
      resolvedIP: json['resolvedIP'] as String? ?? '',
      complete: json['complete'] as bool? ?? false,
      warnings: strings(json['warnings']),
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
