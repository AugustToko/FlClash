part of '../quick_routing.dart';

enum QuickRoutingVerificationStatus {
  verified,
  approximate,
  mismatch,
  unavailable,
}

@immutable
class QuickRoutingVerification {
  final QuickRoutingVerificationStatus status;
  final CoreRuleMatchResult? result;
  final List<String> issues;
  final int attempts;

  const QuickRoutingVerification({
    required this.status,
    required this.result,
    required this.issues,
    this.attempts = 1,
  });

  bool get confirmsApplied =>
      status == QuickRoutingVerificationStatus.verified ||
      status == QuickRoutingVerificationStatus.approximate;

  bool get exact => status == QuickRoutingVerificationStatus.verified;

  String get marker => switch (status) {
    QuickRoutingVerificationStatus.verified => '✓',
    QuickRoutingVerificationStatus.approximate => '≈',
    QuickRoutingVerificationStatus.mismatch => '⚠',
    QuickRoutingVerificationStatus.unavailable => '?',
  };

  MessageLevel get messageLevel => switch (status) {
    QuickRoutingVerificationStatus.verified => MessageLevel.success,
    QuickRoutingVerificationStatus.approximate ||
    QuickRoutingVerificationStatus.unavailable => MessageLevel.warning,
    QuickRoutingVerificationStatus.mismatch => MessageLevel.error,
  };
}

String? _quickRoutingExpectedCoreRuleType(RuleAction action) {
  return switch (action) {
    RuleAction.DOMAIN => 'Domain',
    RuleAction.DOMAIN_SUFFIX => 'DomainSuffix',
    RuleAction.IP_CIDR || RuleAction.IP_CIDR6 => 'IPCIDR',
    RuleAction.SRC_IP_CIDR => 'SrcIPCIDR',
    RuleAction.GEOIP => 'GeoIP',
    RuleAction.SRC_GEOIP => 'SrcGeoIP',
    RuleAction.IP_ASN => 'IPASN',
    RuleAction.SRC_IP_ASN => 'SrcIPASN',
    RuleAction.PROCESS_NAME => 'ProcessName',
    RuleAction.PROCESS_PATH => 'ProcessPath',
    RuleAction.UID => 'Uid',
    RuleAction.NETWORK => 'Network',
    RuleAction.DST_PORT => 'DstPort',
    RuleAction.SRC_PORT => 'SrcPort',
    _ => null,
  };
}

(InternetAddress, int)? _parseQuickRoutingVerificationCidr(String value) {
  final parts = value.trim().split('/');
  if (parts.length != 2) {
    return null;
  }
  final address = InternetAddress.tryParse(
    _normalizeQuickRoutingHost(parts.first),
  );
  final prefix = int.tryParse(parts.last);
  if (address == null || prefix == null) {
    return null;
  }
  final maxBits = address.type == InternetAddressType.IPv6 ? 128 : 32;
  if (prefix < 0 || prefix > maxBits) {
    return null;
  }
  return (address, prefix);
}

bool _quickRoutingVerificationCidrsMatch(
  String expected,
  String actual,
) {
  final expectedCidr = _parseQuickRoutingVerificationCidr(expected);
  final actualCidr = _parseQuickRoutingVerificationCidr(actual);
  if (expectedCidr == null || actualCidr == null) {
    return false;
  }
  final (expectedAddress, expectedPrefix) = expectedCidr;
  final (actualAddress, actualPrefix) = actualCidr;
  if (expectedAddress.type != actualAddress.type ||
      expectedPrefix != actualPrefix) {
    return false;
  }
  final expectedBytes = expectedAddress.rawAddress;
  final actualBytes = actualAddress.rawAddress;
  if (expectedBytes.length != actualBytes.length) {
    return false;
  }
  for (var index = 0; index < expectedBytes.length; index++) {
    if (expectedBytes[index] != actualBytes[index]) {
      return false;
    }
  }
  return true;
}

String _normalizeQuickRoutingVerificationPayload(
  RuleAction action,
  String value,
) {
  final content = value.trim();
  return switch (action) {
    RuleAction.DOMAIN || RuleAction.DOMAIN_SUFFIX =>
      _normalizeQuickRoutingHost(content).toLowerCase(),
    RuleAction.GEOIP ||
    RuleAction.SRC_GEOIP ||
    RuleAction.NETWORK =>
      content.toUpperCase(),
    RuleAction.IP_ASN || RuleAction.SRC_IP_ASN =>
      _normalizeQuickRoutingAsn(content),
    RuleAction.DST_PORT || RuleAction.SRC_PORT || RuleAction.UID =>
      int.tryParse(content)?.toString() ?? content,
    _ => content,
  };
}

bool _quickRoutingVerificationPayloadMatches(
  QuickRoutingCandidate candidate,
  String actual,
) {
  if (candidate.ruleAction == RuleAction.IP_CIDR ||
      candidate.ruleAction == RuleAction.IP_CIDR6 ||
      candidate.ruleAction == RuleAction.SRC_IP_CIDR) {
    return _quickRoutingVerificationCidrsMatch(candidate.content, actual);
  }
  return _normalizeQuickRoutingVerificationPayload(
        candidate.ruleAction,
        candidate.content,
      ) ==
      _normalizeQuickRoutingVerificationPayload(
        candidate.ruleAction,
        actual,
      );
}

bool _quickRoutingFixedMemberMatches(
  CoreRuleMatchResult result,
  QuickRoutingGroupOverride override,
) {
  final desired = override.desiredFixed.trim();
  if (desired.isEmpty) {
    return true;
  }
  final groupIndex = result.policyChain.indexOf(override.groupName);
  return groupIndex >= 0 &&
      groupIndex + 1 < result.policyChain.length &&
      result.policyChain[groupIndex + 1] == desired;
}

QuickRoutingVerification evaluateQuickRoutingVerification({
  required QuickRoutingCandidate candidate,
  required String target,
  required CoreRuleMatchResult? result,
  QuickRoutingGroupOverride? groupOverride,
  int attempts = 1,
}) {
  if (result == null) {
    return QuickRoutingVerification(
      status: QuickRoutingVerificationStatus.unavailable,
      result: null,
      issues: const ['core-unavailable'],
      attempts: attempts,
    );
  }

  final issues = <String>[];
  final expectedType = _quickRoutingExpectedCoreRuleType(candidate.ruleAction);
  if (!result.matched) {
    issues.add('rule-not-matched');
  } else {
    if (expectedType == null || result.ruleType != expectedType) {
      issues.add('rule-type-mismatch');
    }
    if (!_quickRoutingVerificationPayloadMatches(candidate, result.payload)) {
      issues.add('rule-payload-mismatch');
    }
  }
  if (result.target.trim() != target.trim()) {
    issues.add('target-mismatch');
  }
  if (groupOverride != null &&
      groupOverride.changes &&
      !_quickRoutingFixedMemberMatches(result, groupOverride)) {
    issues.add('fixed-policy-mismatch');
  }

  if (issues.isNotEmpty) {
    return QuickRoutingVerification(
      status: QuickRoutingVerificationStatus.mismatch,
      result: result,
      issues: List.unmodifiable(issues),
      attempts: attempts,
    );
  }

  if (!result.complete) {
    return QuickRoutingVerification(
      status: QuickRoutingVerificationStatus.approximate,
      result: result,
      issues: const ['core-result-incomplete'],
      attempts: attempts,
    );
  }

  return QuickRoutingVerification(
    status: QuickRoutingVerificationStatus.verified,
    result: result,
    issues: const [],
    attempts: attempts,
  );
}

QuickRoutingVerification unavailableQuickRoutingVerification(
  String issue, {
  int attempts = 0,
}) {
  return QuickRoutingVerification(
    status: QuickRoutingVerificationStatus.unavailable,
    result: null,
    issues: List.unmodifiable([issue]),
    attempts: attempts,
  );
}

int? _resolveQuickRoutingVerificationProfileId({
  required WidgetRef ref,
  required TrackerInfo trackerInfo,
  required QuickRoutingSelection selection,
  int? profileId,
}) {
  if (profileId != null) {
    return profileId;
  }
  for (final entry in ref.read(quickRoutingVerificationHistoryProvider)) {
    if (identical(entry.selection, selection) &&
        entry.trackerInfo.id == trackerInfo.id) {
      return entry.profileId;
    }
  }
  return ref.read(currentProfileIdProvider);
}

Future<QuickRoutingVerification> _verifyAppliedQuickRoutingRule({
  required WidgetRef ref,
  required TrackerInfo trackerInfo,
  required QuickRoutingSelection selection,
  int? profileId,
}) async {
  final historyProfileId = _resolveQuickRoutingVerificationProfileId(
    ref: ref,
    trackerInfo: trackerInfo,
    selection: selection,
    profileId: profileId,
  );
  if (historyProfileId != null) {
    await _hydrateQuickRoutingVerificationHistory(ref, historyProfileId);
  }
  late final QuickRoutingVerification verification;

  bool profileIsActive() {
    return historyProfileId == null ||
        ref.read(currentProfileIdProvider) == historyProfileId;
  }

  if (!profileIsActive()) {
    return unavailableQuickRoutingVerification('profile-not-active');
  }
  if (ref.read(coreStatusProvider) != CoreStatus.connected) {
    verification = unavailableQuickRoutingVerification('core-unavailable');
  } else {
    try {
      final result = await ref
          .read(coreHandlerProvider)
          .matchRule(trackerInfo.metadata);
      if (!profileIsActive()) {
        return unavailableQuickRoutingVerification(
          'profile-not-active',
          attempts: 1,
        );
      }
      verification = evaluateQuickRoutingVerification(
        candidate: selection.candidate,
        target: selection.target,
        result: result,
        groupOverride: selection.groupOverride,
      );
      if (!verification.exact) {
        commonPrint.log(
          'quick routing post-apply verification: '
          '${verification.status.name}, ${verification.issues.join(', ')}, '
          'actual=${result.ruleText} -> ${result.target}, '
          'chain=${result.policyText}',
          logLevel:
              verification.status == QuickRoutingVerificationStatus.mismatch
                  ? LogLevel.error
                  : LogLevel.warning,
        );
      }
    } catch (error, stackTrace) {
      commonPrint.log(
        'quick routing post-apply verification unavailable: '
        '${compactError(error)}, $stackTrace',
        logLevel: coreFailureLogLevel(error),
      );
      verification = unavailableQuickRoutingVerification('core-unavailable');
    }
  }

  if (historyProfileId != null && profileIsActive()) {
    final record = ref
        .read(quickRoutingVerificationHistoryProvider.notifier)
        .upsert(
          profileId: historyProfileId,
          trackerInfo: trackerInfo,
          selection: selection,
          appliedRule: selection.candidate.buildRule(
            target: selection.target,
            id: -1,
          ),
          verification: verification,
        );
    try {
      await _persistQuickRoutingVerificationRecord(ref, record);
    } catch (error, stackTrace) {
      commonPrint.log(
        'quick routing diagnostic persistence failed: '
        '${compactError(error)}, $stackTrace',
        logLevel: LogLevel.warning,
      );
    }
  }
  return verification;
}

String _quickRoutingVerificationSummary(
  BuildContext context,
  QuickRoutingVerification verification,
) {
  final result = verification.result;
  if (result == null) {
    final issue = verification.issues.firstOrNull;
    final suffix = issue == 'profile-not-active' ? ' · PROFILE' : '';
    return '${verification.marker} ${context.appLocalizations.core}: '
        '${context.appLocalizations.unknown}$suffix';
  }
  final rule = result.matched ? result.ruleText : result.mode.toUpperCase();
  final chain = result.policyChain.length > 1 ? ' · ${result.policyText}' : '';
  return '${verification.marker} ${context.appLocalizations.core}: '
      '$rule → ${result.target}$chain';
}
