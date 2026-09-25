part of '../quick_routing.dart';

const _quickRoutingDiagnosticPayloadVersion = 1;

String quickRoutingVerificationRecordIdentityFor({
  required int profileId,
  required TrackerInfo trackerInfo,
  required Rule appliedRule,
  required String target,
}) {
  return jsonEncode([
    profileId,
    trackerInfo.id,
    appliedRule.ruleAction.name,
    appliedRule.content,
    appliedRule.ruleProvider,
    appliedRule.subRule,
    appliedRule.noResolve,
    appliedRule.src,
    target,
  ]);
}

String quickRoutingVerificationRecordIdentity(
  QuickRoutingVerificationRecord record,
) {
  return quickRoutingVerificationRecordIdentityFor(
    profileId: record.profileId,
    trackerInfo: record.trackerInfo,
    appliedRule: record.appliedRule,
    target: record.selection.target,
  );
}

Map<String, Object?> _quickRoutingCandidateToJson(
  QuickRoutingCandidate candidate,
) {
  return {
    'ruleAction': candidate.ruleAction.name,
    'content': candidate.content,
    'noResolve': candidate.noResolve,
    'scopeHint': candidate.scopeHint,
  };
}

QuickRoutingCandidate _quickRoutingCandidateFromJson(
  Map<String, Object?> json,
) {
  final actionName = json['ruleAction'] as String? ?? '';
  final action = RuleAction.values.firstWhere(
    (value) => value.name == actionName,
    orElse: () => RuleAction.DOMAIN,
  );
  return QuickRoutingCandidate(
    ruleAction: action,
    content: json['content'] as String? ?? '',
    noResolve: json['noResolve'] as bool? ?? false,
    scopeHint: json['scopeHint'] as String? ?? '',
  );
}

Map<String, Object?>? _quickRoutingGroupOverrideToJson(
  QuickRoutingGroupOverride? override,
) {
  if (override == null) {
    return null;
  }
  return {
    'groupName': override.groupName,
    'previousFixed': override.previousFixed,
    'expectedFixed': override.expectedFixed,
    'desiredFixed': override.desiredFixed,
  };
}

QuickRoutingGroupOverride? _quickRoutingGroupOverrideFromJson(Object? value) {
  if (value is! Map<Object?, Object?>) {
    return null;
  }
  final json = Map<String, Object?>.from(value);
  final groupName = json['groupName'] as String? ?? '';
  if (groupName.isEmpty) {
    return null;
  }
  final previousFixed = json['previousFixed'] as String? ?? '';
  return QuickRoutingGroupOverride(
    groupName: groupName,
    previousFixed: previousFixed,
    expectedFixed: json['expectedFixed'] as String? ?? previousFixed,
    desiredFixed: json['desiredFixed'] as String? ?? '',
  );
}

Map<String, Object?> _quickRoutingSelectionToJson(
  QuickRoutingSelection selection,
) {
  return {
    'candidate': _quickRoutingCandidateToJson(selection.candidate),
    'target': selection.target,
    'lifetime': selection.lifetime.name,
    'groupOverride': _quickRoutingGroupOverrideToJson(selection.groupOverride),
  };
}

QuickRoutingSelection _quickRoutingSelectionFromJson(
  Map<String, Object?> json,
) {
  final rawCandidate = json['candidate'];
  final candidate = rawCandidate is Map<Object?, Object?>
      ? _quickRoutingCandidateFromJson(
          Map<String, Object?>.from(rawCandidate),
        )
      : const QuickRoutingCandidate(
          ruleAction: RuleAction.DOMAIN,
          content: '',
        );
  final lifetimeName = json['lifetime'] as String? ?? '';
  final lifetime = QuickRoutingLifetime.values.firstWhere(
    (value) => value.name == lifetimeName,
    orElse: () => QuickRoutingLifetime.session,
  );
  return QuickRoutingSelection(
    candidate: candidate,
    target: json['target'] as String? ?? '',
    lifetime: lifetime,
    groupOverride: _quickRoutingGroupOverrideFromJson(json['groupOverride']),
  );
}

Map<String, Object?> _coreRuleMatchTraceStepToJson(
  CoreRuleMatchTraceStep step,
) {
  return {
    'ruleScope': step.ruleScope,
    'ruleIndex': step.ruleIndex,
    'ruleType': step.ruleType,
    'payload': step.payload,
    'target': step.target,
    'policyChain': step.policyChain,
    'outcome': step.outcome,
    'rematchName': step.rematchName,
    'subRule': step.subRule,
  };
}

Map<String, Object?> _corePolicyExplainStepToJson(
  CorePolicyExplainStep step,
) {
  return {
    'name': step.name,
    'type': step.type,
    'selected': step.selected,
    'reason': step.reason,
    'strategy': step.strategy,
    'key': step.key,
    'keySource': step.keySource,
    'testURL': step.testURL,
    'fastest': step.fastest,
    'candidateCount': step.candidateCount,
    'selectedIndex': step.selectedIndex,
    'bucket': step.bucket,
    'retry': step.retry,
    'tolerance': step.tolerance,
    'selectedDelay': step.selectedDelay,
    'fastestDelay': step.fastestDelay,
    'fixed': step.fixed,
    'healthKnown': step.healthKnown,
    'selectedAlive': step.selectedAlive,
    'complete': step.complete,
  };
}

Map<String, Object?> _corePolicyExplanationToJson(
  CorePolicyExplanation explanation,
) {
  return {
    'target': explanation.target,
    'policyChain': explanation.policyChain,
    'steps': explanation.steps.map(_corePolicyExplainStepToJson).toList(),
    'complete': explanation.complete,
    'warnings': explanation.warnings,
  };
}

Map<String, Object?> _coreRuleMatchResultToJson(
  CoreRuleMatchResult result,
) {
  return {
    'mode': result.mode,
    'matched': result.matched,
    'ruleScope': result.ruleScope,
    'ruleIndex': result.ruleIndex,
    'ruleType': result.ruleType,
    'payload': result.payload,
    'target': result.target,
    'policyChain': result.policyChain,
    'ruleTrace': result.ruleTrace.map(_coreRuleMatchTraceStepToJson).toList(),
    'providerNames': result.providerNames,
    'resolvedIP': result.resolvedIP,
    'complete': result.complete,
    'warnings': result.warnings,
    if (result.policyExplanation != null)
      'policyExplanation': _corePolicyExplanationToJson(
        result.policyExplanation!,
      ),
  };
}

CoreRuleMatchResult _coreRuleMatchResultFromJson(
  Map<String, Object?> json,
) {
  var result = CoreRuleMatchResult.fromJson(
    Map<String, dynamic>.from(json),
  );
  final rawExplanation = json['policyExplanation'];
  if (rawExplanation is Map<Object?, Object?>) {
    result = result.copyWith(
      policyExplanation: CorePolicyExplanation.fromJson(
        Map<String, dynamic>.from(rawExplanation),
      ),
    );
  }
  return result;
}

Map<String, Object?> _quickRoutingVerificationToJson(
  QuickRoutingVerification verification,
) {
  return {
    'status': verification.status.name,
    'issues': verification.issues,
    'attempts': verification.attempts,
    if (verification.result != null)
      'result': _coreRuleMatchResultToJson(verification.result!),
  };
}

QuickRoutingVerification _quickRoutingVerificationFromJson(
  Map<String, Object?> json,
) {
  final statusName = json['status'] as String? ?? '';
  final status = QuickRoutingVerificationStatus.values.firstWhere(
    (value) => value.name == statusName,
    orElse: () => QuickRoutingVerificationStatus.unavailable,
  );
  final rawIssues = json['issues'];
  final issues = rawIssues is List
      ? List<String>.unmodifiable(rawIssues.whereType<String>())
      : const <String>[];
  final rawResult = json['result'];
  return QuickRoutingVerification(
    status: status,
    result: rawResult is Map<Object?, Object?>
        ? _coreRuleMatchResultFromJson(
            Map<String, Object?>.from(rawResult),
          )
        : null,
    issues: issues,
    attempts: (json['attempts'] as num?)?.toInt() ?? 0,
  );
}

QuickRoutingDiagnosticSnapshot _quickRoutingRecordToSnapshot(
  QuickRoutingVerificationRecord record,
) {
  final payload = jsonEncode({
    'version': _quickRoutingDiagnosticPayloadVersion,
    'trackerInfo': record.trackerInfo.toJson(),
    'selection': _quickRoutingSelectionToJson(record.selection),
    'appliedRule': record.appliedRule.toJson(),
    'verification': _quickRoutingVerificationToJson(record.verification),
  });
  return QuickRoutingDiagnosticSnapshot(
    id: record.id,
    profileId: record.profileId,
    fingerprint: quickRoutingVerificationRecordIdentity(record),
    createdAt: record.createdAt,
    checkedAt: record.checkedAt,
    status: record.verification.status.name,
    searchText: quickRoutingVerificationSearchText(record),
    payload: payload,
  );
}

QuickRoutingVerificationRecord _quickRoutingRecordFromSnapshot(
  QuickRoutingDiagnosticSnapshot snapshot,
) {
  final decoded = jsonDecode(snapshot.payload);
  if (decoded is! Map<Object?, Object?>) {
    throw const FormatException('Invalid quick routing diagnostic payload');
  }
  final payload = Map<String, Object?>.from(decoded);
  final version = (payload['version'] as num?)?.toInt() ?? 0;
  if (version != _quickRoutingDiagnosticPayloadVersion) {
    throw FormatException(
      'Unsupported quick routing diagnostic payload version $version',
    );
  }
  final rawTracker = payload['trackerInfo'];
  final rawSelection = payload['selection'];
  final rawRule = payload['appliedRule'];
  final rawVerification = payload['verification'];
  if (rawTracker is! Map<Object?, Object?> ||
      rawSelection is! Map<Object?, Object?> ||
      rawRule is! Map<Object?, Object?> ||
      rawVerification is! Map<Object?, Object?>) {
    throw const FormatException('Incomplete quick routing diagnostic payload');
  }
  return QuickRoutingVerificationRecord(
    id: snapshot.id,
    profileId: snapshot.profileId,
    createdAt: snapshot.createdAt,
    checkedAt: snapshot.checkedAt,
    trackerInfo: TrackerInfo.fromJson(
      Map<String, Object?>.from(rawTracker),
    ),
    selection: _quickRoutingSelectionFromJson(
      Map<String, Object?>.from(rawSelection),
    ),
    appliedRule: Rule.fromJson(Map<String, Object?>.from(rawRule)),
    verification: _quickRoutingVerificationFromJson(
      Map<String, Object?>.from(rawVerification),
    ),
  );
}

abstract interface class QuickRoutingDiagnosticsPersistence {
  Future<List<QuickRoutingVerificationRecord>> loadProfile(
    int profileId, {
    int limit = QuickRoutingVerificationHistory.maxEntries,
  });

  Future<QuickRoutingVerificationRecord> upsert(
    QuickRoutingVerificationRecord record, {
    int maxEntries = QuickRoutingVerificationHistory.maxEntries,
  });

  Future<void> remove(int id);

  Future<void> clearProfile(int profileId);
}

class DatabaseQuickRoutingDiagnosticsPersistence
    implements QuickRoutingDiagnosticsPersistence {
  const DatabaseQuickRoutingDiagnosticsPersistence();

  @override
  Future<List<QuickRoutingVerificationRecord>> loadProfile(
    int profileId, {
    int limit = QuickRoutingVerificationHistory.maxEntries,
  }) async {
    final snapshots = await database.loadQuickRoutingDiagnostics(
      profileId: profileId,
      limit: limit,
    );
    final records = <QuickRoutingVerificationRecord>[];
    for (final snapshot in snapshots) {
      try {
        records.add(_quickRoutingRecordFromSnapshot(snapshot));
      } catch (error, stackTrace) {
        commonPrint.log(
          'quick routing diagnostic decode failed: '
          '${compactError(error)}, $stackTrace',
          logLevel: LogLevel.warning,
        );
      }
    }
    return List.unmodifiable(records);
  }

  @override
  Future<QuickRoutingVerificationRecord> upsert(
    QuickRoutingVerificationRecord record, {
    int maxEntries = QuickRoutingVerificationHistory.maxEntries,
  }) async {
    final snapshot = await database.upsertQuickRoutingDiagnostic(
      _quickRoutingRecordToSnapshot(record),
      maxEntries: maxEntries,
    );
    return _quickRoutingRecordFromSnapshot(snapshot);
  }

  @override
  Future<void> remove(int id) => database.deleteQuickRoutingDiagnostic(id);

  @override
  Future<void> clearProfile(int profileId) =>
      database.clearQuickRoutingDiagnostics(profileId);
}

final quickRoutingDiagnosticsPersistenceProvider =
    Provider<QuickRoutingDiagnosticsPersistence>(
  (_) => const DatabaseQuickRoutingDiagnosticsPersistence(),
);

class QuickRoutingDiagnosticsCoordinator {
  final QuickRoutingDiagnosticsPersistence persistence;
  final Set<int> _loadedProfiles = <int>{};
  final Map<int, Future<void>> _profileLoads = <int, Future<void>>{};
  Future<void> _writeTail = Future<void>.value();

  QuickRoutingDiagnosticsCoordinator(this.persistence);

  Future<T> _serialize<T>(Future<T> Function() action) {
    final completer = Completer<T>();
    _writeTail = _writeTail.then((_) async {
      try {
        completer.complete(await action());
      } catch (error, stackTrace) {
        completer.completeError(error, stackTrace);
      }
    });
    return completer.future;
  }

  Future<void> hydrate(
    QuickRoutingVerificationHistory notifier,
    int profileId,
  ) {
    if (_loadedProfiles.contains(profileId)) {
      return Future<void>.value();
    }
    final pending = _profileLoads[profileId];
    if (pending != null) {
      return pending;
    }
    final load = () async {
      try {
        final records = await _serialize(
          () => persistence.loadProfile(profileId),
        );
        notifier.mergePersisted(records);
        _loadedProfiles.add(profileId);
      } catch (error, stackTrace) {
        commonPrint.log(
          'quick routing diagnostic hydration failed: '
          '${compactError(error)}, $stackTrace',
          logLevel: LogLevel.warning,
        );
      } finally {
        _profileLoads.remove(profileId);
      }
    }();
    _profileLoads[profileId] = load;
    return load;
  }

  Future<QuickRoutingVerificationRecord> persist(
    QuickRoutingVerificationHistory notifier,
    QuickRoutingVerificationRecord record,
  ) async {
    final canonical = await _serialize(
      () => persistence.upsert(record),
    );
    notifier.replaceRecord(canonical);
    _loadedProfiles.add(record.profileId);
    return canonical;
  }

  Future<void> remove(
    QuickRoutingVerificationHistory notifier,
    int id,
  ) async {
    await _serialize(() => persistence.remove(id));
    // A hydration request may have been queued before this delete. Confirm the
    // in-memory tombstone after the serialized database mutation completes.
    notifier.remove(id, persist: false);
  }

  Future<void> clearProfile(
    QuickRoutingVerificationHistory notifier,
    int profileId,
  ) async {
    await _serialize(() => persistence.clearProfile(profileId));
    // Keep the final state empty even if an older hydration completed while
    // this clear operation was queued.
    notifier.clearProfile(profileId, persist: false);
    _loadedProfiles.add(profileId);
  }
}

final quickRoutingDiagnosticsCoordinatorProvider =
    Provider<QuickRoutingDiagnosticsCoordinator>((ref) {
  return QuickRoutingDiagnosticsCoordinator(
    ref.watch(quickRoutingDiagnosticsPersistenceProvider),
  );
});

final quickRoutingDiagnosticsHydrationProvider =
    FutureProvider.family<void, int>((ref, profileId) {
  return ref.watch(quickRoutingDiagnosticsCoordinatorProvider).hydrate(
        ref.read(quickRoutingVerificationHistoryProvider.notifier),
        profileId,
      );
});

Future<void> _hydrateQuickRoutingVerificationHistory(
  WidgetRef ref,
  int profileId,
) {
  return ref.read(quickRoutingDiagnosticsCoordinatorProvider).hydrate(
        ref.read(quickRoutingVerificationHistoryProvider.notifier),
        profileId,
      );
}

Future<QuickRoutingVerificationRecord> _persistQuickRoutingVerificationRecord(
  WidgetRef ref,
  QuickRoutingVerificationRecord record,
) {
  return ref.read(quickRoutingDiagnosticsCoordinatorProvider).persist(
        ref.read(quickRoutingVerificationHistoryProvider.notifier),
        record,
      );
}

Future<void> _removeQuickRoutingVerificationRecord(
  WidgetRef ref,
  int id,
) {
  return ref.read(quickRoutingDiagnosticsCoordinatorProvider).remove(
        ref.read(quickRoutingVerificationHistoryProvider.notifier),
        id,
      );
}

Future<void> _clearQuickRoutingVerificationRecords(
  WidgetRef ref,
  int profileId,
) {
  return ref.read(quickRoutingDiagnosticsCoordinatorProvider).clearProfile(
        ref.read(quickRoutingVerificationHistoryProvider.notifier),
        profileId,
      );
}
