import 'dart:async';
import 'dart:convert';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/core/core.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/app.dart';
import 'package:fl_clash/providers/core.dart';
import 'package:fl_clash/providers/logbook.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

bool _hasTlsInspectionServicesBinding() {
  try {
    ServicesBinding.instance;
    return true;
  } on AssertionError {
    return false;
  }
}

final tlsInspectionPersistenceEnabledProvider = Provider<bool>(
  (_) => _hasTlsInspectionServicesBinding(),
);

abstract interface class TlsInspectionPolicyStore {
  Future<TlsInspectionPolicy> load();

  Future<void> save(TlsInspectionPolicy value);
}

class PreferencesTlsInspectionPolicyStore implements TlsInspectionPolicyStore {
  const PreferencesTlsInspectionPolicyStore();

  @override
  Future<TlsInspectionPolicy> load() async {
    final raw = await preferences.getTlsInspectionPolicy();
    if (raw == null || raw.isEmpty) {
      return const TlsInspectionPolicy();
    }
    if (utf8.encode(raw).length > 256 * 1024) {
      throw const TlsInspectionPolicyException(
        'policy_too_large',
        'Local inspection policy is larger than the supported limit.',
      );
    }
    final decoded = jsonDecode(raw);
    if (decoded is! Map) {
      throw const TlsInspectionPolicyException(
        'policy_invalid',
        'Local inspection policy is not a JSON object.',
      );
    }
    return TlsInspectionPolicy.fromJson(Map<String, Object?>.from(decoded));
  }

  @override
  Future<void> save(TlsInspectionPolicy value) async {
    final encoded = jsonEncode(value.toJson());
    if (utf8.encode(encoded).length > 256 * 1024) {
      throw const TlsInspectionPolicyException(
        'policy_too_large',
        'Local inspection policy is larger than the supported limit.',
      );
    }
    final saved = await preferences.saveTlsInspectionPolicy(encoded);
    if (!saved) {
      throw const TlsInspectionPolicyException(
        'policy_store_unavailable',
        'The local policy store is unavailable.',
      );
    }
  }
}

final tlsInspectionPolicyStoreProvider = Provider<TlsInspectionPolicyStore>(
  (_) => const PreferencesTlsInspectionPolicyStore(),
);

class TlsInspectionPolicyException implements Exception {
  final String code;
  final String message;

  const TlsInspectionPolicyException(this.code, this.message);

  @override
  String toString() => 'TlsInspectionPolicyException($code, $message)';
}

class TlsInspectionState {
  final bool loading;
  final bool busy;
  final TlsInspectionPolicy policy;
  final TlsInspectionAuthorityStatus authority;
  final bool rulesValidated;
  final String errorCode;
  final int revision;

  const TlsInspectionState({
    this.loading = false,
    this.busy = false,
    this.policy = const TlsInspectionPolicy(),
    this.authority = const TlsInspectionAuthorityStatus(),
    this.rulesValidated = false,
    this.errorCode = '',
    this.revision = 0,
  });

  TlsInspectionState copyWith({
    bool? loading,
    bool? busy,
    TlsInspectionPolicy? policy,
    TlsInspectionAuthorityStatus? authority,
    bool? rulesValidated,
    String? errorCode,
    int? revision,
  }) {
    return TlsInspectionState(
      loading: loading ?? this.loading,
      busy: busy ?? this.busy,
      policy: policy ?? this.policy,
      authority: authority ?? this.authority,
      rulesValidated: rulesValidated ?? this.rulesValidated,
      errorCode: errorCode ?? this.errorCode,
      revision: revision ?? this.revision,
    );
  }

  bool get manuallyTrusted => policy.manuallyTrusts(authority);

  bool get prepared =>
      policy.prepared && rulesValidated && policy.canPrepareWith(authority);

  bool isAllowed(String host) => prepared && policy.matchesAllowlist(host);
}

class TlsInspectionNotifier extends Notifier<TlsInspectionState> {
  Future<void>? _loadOperation;
  Future<void> _stateOperationTail = Future<void>.value();
  Future<void> _writeTail = Future<void>.value();

  @override
  TlsInspectionState build() {
    ref.listen<CoreStatus>(coreStatusProvider, (previous, next) {
      if (next == CoreStatus.connected) {
        if (previous != CoreStatus.connected) {
          unawaited(reload());
        }
        return;
      }
      if (state.authority.issue == 'core-disconnected' &&
          !state.rulesValidated) {
        return;
      }
      state = state.copyWith(
        authority: const TlsInspectionAuthorityStatus(
          state: 'unavailable',
          issue: 'core-disconnected',
        ),
        rulesValidated: false,
        revision: state.revision + 1,
      );
    });
    return const TlsInspectionState();
  }

  Future<T> _serialize<T>(Future<T> Function() action) {
    final completer = Completer<T>();
    final previous = _writeTail.catchError((_) {});
    _writeTail = previous.then((_) async {
      try {
        completer.complete(await action());
      } catch (error, stackTrace) {
        completer.completeError(error, stackTrace);
      }
    });
    return completer.future;
  }

  Future<T> _serializeStateOperation<T>(Future<T> Function() action) {
    final completer = Completer<T>();
    final previous = _stateOperationTail.catchError((_) {});
    _stateOperationTail = previous.then((_) async {
      try {
        completer.complete(await action());
      } catch (error, stackTrace) {
        completer.completeError(error, stackTrace);
      }
    });
    return completer.future;
  }

  Future<TlsInspectionPolicy> _readPolicy() async {
    if (!ref.read(tlsInspectionPersistenceEnabledProvider)) {
      return state.policy;
    }
    return ref.read(tlsInspectionPolicyStoreProvider).load();
  }

  Future<void> _writePolicy(TlsInspectionPolicy value) async {
    if (!ref.read(tlsInspectionPersistenceEnabledProvider)) {
      return;
    }
    await ref.read(tlsInspectionPolicyStoreProvider).save(value);
  }

  Future<TlsInspectionAuthorityStatus> _readAuthority() async {
    if (ref.read(coreStatusProvider) != CoreStatus.connected) {
      return const TlsInspectionAuthorityStatus(
        state: 'unavailable',
        issue: 'core-disconnected',
      );
    }
    return ref.read(coreHandlerProvider).getTlsInspectionAuthorityStatus();
  }

  Future<void> _validatePolicyRules(TlsInspectionPolicy policy) async {
    final core = ref.read(coreHandlerProvider);
    final rules = <String, TlsInspectionDomainRule>{
      for (final rule in [...policy.allowlist, ...policy.exclusions])
        rule.identity: rule,
    }.values.toList(growable: false);
    const batchSize = 8;
    for (var offset = 0; offset < rules.length; offset += batchSize) {
      final end = (offset + batchSize).clamp(0, rules.length);
      final batch = rules.sublist(offset, end);
      final analyses = await Future.wait(
        batch.map((rule) => core.analyzeDomain(rule.host)),
      );
      for (var index = 0; index < batch.length; index++) {
        final rule = batch[index];
        final analysis = analyses[index];
        final valid =
            !analysis.isIP &&
            analysis.hasRegistrableDomain &&
            analysis.normalizedHost == rule.host &&
            analysis.normalizedHost != analysis.publicSuffix;
        if (!valid) {
          throw TlsInspectionPolicyException(
            'policy_rule_invalid',
            'The persisted inspection policy contains an unsafe domain rule: ${rule.host}',
          );
        }
      }
    }
  }

  Future<void> reload() {
    final active = _loadOperation;
    if (active != null) {
      return active;
    }
    state = state.copyWith(
      loading: true,
      errorCode: '',
      revision: state.revision + 1,
    );
    final operation = _serializeStateOperation(() async {
      try {
        final results = await (_serialize(_readPolicy), _readAuthority()).wait;
        var policy = results.$1;
        var authority = results.$2;
        if (ref.read(coreStatusProvider) != CoreStatus.connected) {
          authority = const TlsInspectionAuthorityStatus(
            state: 'unavailable',
            issue: 'core-disconnected',
          );
        }
        final authorityWasChecked = authority.issue != 'core-disconnected';
        var rulesValidated = false;
        var validationErrorCode = '';
        if (authorityWasChecked && policy.prepared) {
          try {
            await _validatePolicyRules(policy);
            rulesValidated = true;
          } catch (error, stackTrace) {
            validationErrorCode = _errorCode(error);
            commonPrint.log(
              'TLS inspection policy validation failed: '
              '${compactError(error)}, $stackTrace',
              logLevel: coreFailureLogLevel(error),
            );
            if (error case TlsInspectionPolicyException(
              code: 'policy_rule_invalid',
            )) {
              policy = policy.copyWith(
                prepared: false,
                updatedAt: DateTime.now().toUtc(),
              );
              await _serialize(() => _writePolicy(policy));
            }
          }
        }
        final staleTrust =
            authorityWasChecked &&
            policy.manuallyTrustedFingerprint.isNotEmpty &&
            !policy.manuallyTrusts(authority);
        final stalePreparation =
            authorityWasChecked &&
            policy.prepared &&
            !policy.canPrepareWith(authority);
        if (staleTrust || stalePreparation) {
          policy = policy.copyWith(
            prepared: false,
            clearManualTrust: staleTrust,
            updatedAt: DateTime.now().toUtc(),
          );
          rulesValidated = false;
          await _serialize(() => _writePolicy(policy));
        }
        if (!ref.mounted) {
          return;
        }
        state = state.copyWith(
          loading: false,
          policy: policy,
          authority: authority,
          rulesValidated: rulesValidated,
          errorCode: validationErrorCode,
          revision: state.revision + 1,
        );
      } catch (error, stackTrace) {
        commonPrint.log(
          'TLS inspection foundation reload failed: '
          '${compactError(error)}, $stackTrace',
          logLevel: coreFailureLogLevel(error),
        );
        if (!ref.mounted) {
          return;
        }
        state = state.copyWith(
          loading: false,
          errorCode: _errorCode(error),
          revision: state.revision + 1,
        );
      } finally {
        _loadOperation = null;
      }
    });
    _loadOperation = operation;
    return operation;
  }

  Future<void> ensureAuthority() => _authorityOperation(
    eventType: 'tls.inspection.authority.create',
    action: () => ref.read(coreHandlerProvider).ensureTlsInspectionAuthority(),
  );

  Future<void> rotateAuthority() => _authorityOperation(
    eventType: 'tls.inspection.authority.rotate',
    clearTrust: true,
    action: () => ref.read(coreHandlerProvider).rotateTlsInspectionAuthority(),
  );

  Future<void> deleteAuthority() async {
    await _authorityOperation(
      eventType: 'tls.inspection.authority.delete',
      clearTrust: true,
      action: () async {
        final deleted = await ref
            .read(coreHandlerProvider)
            .deleteTlsInspectionAuthority();
        if (!deleted) {
          throw const CoreMethodException(
            code: 'authority_delete_failed',
            message: 'Core did not confirm authority deletion.',
          );
        }
        return const TlsInspectionAuthorityStatus(state: 'missing');
      },
    );
  }

  Future<void> _authorityOperation({
    required String eventType,
    required Future<TlsInspectionAuthorityStatus> Function() action,
    bool clearTrust = false,
  }) => _serializeStateOperation(
    () => _authorityOperationNow(
      eventType: eventType,
      action: action,
      clearTrust: clearTrust,
    ),
  );

  Future<void> _authorityOperationNow({
    required String eventType,
    required Future<TlsInspectionAuthorityStatus> Function() action,
    required bool clearTrust,
  }) async {
    if (state.busy) {
      return;
    }
    final correlationId = '$eventType:${DateTime.now().microsecondsSinceEpoch}';
    state = state.copyWith(
      busy: true,
      errorCode: '',
      revision: state.revision + 1,
    );
    unawaited(
      ref
          .read(logbookProvider.notifier)
          .record(
            category: LogbookCategory.system,
            severity: LogbookSeverity.info,
            eventType: eventType,
            title: eventType,
            message: 'running',
            correlationId: correlationId,
            details: const {'status': 'running', 'localOnly': true},
          ),
    );
    TlsInspectionAuthorityStatus? visibleAuthority;
    TlsInspectionPolicy? safePolicy;
    try {
      final authority = await action();
      visibleAuthority = ref.read(coreStatusProvider) == CoreStatus.connected
          ? authority
          : const TlsInspectionAuthorityStatus(
              state: 'unavailable',
              issue: 'core-disconnected',
            );
      final staleTrust =
          state.policy.manuallyTrustedFingerprint.isNotEmpty &&
          !state.policy.manuallyTrusts(authority);
      final disablePrepared =
          state.policy.prepared && !state.policy.canPrepareWith(authority);
      final policyInvalidated = clearTrust || staleTrust || disablePrepared;
      safePolicy = policyInvalidated
          ? state.policy.copyWith(
              prepared: false,
              clearManualTrust: clearTrust || staleTrust,
              updatedAt: DateTime.now().toUtc(),
            )
          : state.policy;
      if (ref.mounted) {
        state = state.copyWith(
          authority: visibleAuthority,
          policy: safePolicy,
          rulesValidated: policyInvalidated ? false : state.rulesValidated,
          revision: state.revision + 1,
        );
      }
      if (policyInvalidated) {
        await _serialize(() => _writePolicy(safePolicy!));
      }
      if (!ref.mounted) {
        return;
      }
      state = state.copyWith(
        busy: false,
        authority: visibleAuthority,
        policy: safePolicy,
        rulesValidated: policyInvalidated ? false : state.rulesValidated,
        errorCode: '',
        revision: state.revision + 1,
      );
      unawaited(
        ref
            .read(logbookProvider.notifier)
            .record(
              category: LogbookCategory.system,
              severity: LogbookSeverity.success,
              eventType: eventType,
              title: eventType,
              message: authority.state,
              correlationId: correlationId,
              details: {
                'status': 'completed',
                'localOnly': true,
                'authorityState': authority.state,
                if (authority.fingerprintSha256.isNotEmpty)
                  'fingerprintSha256': authority.fingerprintSha256,
              },
            ),
      );
    } catch (error, stackTrace) {
      commonPrint.log(
        'TLS inspection authority operation failed: '
        '${compactError(error)}, $stackTrace',
        logLevel: coreFailureLogLevel(error),
      );
      if (ref.mounted) {
        state = state.copyWith(
          busy: false,
          authority: visibleAuthority ?? state.authority,
          policy: safePolicy ?? state.policy,
          errorCode: _errorCode(error),
          revision: state.revision + 1,
        );
      }
      unawaited(
        ref
            .read(logbookProvider.notifier)
            .record(
              category: LogbookCategory.system,
              severity: LogbookSeverity.error,
              eventType: eventType,
              title: eventType,
              message: _errorCode(error),
              correlationId: correlationId,
              details: {
                'status': 'failed',
                'localOnly': true,
                'failureKind': error.runtimeType.toString(),
              },
            ),
      );
      rethrow;
    }
  }

  Future<TlsInspectionAuthorityExport> exportCertificate() =>
      _serializeStateOperation(() async {
        final value = await ref
            .read(coreHandlerProvider)
            .exportTlsInspectionCertificate();
        if (!value.valid ||
            !state.authority.validNow ||
            value.fingerprintSha256 != state.authority.fingerprintSha256) {
          throw const TlsInspectionPolicyException(
            'authority_export_invalid',
            'Core returned an invalid or stale public certificate export.',
          );
        }
        return value;
      });

  Future<TlsInspectionDomainRule> normalizeRule({
    required String input,
    required TlsInspectionRuleScope scope,
  }) async {
    final analysis = await ref.read(coreHandlerProvider).analyzeDomain(input);
    if (analysis.isIP) {
      throw const TlsInspectionPolicyException(
        'ip_not_supported',
        'Use a domain name instead of an IP address.',
      );
    }
    if (!analysis.hasRegistrableDomain ||
        analysis.normalizedHost == analysis.publicSuffix) {
      throw const TlsInspectionPolicyException(
        'domain_too_broad',
        'A registrable public domain is required.',
      );
    }
    return TlsInspectionDomainRule(host: analysis.normalizedHost, scope: scope);
  }

  Future<void> addRule({
    required bool exclusion,
    required String input,
    required TlsInspectionRuleScope scope,
  }) => _serializeStateOperation(() async {
    final rule = await normalizeRule(input: input, scope: scope);
    final current = exclusion
        ? state.policy.exclusions
        : state.policy.allowlist;
    if (current.any((item) => item == rule)) {
      return;
    }
    if (current.length >= tlsInspectionMaxRulesPerList) {
      throw const TlsInspectionPolicyException(
        'rule_limit_reached',
        'The inspection policy has reached its rule limit.',
      );
    }
    final next = exclusion
        ? state.policy.copyWith(exclusions: [...current, rule])
        : state.policy.copyWith(allowlist: [...current, rule]);
    await _savePolicy(next);
  });

  Future<void> removeRule({
    required bool exclusion,
    required TlsInspectionDomainRule rule,
  }) => _serializeStateOperation(() async {
    final current = exclusion
        ? state.policy.exclusions
        : state.policy.allowlist;
    final nextRules = current.where((item) => item != rule).toList();
    final next = exclusion
        ? state.policy.copyWith(exclusions: nextRules)
        : state.policy.copyWith(
            allowlist: nextRules,
            prepared: nextRules.isEmpty ? false : state.policy.prepared,
          );
    await _savePolicy(next);
  });

  Future<void> acknowledgeRisk() => _serializeStateOperation(() async {
    await _savePolicy(
      state.policy.copyWith(acknowledgedRiskVersion: tlsInspectionRiskVersion),
    );
  });

  Future<void> confirmManualTrust() => _serializeStateOperation(() async {
    final authority = state.authority;
    if (!authority.validNow || authority.fingerprintSha256.isEmpty) {
      throw const TlsInspectionPolicyException(
        'authority_not_ready',
        'Create a valid local authority before confirming trust.',
      );
    }
    final now = DateTime.now().toUtc();
    await _savePolicy(
      state.policy.copyWith(
        manuallyTrustedFingerprint: authority.fingerprintSha256,
        manuallyTrustedAt: now,
      ),
    );
  });

  Future<void> clearManualTrust() => _serializeStateOperation(() async {
    await _savePolicy(
      state.policy.copyWith(prepared: false, clearManualTrust: true),
    );
  });

  Future<void> setPrepared(bool value) => _serializeStateOperation(() async {
    if (value && !state.policy.canPrepareWith(state.authority)) {
      throw const TlsInspectionPolicyException(
        'safety_requirements_incomplete',
        'Authority, manual trust confirmation, risk acknowledgement, and an allowlist are required.',
      );
    }
    if (value) {
      await _validatePolicyRules(state.policy);
    }
    await _savePolicy(
      state.policy.copyWith(prepared: value),
      rulesValidated: value,
    );
  });

  Future<void> _savePolicy(
    TlsInspectionPolicy value, {
    bool? rulesValidated,
  }) async {
    final now = DateTime.now().toUtc();
    final updated = value.copyWith(updatedAt: now);
    await _serialize(() => _writePolicy(updated));
    if (!ref.mounted) {
      return;
    }
    state = state.copyWith(
      policy: updated,
      rulesValidated: rulesValidated ?? state.rulesValidated,
      errorCode: '',
      revision: state.revision + 1,
    );
    unawaited(
      ref
          .read(logbookProvider.notifier)
          .record(
            category: LogbookCategory.system,
            severity: LogbookSeverity.info,
            eventType: 'tls.inspection.policy',
            title: 'tls.inspection.policy',
            message: updated.prepared ? 'prepared' : 'not-prepared',
            correlationId: 'tls-inspection-policy',
            details: {
              'status': updated.prepared ? 'prepared' : 'not-prepared',
              'localOnly': true,
              'allowlistCount': updated.allowlist.length,
              'exclusionCount': updated.exclusions.length,
              'riskAcknowledged': updated.riskAcknowledged,
              'manualTrustConfirmed': updated.manuallyTrusts(state.authority),
            },
          ),
    );
  }

  String _errorCode(Object error) => switch (error) {
    final CoreMethodException value => value.code,
    final TlsInspectionPolicyException value => value.code,
    final FormatException _ => 'policy_invalid',
    _ => 'unexpected_error',
  };
}

final tlsInspectionProvider =
    NotifierProvider<TlsInspectionNotifier, TlsInspectionState>(
      TlsInspectionNotifier.new,
    );
