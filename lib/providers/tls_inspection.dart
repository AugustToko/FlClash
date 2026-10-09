import 'dart:async';
import 'dart:convert';

import 'package:certificate_trust/certificate_trust.dart';
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

final certificateTrustClientProvider = Provider<CertificateTrustClient>(
  (_) => certificateTrustManager,
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
  final CertificateTrustStatus platformTrust;
  final TlsInspectionLeafCacheStatus leafCache;
  final bool requiresPlatformTrust;
  final bool rulesValidated;
  final String errorCode;
  final int revision;

  const TlsInspectionState({
    this.loading = false,
    this.busy = false,
    this.policy = const TlsInspectionPolicy(),
    this.authority = const TlsInspectionAuthorityStatus(),
    this.platformTrust = const CertificateTrustStatus(),
    this.leafCache = const TlsInspectionLeafCacheStatus(),
    this.requiresPlatformTrust = false,
    this.rulesValidated = false,
    this.errorCode = '',
    this.revision = 0,
  });

  TlsInspectionState copyWith({
    bool? loading,
    bool? busy,
    TlsInspectionPolicy? policy,
    TlsInspectionAuthorityStatus? authority,
    CertificateTrustStatus? platformTrust,
    TlsInspectionLeafCacheStatus? leafCache,
    bool? requiresPlatformTrust,
    bool? rulesValidated,
    String? errorCode,
    int? revision,
  }) {
    return TlsInspectionState(
      loading: loading ?? this.loading,
      busy: busy ?? this.busy,
      policy: policy ?? this.policy,
      authority: authority ?? this.authority,
      platformTrust: platformTrust ?? this.platformTrust,
      leafCache: leafCache ?? this.leafCache,
      requiresPlatformTrust:
          requiresPlatformTrust ?? this.requiresPlatformTrust,
      rulesValidated: rulesValidated ?? this.rulesValidated,
      errorCode: errorCode ?? this.errorCode,
      revision: revision ?? this.revision,
    );
  }

  bool get manuallyTrusted => policy.manuallyTrusts(authority);

  bool get platformTrustRequired =>
      requiresPlatformTrust || platformTrust.verificationSupported;

  bool get platformTrusted =>
      authority.validNow &&
      platformTrust.verificationSupported &&
      platformTrust.matchesFingerprint(authority.fingerprintSha256);

  bool get trustSatisfied =>
      platformTrustRequired ? platformTrusted : manuallyTrusted;

  bool get prepared =>
      policy.prepared &&
      rulesValidated &&
      policy.canPrepareWith(authority, trustSatisfied: trustSatisfied) &&
      leafCache.matchesAuthority(authority);

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
        platformTrust: _unavailablePlatformTrust(
          state.platformTrust,
          'core-disconnected',
        ),
        leafCache: _unavailableLeafCache('core-disconnected'),
        rulesValidated: false,
        revision: state.revision + 1,
      );
    });
    final trustClient = ref.read(certificateTrustClientProvider);
    final requiresPlatformTrust = trustClient.verificationSupported;
    return TlsInspectionState(
      requiresPlatformTrust: requiresPlatformTrust,
      platformTrust: requiresPlatformTrust
          ? CertificateTrustStatus(
              platform: trustClient.platform,
              state: CertificateTrustState.unavailable,
              verificationSupported: true,
              errorCode: 'not-checked',
            )
          : CertificateTrustStatus(platform: trustClient.platform),
      leafCache: const TlsInspectionLeafCacheStatus(
        state: 'unavailable',
        issue: 'not-checked',
      ),
    );
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

  bool _trustSatisfied(
    TlsInspectionPolicy policy,
    TlsInspectionAuthorityStatus authority,
    CertificateTrustStatus platformTrust,
  ) =>
      authority.validNow &&
      (state.platformTrustRequired
          ? platformTrust.verificationSupported &&
                platformTrust.matchesFingerprint(authority.fingerprintSha256)
          : policy.manuallyTrusts(authority));

  bool _platformTrustIsDefinitive(CertificateTrustStatus value) =>
      !state.platformTrustRequired ||
      value.state == CertificateTrustState.trusted ||
      value.state == CertificateTrustState.notTrusted ||
      value.state == CertificateTrustState.blocked;

  CertificateTrustStatus _unavailablePlatformTrust(
    CertificateTrustStatus current,
    String errorCode,
  ) {
    if (!state.platformTrustRequired) {
      return current;
    }
    final client = ref.read(certificateTrustClientProvider);
    return CertificateTrustStatus(
      platform: current.platform.isEmpty ? client.platform : current.platform,
      state: CertificateTrustState.unavailable,
      store: CertificateTrustStore.unknown,
      installMode: current.installMode,
      verificationSupported: true,
      platformVersion: current.platformVersion,
      limitations: current.limitations,
      errorCode: errorCode,
      checkedAt: DateTime.now().toUtc(),
    );
  }

  TlsInspectionLeafCacheStatus _unavailableLeafCache(
    String issue, {
    TlsInspectionAuthorityStatus? authority,
    String policyDigest = '',
  }) {
    final effectiveAuthority = authority ?? state.authority;
    return TlsInspectionLeafCacheStatus(
      state: 'unavailable',
      generation: effectiveAuthority.generation,
      authorityFingerprintSha256: effectiveAuthority.fingerprintSha256,
      policyDigest: policyDigest.isEmpty
          ? state.leafCache.policyDigest
          : policyDigest,
      issue: issue,
    );
  }

  Future<TlsInspectionLeafCacheStatus> _configureLeafPolicy({
    required TlsInspectionPolicy policy,
    required TlsInspectionAuthorityStatus authority,
    required bool trustSatisfied,
    required bool rulesValidated,
  }) async {
    if (ref.read(coreStatusProvider) != CoreStatus.connected) {
      return _unavailableLeafCache('core-disconnected', authority: authority);
    }
    final enabled =
        policy.prepared &&
        rulesValidated &&
        policy.canPrepareWith(authority, trustSatisfied: trustSatisfied);
    final result = await ref
        .read(coreHandlerProvider)
        .configureTlsInspectionLeafPolicy(
          enabled: enabled,
          policy: policy,
          authority: authority,
          trustSatisfied: trustSatisfied,
        );
    if (enabled && !result.matchesAuthority(authority)) {
      throw const TlsInspectionPolicyException(
        'leaf_cache_invalid',
        'Core did not bind the leaf cache to the active authority.',
      );
    }
    if (!enabled && result.ready) {
      throw const TlsInspectionPolicyException(
        'leaf_cache_invalid',
        'Core retained leaf issuance after policy revocation.',
      );
    }
    return result;
  }

  Future<TlsInspectionLeafCacheStatus> _disableLeafPolicy(
    String issue, {
    TlsInspectionAuthorityStatus? authority,
    TlsInspectionPolicy? policy,
  }) async {
    final effectiveAuthority = authority ?? state.authority;
    if (ref.read(coreStatusProvider) != CoreStatus.connected) {
      return _unavailableLeafCache(issue, authority: effectiveAuthority);
    }
    try {
      final result = await ref
          .read(coreHandlerProvider)
          .configureTlsInspectionLeafPolicy(
            enabled: false,
            policy: policy ?? state.policy,
            authority: effectiveAuthority,
            trustSatisfied: false,
          );
      if (result.ready) {
        throw const TlsInspectionPolicyException(
          'leaf_cache_invalid',
          'Core retained leaf issuance after authorization revocation.',
        );
      }
      return result;
    } catch (error, stackTrace) {
      commonPrint.log(
        'TLS inspection leaf authorization revoke failed: '
        '${compactError(error)}, $stackTrace',
        logLevel: coreFailureLogLevel(error),
      );
      return _unavailableLeafCache(
        _errorCode(error),
        authority: effectiveAuthority,
      );
    }
  }

  CertificateTrustStatus _trustAfterAuthorityUnavailable() {
    final current = state.platformTrust;
    if (!state.platformTrustRequired) {
      return current;
    }
    final client = ref.read(certificateTrustClientProvider);
    return CertificateTrustStatus(
      platform: current.platform.isEmpty ? client.platform : current.platform,
      state: CertificateTrustState.notTrusted,
      store: CertificateTrustStore.none,
      installMode: current.installMode,
      verificationSupported: true,
      platformVersion: current.platformVersion,
      limitations: current.limitations,
      checkedAt: DateTime.now().toUtc(),
    );
  }

  Future<TlsInspectionAuthorityExport> _readAuthorityExport(
    TlsInspectionAuthorityStatus authority,
  ) async {
    final value = await ref
        .read(coreHandlerProvider)
        .exportTlsInspectionCertificate();
    if (!value.valid ||
        !authority.validNow ||
        value.fingerprintSha256 != authority.fingerprintSha256) {
      throw const TlsInspectionPolicyException(
        'authority_export_invalid',
        'Core returned an invalid or stale public certificate export.',
      );
    }
    return value;
  }

  Uint8List _decodePublicCertificate(TlsInspectionAuthorityExport value) {
    const begin = '-----BEGIN CERTIFICATE-----';
    const end = '-----END CERTIFICATE-----';
    final normalized = value.pem.trim();
    if (!normalized.startsWith('$begin\n') || !normalized.endsWith(end)) {
      throw const TlsInspectionPolicyException(
        'authority_export_invalid',
        'The exported public certificate has an invalid PEM envelope.',
      );
    }
    final payload = normalized
        .substring(begin.length, normalized.length - end.length)
        .replaceAll(RegExp(r'\s+'), '');
    try {
      final decoded = base64Decode(payload);
      if (decoded.isEmpty || decoded.length > 64 * 1024) {
        throw const FormatException('certificate DER is outside its bounds');
      }
      return decoded;
    } on FormatException {
      throw const TlsInspectionPolicyException(
        'authority_export_invalid',
        'The exported public certificate contains invalid base64 data.',
      );
    }
  }

  CertificateTrustStatus _validatedPlatformTrust(
    TlsInspectionAuthorityStatus authority,
    CertificateTrustStatus value,
  ) {
    if (value.state != CertificateTrustState.trusted) {
      return value;
    }
    final errorCode = !value.verificationSupported
        ? 'verification-not-supported'
        : value.matchesFingerprint(authority.fingerprintSha256)
        ? ''
        : 'fingerprint-mismatch';
    if (errorCode.isEmpty) {
      return value;
    }
    return CertificateTrustStatus(
      platform: value.platform,
      state: CertificateTrustState.unavailable,
      store: value.store,
      installMode: value.installMode,
      verificationSupported: true,
      fingerprintSha256: value.fingerprintSha256,
      platformVersion: value.platformVersion,
      limitations: value.limitations,
      errorCode: errorCode,
      checkedAt: value.checkedAt ?? DateTime.now().toUtc(),
    );
  }

  Future<CertificateTrustStatus> _readPlatformTrust(
    TlsInspectionAuthorityStatus authority,
  ) async {
    if (!authority.validNow) {
      return _trustAfterAuthorityUnavailable();
    }
    final value = await _readAuthorityExport(authority);
    final trust = await ref
        .read(certificateTrustClientProvider)
        .checkCertificate(
          certificateDer: _decodePublicCertificate(value),
          fingerprintSha256: value.fingerprintSha256,
        );
    return _validatedPlatformTrust(authority, trust);
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
        var platformTrust = _unavailablePlatformTrust(
          state.platformTrust,
          'core-disconnected',
        );
        var validationErrorCode = '';
        if (authorityWasChecked) {
          try {
            platformTrust = await _readPlatformTrust(authority);
          } catch (error, stackTrace) {
            validationErrorCode = validationErrorCode.isEmpty
                ? _errorCode(error)
                : validationErrorCode;
            platformTrust = _unavailablePlatformTrust(
              state.platformTrust,
              validationErrorCode,
            );
            commonPrint.log(
              'TLS inspection platform trust check failed: '
              '${compactError(error)}, $stackTrace',
              logLevel: coreFailureLogLevel(error),
            );
          }
        }
        var rulesValidated = false;
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
        final trustSatisfied = _trustSatisfied(
          policy,
          authority,
          platformTrust,
        );
        final stalePreparation =
            authorityWasChecked &&
            policy.prepared &&
            _platformTrustIsDefinitive(platformTrust) &&
            !policy.canPrepareWith(authority, trustSatisfied: trustSatisfied);
        if (staleTrust || stalePreparation) {
          policy = policy.copyWith(
            prepared: false,
            clearManualTrust: staleTrust,
            updatedAt: DateTime.now().toUtc(),
          );
          rulesValidated = false;
          await _serialize(() => _writePolicy(policy));
        }
        var leafCache = _unavailableLeafCache(
          authorityWasChecked ? 'not-configured' : 'core-disconnected',
          authority: authority,
        );
        if (authorityWasChecked) {
          try {
            leafCache = await _configureLeafPolicy(
              policy: policy,
              authority: authority,
              trustSatisfied: _trustSatisfied(policy, authority, platformTrust),
              rulesValidated: rulesValidated,
            );
          } catch (error, stackTrace) {
            validationErrorCode = validationErrorCode.isEmpty
                ? _errorCode(error)
                : validationErrorCode;
            leafCache = _unavailableLeafCache(
              _errorCode(error),
              authority: authority,
            );
            commonPrint.log(
              'TLS inspection leaf policy synchronization failed: '
              '${compactError(error)}, $stackTrace',
              logLevel: coreFailureLogLevel(error),
            );
          }
        }
        if (!ref.mounted) {
          return;
        }
        state = state.copyWith(
          loading: false,
          policy: policy,
          authority: authority,
          platformTrust: platformTrust,
          leafCache: leafCache,
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
        final leafCache = await _disableLeafPolicy(_errorCode(error));
        if (!ref.mounted) {
          return;
        }
        state = state.copyWith(
          loading: false,
          platformTrust: _unavailablePlatformTrust(
            state.platformTrust,
            _errorCode(error),
          ),
          leafCache: leafCache,
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
      final platformTrust = visibleAuthority.validNow
          ? await _readPlatformTrust(authority)
          : _trustAfterAuthorityUnavailable();
      final staleTrust =
          state.policy.manuallyTrustedFingerprint.isNotEmpty &&
          !state.policy.manuallyTrusts(authority);
      final trustSatisfied = _trustSatisfied(
        state.policy,
        authority,
        platformTrust,
      );
      final disablePrepared =
          state.policy.prepared &&
          _platformTrustIsDefinitive(platformTrust) &&
          !state.policy.canPrepareWith(
            authority,
            trustSatisfied: trustSatisfied,
          );
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
          platformTrust: platformTrust,
          policy: safePolicy,
          rulesValidated: policyInvalidated ? false : state.rulesValidated,
          revision: state.revision + 1,
        );
      }
      if (policyInvalidated) {
        await _serialize(() => _writePolicy(safePolicy!));
      }
      final effectiveRulesValidated = policyInvalidated
          ? false
          : state.rulesValidated;
      var leafCache = _unavailableLeafCache(
        'not-configured',
        authority: visibleAuthority,
      );
      var leafErrorCode = '';
      try {
        leafCache = await _configureLeafPolicy(
          policy: safePolicy,
          authority: authority,
          trustSatisfied: _trustSatisfied(safePolicy, authority, platformTrust),
          rulesValidated: effectiveRulesValidated,
        );
      } catch (error, stackTrace) {
        leafErrorCode = _errorCode(error);
        leafCache = _unavailableLeafCache(
          leafErrorCode,
          authority: visibleAuthority,
        );
        commonPrint.log(
          'TLS inspection leaf policy synchronization failed after authority operation: '
          '${compactError(error)}, $stackTrace',
          logLevel: coreFailureLogLevel(error),
        );
      }
      if (!ref.mounted) {
        return;
      }
      state = state.copyWith(
        busy: false,
        authority: visibleAuthority,
        platformTrust: platformTrust,
        leafCache: leafCache,
        policy: safePolicy,
        rulesValidated: effectiveRulesValidated,
        errorCode: leafErrorCode,
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
      final fallbackAuthority = visibleAuthority ?? state.authority;
      final fallbackPolicy = safePolicy ?? state.policy;
      final leafCache = await _disableLeafPolicy(
        _errorCode(error),
        authority: fallbackAuthority,
        policy: fallbackPolicy,
      );
      if (ref.mounted) {
        state = state.copyWith(
          busy: false,
          authority: fallbackAuthority,
          platformTrust: _unavailablePlatformTrust(
            state.platformTrust,
            _errorCode(error),
          ),
          leafCache: leafCache,
          policy: fallbackPolicy,
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

  Future<CertificateTrustStatus> refreshPlatformTrust() =>
      _serializeStateOperation(() async {
        if (!state.authority.validNow) {
          throw const TlsInspectionPolicyException(
            'authority_not_ready',
            'Create a valid local authority before checking platform trust.',
          );
        }
        state = state.copyWith(
          busy: true,
          errorCode: '',
          revision: state.revision + 1,
        );
        try {
          final leafCache = await _disableLeafPolicy('trust-refresh');
          if (ref.mounted) {
            state = state.copyWith(
              leafCache: leafCache,
              revision: state.revision + 1,
            );
          }
          final value = await _readPlatformTrust(state.authority);
          await _applyPlatformTrust(value);
          if (ref.mounted) {
            state = state.copyWith(
              busy: false,
              errorCode: '',
              revision: state.revision + 1,
            );
          }
          return value;
        } catch (error) {
          final leafCache = await _disableLeafPolicy(_errorCode(error));
          if (ref.mounted) {
            state = state.copyWith(
              busy: false,
              platformTrust: _unavailablePlatformTrust(
                state.platformTrust,
                _errorCode(error),
              ),
              leafCache: leafCache,
              errorCode: _errorCode(error),
              revision: state.revision + 1,
            );
          }
          rethrow;
        }
      });

  Future<CertificateInstallResult>
  requestPlatformTrustInstall() => _serializeStateOperation(() async {
    final authority = state.authority;
    if (!authority.validNow) {
      throw const TlsInspectionPolicyException(
        'authority_not_ready',
        'Create a valid local authority before installing trust.',
      );
    }
    final correlationId =
        'tls.inspection.trust.install:${DateTime.now().microsecondsSinceEpoch}';
    state = state.copyWith(
      busy: true,
      leafCache: await _disableLeafPolicy('trust-install'),
      errorCode: '',
      revision: state.revision + 1,
    );
    unawaited(
      ref
          .read(logbookProvider.notifier)
          .record(
            category: LogbookCategory.system,
            severity: LogbookSeverity.info,
            eventType: 'tls.inspection.trust.install',
            title: 'tls.inspection.trust.install',
            message: 'running',
            correlationId: correlationId,
            details: const {'status': 'running', 'localOnly': true},
          ),
    );
    try {
      final exported = await _readAuthorityExport(authority);
      final result = await ref
          .read(certificateTrustClientProvider)
          .requestInstall(
            certificateDer: _decodePublicCertificate(exported),
            fingerprintSha256: exported.fingerprintSha256,
            displayName: 'FlClash Local Inspection CA',
          );
      final rawTrust =
          result.trustStatus ?? await _readPlatformTrust(authority);
      final trust = _validatedPlatformTrust(state.authority, rawTrust);
      final installedConfirmed =
          result.outcome != CertificateInstallOutcome.installed ||
          _trustSatisfied(state.policy, state.authority, trust);
      final effectiveResult = installedConfirmed
          ? CertificateInstallResult(
              outcome: result.outcome,
              trustStatus: trust,
              errorCode: result.errorCode,
            )
          : CertificateInstallResult(
              outcome: CertificateInstallOutcome.failed,
              trustStatus: trust,
              errorCode: result.errorCode.isEmpty
                  ? 'trust-not-confirmed'
                  : result.errorCode,
            );
      await _applyPlatformTrust(trust);
      if (ref.mounted) {
        state = state.copyWith(
          busy: false,
          errorCode: effectiveResult.errorCode,
          revision: state.revision + 1,
        );
      }
      unawaited(
        ref
            .read(logbookProvider.notifier)
            .record(
              category: LogbookCategory.system,
              severity: switch (effectiveResult.outcome) {
                CertificateInstallOutcome.installed => LogbookSeverity.success,
                CertificateInstallOutcome.settingsOpened ||
                CertificateInstallOutcome.cancelled => LogbookSeverity.info,
                CertificateInstallOutcome.unsupported =>
                  LogbookSeverity.warning,
                CertificateInstallOutcome.failed => LogbookSeverity.error,
              },
              eventType: 'tls.inspection.trust.install',
              title: 'tls.inspection.trust.install',
              message: effectiveResult.outcome.name,
              correlationId: correlationId,
              details: {
                'status': effectiveResult.outcome.name,
                'localOnly': true,
                'trustState': trust.state.name,
                'trustStore': trust.store.name,
              },
            ),
      );
      return effectiveResult;
    } catch (error) {
      final leafCache = await _disableLeafPolicy(_errorCode(error));
      if (ref.mounted) {
        state = state.copyWith(
          busy: false,
          platformTrust: _unavailablePlatformTrust(
            state.platformTrust,
            _errorCode(error),
          ),
          leafCache: leafCache,
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
              eventType: 'tls.inspection.trust.install',
              title: 'tls.inspection.trust.install',
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
  });

  Future<bool> openPlatformTrustSettings() =>
      ref.read(certificateTrustClientProvider).openTrustSettings();

  Future<void> _applyPlatformTrust(CertificateTrustStatus value) async {
    var policy = state.policy;
    final trustSatisfied = _trustSatisfied(policy, state.authority, value);
    final shouldDisable =
        policy.prepared &&
        _platformTrustIsDefinitive(value) &&
        !policy.canPrepareWith(state.authority, trustSatisfied: trustSatisfied);
    if (shouldDisable) {
      policy = policy.copyWith(
        prepared: false,
        updatedAt: DateTime.now().toUtc(),
      );
      await _serialize(() => _writePolicy(policy));
    }
    final rulesValidated = shouldDisable ? false : state.rulesValidated;
    TlsInspectionLeafCacheStatus leafCache;
    try {
      leafCache = await _configureLeafPolicy(
        policy: policy,
        authority: state.authority,
        trustSatisfied: _trustSatisfied(policy, state.authority, value),
        rulesValidated: rulesValidated,
      );
    } catch (error) {
      if (ref.mounted) {
        state = state.copyWith(
          policy: policy,
          platformTrust: value,
          leafCache: _unavailableLeafCache(_errorCode(error)),
          rulesValidated: rulesValidated,
          errorCode: _errorCode(error),
          revision: state.revision + 1,
        );
      }
      rethrow;
    }
    if (!ref.mounted) {
      return;
    }
    state = state.copyWith(
      policy: policy,
      platformTrust: value,
      leafCache: leafCache,
      rulesValidated: rulesValidated,
      revision: state.revision + 1,
    );
  }

  Future<TlsInspectionAuthorityExport> exportCertificate() =>
      _serializeStateOperation(() => _readAuthorityExport(state.authority));

  Future<TlsInspectionLeafCertificateStatus> prepareLeafCertificate(
    String host, {
    bool verifyHandshake = false,
  }) => _serializeStateOperation(() async {
    if (state.busy || !state.prepared || !state.policy.matchesAllowlist(host)) {
      throw const TlsInspectionPolicyException(
        'domain_not_allowed',
        'Leaf certificates are available only for the active allowlist.',
      );
    }
    final expectedPolicyDigest = state.leafCache.policyDigest;
    final expectedRuntimeProofId = state.leafCache.runtimeProofId;
    try {
      final result = await ref
          .read(coreHandlerProvider)
          .prepareTlsInspectionLeafCertificate(
            host: host,
            authority: state.authority,
            policyDigest: expectedPolicyDigest,
            verifyHandshake: verifyHandshake,
          );
      if ((verifyHandshake && !result.handshakeContractValid) ||
          !result.validFor(
            state.authority,
            expectedPolicyDigest,
            expectedHost: host,
            expectedRuntimeProofId: verifyHandshake
                ? expectedRuntimeProofId
                : '',
          )) {
        throw const TlsInspectionPolicyException(
          'leaf_result_invalid',
          'Core returned an invalid leaf certificate status.',
        );
      }
      final leafCache = await ref
          .read(coreHandlerProvider)
          .getTlsInspectionLeafCacheStatus();
      if (!leafCache.matchesAuthority(state.authority) ||
          leafCache.policyDigest != expectedPolicyDigest ||
          leafCache.policyDigest != result.policyDigest ||
          (verifyHandshake &&
              (expectedRuntimeProofId.isEmpty ||
                  leafCache.runtimeProofId != expectedRuntimeProofId ||
                  result.runtimeProofId != expectedRuntimeProofId))) {
        throw const TlsInspectionPolicyException(
          'leaf_cache_invalid',
          'Core leaf cache no longer matches the active authority and policy.',
        );
      }
      if (ref.mounted) {
        state = state.copyWith(
          leafCache: leafCache,
          errorCode: '',
          revision: state.revision + 1,
        );
      }
      return result;
    } catch (error) {
      final leafCache = await _disableLeafPolicy(_errorCode(error));
      if (ref.mounted) {
        state = state.copyWith(
          leafCache: leafCache,
          errorCode: _errorCode(error),
          revision: state.revision + 1,
        );
      }
      rethrow;
    }
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
    if (state.platformTrustRequired) {
      throw const TlsInspectionPolicyException(
        'platform_trust_required',
        'Platform verification is required before preparation.',
      );
    }
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
    if (value && state.platformTrustRequired) {
      try {
        final liveTrust = await _readPlatformTrust(state.authority);
        await _applyPlatformTrust(liveTrust);
      } catch (error) {
        final leafCache = await _disableLeafPolicy(_errorCode(error));
        if (ref.mounted) {
          state = state.copyWith(
            platformTrust: _unavailablePlatformTrust(
              state.platformTrust,
              _errorCode(error),
            ),
            leafCache: leafCache,
            errorCode: _errorCode(error),
            revision: state.revision + 1,
          );
        }
        rethrow;
      }
    }
    if (value &&
        !state.policy.canPrepareWith(
          state.authority,
          trustSatisfied: state.trustSatisfied,
        )) {
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
    final effectiveRulesValidated = updated.prepared
        ? rulesValidated ?? state.rulesValidated
        : false;
    TlsInspectionLeafCacheStatus leafCache;
    try {
      leafCache = await _configureLeafPolicy(
        policy: updated,
        authority: state.authority,
        trustSatisfied: _trustSatisfied(
          updated,
          state.authority,
          state.platformTrust,
        ),
        rulesValidated: effectiveRulesValidated,
      );
    } catch (error) {
      if (ref.mounted) {
        state = state.copyWith(
          policy: updated,
          leafCache: _unavailableLeafCache(_errorCode(error)),
          rulesValidated: effectiveRulesValidated,
          errorCode: _errorCode(error),
          revision: state.revision + 1,
        );
      }
      rethrow;
    }
    if (!ref.mounted) {
      return;
    }
    state = state.copyWith(
      policy: updated,
      leafCache: leafCache,
      rulesValidated: effectiveRulesValidated,
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
              'platformTrustVerified': state.platformTrusted,
            },
          ),
    );
  }

  String _errorCode(Object error) => switch (error) {
    final CoreMethodException value => value.code,
    final TlsInspectionPolicyException value => value.code,
    final PlatformException value when value.code.isNotEmpty => value.code,
    final FormatException _ => 'policy_invalid',
    _ => 'unexpected_error',
  };
}

final tlsInspectionProvider =
    NotifierProvider<TlsInspectionNotifier, TlsInspectionState>(
      TlsInspectionNotifier.new,
    );
