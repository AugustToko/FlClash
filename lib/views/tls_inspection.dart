import 'dart:async';
import 'dart:convert';

import 'package:certificate_trust/certificate_trust.dart';
import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/core/core.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/providers.dart';
import 'package:fl_clash/views/tls_handshake_card.dart';
import 'package:fl_clash/views/tls_runtime_card.dart';
import 'package:fl_clash/widgets/widgets.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

class TlsInspectionView extends ConsumerStatefulWidget {
  const TlsInspectionView({super.key});

  @override
  ConsumerState<TlsInspectionView> createState() => _TlsInspectionViewState();
}

class _TlsInspectionViewState extends ConsumerState<TlsInspectionView>
    with WidgetsBindingObserver {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) {
        unawaited(ref.read(tlsInspectionProvider.notifier).reload());
        unawaited(ref.read(tlsInspectionRuntimeProvider.notifier).reconcile());
      }
    });
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state != AppLifecycleState.resumed || !mounted) {
      return;
    }
    final current = ref.read(tlsInspectionProvider);
    if (current.authority.validNow &&
        current.platformTrust.verificationSupported &&
        !current.busy) {
      unawaited(_refreshPlatformTrustAfterResume());
    }
  }

  Future<void> _refreshPlatformTrustAfterResume() async {
    try {
      await ref.read(tlsInspectionProvider.notifier).refreshPlatformTrust();
      await ref.read(tlsInspectionRuntimeProvider.notifier).reconcile();
    } catch (error, stackTrace) {
      commonPrint.log(
        'TLS inspection trust refresh after resume failed: '
        '${compactError(error)}, $stackTrace',
        logLevel: LogLevel.warning,
      );
    }
  }

  String _authorityStateLabel(String state) {
    final l = context.appLocalizations;
    return switch (state) {
      'missing' => l.tlsInspectionAuthorityMissing,
      'ready' => l.tlsInspectionAuthorityReady,
      'corrupt' => l.tlsInspectionAuthorityCorrupt,
      'expired' => l.tlsInspectionAuthorityExpired,
      'not-yet-valid' => l.tlsInspectionAuthorityNotYetValid,
      'permissions-warning' => l.tlsInspectionAuthorityPermissionsWarning,
      'stale-material-warning' => l.tlsInspectionAuthorityStaleMaterial,
      _ => l.tlsInspectionAuthorityUnavailable,
    };
  }

  String _platformTrustStateLabel(CertificateTrustState state) {
    final l = context.appLocalizations;
    return switch (state) {
      CertificateTrustState.trusted => l.tlsInspectionPlatformTrustVerified,
      CertificateTrustState.notTrusted => l.tlsInspectionPlatformTrustMissing,
      CertificateTrustState.blocked => l.tlsInspectionPlatformTrustBlocked,
      CertificateTrustState.unavailable =>
        l.tlsInspectionPlatformTrustUnavailable,
      CertificateTrustState.unsupported =>
        l.tlsInspectionPlatformTrustUnsupported,
    };
  }

  String _platformTrustConstraintLabel(String value) {
    final l = context.appLocalizations;
    return switch (value) {
      'android-user-ca-opt-in' => l.tlsInspectionPlatformConstraintUserCaOptIn,
      'certificate-pinning-may-block' =>
        l.tlsInspectionPlatformConstraintCertificatePinning,
      'manual-settings-install-required' =>
        l.tlsInspectionPlatformConstraintManualSettings,
      'user-confirmation-required' =>
        l.tlsInspectionPlatformConstraintUserConfirmation,
      _ => value,
    };
  }

  String _platformTrustErrorLabel(String errorCode) {
    final l = context.appLocalizations;
    return switch (errorCode) {
      'not-checked' => l.tlsInspectionPlatformTrustNotChecked,
      'core-disconnected' => l.tlsInspectionErrorCoreDisconnected,
      'authority_export_invalid' => l.tlsInspectionErrorAuthority,
      'fingerprint-mismatch' => l.tlsInspectionPlatformTrustFingerprintMismatch,
      _ => l.tlsInspectionPlatformTrustCheckFailed,
    };
  }

  String _platformTrustStoreLabel(CertificateTrustStore store) {
    final l = context.appLocalizations;
    return switch (store) {
      CertificateTrustStore.user => l.tlsInspectionPlatformTrustStoreUser,
      CertificateTrustStore.system => l.tlsInspectionPlatformTrustStoreSystem,
      CertificateTrustStore.both => l.tlsInspectionPlatformTrustStoreBoth,
      CertificateTrustStore.none => l.tlsInspectionPlatformTrustStoreNone,
      CertificateTrustStore.unknown => l.tlsInspectionPlatformTrustStoreUnknown,
    };
  }

  String _leafCacheStateLabel(String state) {
    final l = context.appLocalizations;
    return switch (state) {
      'ready' => l.tlsInspectionLeafCacheReady,
      'disabled' => l.tlsInspectionLeafCacheDisabled,
      _ => l.tlsInspectionLeafCacheUnavailable,
    };
  }

  String _leafCacheIssueLabel(String issue) {
    final l = context.appLocalizations;
    return switch (issue) {
      'runtime-authorization-missing' ||
      'policy-disabled' ||
      'not-configured' ||
      'not-checked' => l.tlsInspectionLeafCacheWaiting,
      'core-disconnected' => l.tlsInspectionErrorCoreDisconnected,
      'authority-changed' => l.tlsInspectionLeafCacheAuthorityChanged,
      'leaf-key-permissions' => l.tlsInspectionLeafCachePermissions,
      _ => l.tlsInspectionErrorLeafCache,
    };
  }

  String _errorLabel(Object error) {
    final l = context.appLocalizations;
    final code = switch (error) {
      final TlsInspectionPolicyException value => value.code,
      final CoreMethodException value => value.code,
      _ => '',
    };
    return switch (code) {
      'ip_not_supported' => l.tlsInspectionErrorIp,
      'domain_too_broad' => l.tlsInspectionErrorBroad,
      'policy_rule_invalid' => l.tlsInspectionErrorPolicyRule,
      'rule_limit_reached' => l.tlsInspectionErrorLimit,
      'authority_not_ready' ||
      'authority_requires_rotation' => l.tlsInspectionErrorAuthority,
      'safety_requirements_incomplete' ||
      'platform_trust_required' => l.tlsInspectionErrorRequirements,
      'leaf_cache_clear_failed' ||
      'leaf_cache_unavailable' ||
      'leaf_key_permissions' ||
      'leaf_issue_failed' ||
      'leaf_policy_invalid' ||
      'leaf_policy_not_configured' ||
      'leaf_policy_mismatch' ||
      'leaf_result_invalid' ||
      'leaf_cache_invalid' => l.tlsInspectionErrorLeafCache,
      'transport_disconnected' ||
      'transport_error' => l.tlsInspectionErrorCoreDisconnected,
      _ => l.tlsInspectionErrorGeneric,
    };
  }

  Future<void> _run(
    Future<void> Function() action, {
    String? successMessage,
  }) async {
    try {
      await action();
      if (mounted && successMessage != null) {
        context.showNotifier(successMessage, level: MessageLevel.success);
      }
    } catch (error) {
      if (mounted) {
        context.showNotifier(_errorLabel(error), level: MessageLevel.error);
      }
    }
  }

  Future<void> _createAuthority() {
    return _run(ref.read(tlsInspectionProvider.notifier).ensureAuthority);
  }

  Future<void> _rotateAuthority() async {
    final l = context.appLocalizations;
    final confirmed = await dialogs.showMessage(
      context: context,
      title: l.tlsInspectionRotateAuthority,
      message: TextSpan(text: l.tlsInspectionRotateWarning),
    );
    if (confirmed != true || !mounted) {
      return;
    }
    await _run(ref.read(tlsInspectionProvider.notifier).rotateAuthority);
  }

  Future<void> _deleteAuthority() async {
    final l = context.appLocalizations;
    final confirmed = await dialogs.showMessage(
      context: context,
      title: l.tlsInspectionDeleteAuthority,
      message: TextSpan(text: l.tlsInspectionDeleteWarning),
    );
    if (confirmed != true || !mounted) {
      return;
    }
    await _run(ref.read(tlsInspectionProvider.notifier).deleteAuthority);
  }

  Future<bool> _saveCertificate({bool notify = true}) async {
    final l = context.appLocalizations;
    try {
      final value = await ref
          .read(tlsInspectionProvider.notifier)
          .exportCertificate();
      final saved = await picker.saveFile(
        value.fileName,
        Uint8List.fromList(utf8.encode(value.pem)),
      );
      if (saved == null || !mounted) {
        return false;
      }
      if (notify) {
        context.showNotifier(
          l.tlsInspectionExportSuccess,
          level: MessageLevel.success,
        );
      }
      return true;
    } catch (error) {
      if (mounted) {
        context.showNotifier(_errorLabel(error), level: MessageLevel.error);
      }
      return false;
    }
  }

  Future<void> _exportCertificate() async {
    await _saveCertificate();
  }

  Future<void> _refreshPlatformTrust() {
    return _run(
      () async {
        await ref.read(tlsInspectionProvider.notifier).refreshPlatformTrust();
      },
      successMessage:
          context.appLocalizations.tlsInspectionPlatformTrustChecked,
    );
  }

  Future<void> _openPlatformTrustSettings() async {
    final opened = await ref
        .read(tlsInspectionProvider.notifier)
        .openPlatformTrustSettings();
    if (!opened && mounted) {
      context.showNotifier(
        context.appLocalizations.tlsInspectionPlatformTrustInstallFailed,
        level: MessageLevel.error,
      );
    }
  }

  Future<void> _installPlatformTrust() async {
    final l = context.appLocalizations;
    final current = ref.read(tlsInspectionProvider);
    if (current.platformTrust.installMode == CertificateInstallMode.settings) {
      final saved = await _saveCertificate(notify: false);
      if (!saved || !mounted) {
        return;
      }
    }
    try {
      final result = await ref
          .read(tlsInspectionProvider.notifier)
          .requestPlatformTrustInstall();
      if (!mounted) {
        return;
      }
      switch (result.outcome) {
        case CertificateInstallOutcome.installed:
          context.showNotifier(
            l.tlsInspectionPlatformTrustInstalled,
            level: MessageLevel.success,
          );
        case CertificateInstallOutcome.settingsOpened:
          context.showNotifier(l.tlsInspectionPlatformTrustSettingsOpened);
        case CertificateInstallOutcome.cancelled:
          break;
        case CertificateInstallOutcome.unsupported:
        case CertificateInstallOutcome.failed:
          context.showNotifier(
            l.tlsInspectionPlatformTrustInstallFailed,
            level: MessageLevel.error,
          );
      }
    } catch (error) {
      if (mounted) {
        context.showNotifier(_errorLabel(error), level: MessageLevel.error);
      }
    }
  }

  Future<void> _copyFingerprint(String value) async {
    if (value.isEmpty) {
      return;
    }
    await Clipboard.setData(ClipboardData(text: value));
    if (mounted) {
      context.showNotifier(
        context.appLocalizations.copySuccess,
        level: MessageLevel.success,
      );
    }
  }

  Future<void> _acknowledgeRisk() async {
    final l = context.appLocalizations;
    final confirmed = await dialogs.showMessage(
      context: context,
      title: l.tlsInspectionRisk,
      message: TextSpan(text: l.tlsInspectionRiskDesc),
      confirmText: l.tlsInspectionAcknowledgeRisk,
    );
    if (confirmed == true && mounted) {
      await _run(ref.read(tlsInspectionProvider.notifier).acknowledgeRisk);
    }
  }

  Future<void> _confirmManualTrust() async {
    final l = context.appLocalizations;
    final state = ref.read(tlsInspectionProvider);
    final confirmed = await dialogs.showMessage(
      context: context,
      title: l.tlsInspectionTrust,
      message: TextSpan(
        text:
            '${l.tlsInspectionTrustDesc}\n\n'
            '${l.tlsInspectionFingerprint}: '
            '${state.authority.fingerprintSha256}',
      ),
      confirmText: l.tlsInspectionConfirmTrust,
    );
    if (confirmed == true && mounted) {
      await _run(ref.read(tlsInspectionProvider.notifier).confirmManualTrust);
    }
  }

  Future<void> _togglePrepared(bool value) {
    return _run(
      () => ref.read(tlsInspectionProvider.notifier).setPrepared(value),
    );
  }

  Future<void> _addRule(bool exclusion) async {
    final l = context.appLocalizations;
    final value = await dialogs
        .showCommonDialog<({String input, TlsInspectionRuleScope scope})>(
          context: context,
          child: _TlsInspectionRuleDialog(
            title: exclusion
                ? l.tlsInspectionExclusions
                : l.tlsInspectionAllowlist,
          ),
        );
    if (value == null || !mounted) {
      return;
    }
    await _run(
      () => ref
          .read(tlsInspectionProvider.notifier)
          .addRule(
            exclusion: exclusion,
            input: value.input,
            scope: value.scope,
          ),
    );
  }

  Widget _boundaryCard(TlsInspectionState state) {
    final l = context.appLocalizations;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  Icons.security_outlined,
                  color: context.colorScheme.primary,
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    l.tlsInspectionBoundaryTitle,
                    style: context.textTheme.titleMedium?.toSoftBold,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            Text(l.tlsInspectionBoundaryDesc),
            const SizedBox(height: 12),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                Chip(label: Text(l.tlsInspectionDisabledByDefault)),
                Chip(label: Text(l.tlsInspectionAllowlistOnly)),
                Chip(label: Text(l.tlsInspectionMetadataOnly)),
                Chip(
                  label: Text(
                    state.platformTrustRequired
                        ? l.tlsInspectionPlatformTrustVerifiedOnly
                        : l.tlsInspectionManualTrustOnly,
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _requirementRow(String label, bool complete) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: [
          Icon(
            complete ? Icons.check_circle : Icons.radio_button_unchecked,
            size: 20,
            color: complete
                ? context.colorScheme.primary
                : context.colorScheme.outline,
          ),
          const SizedBox(width: 10),
          Expanded(child: Text(label)),
        ],
      ),
    );
  }

  Widget _readinessCard(TlsInspectionState state) {
    final l = context.appLocalizations;
    return Card(
      child: Column(
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Icon(
                      state.prepared
                          ? Icons.verified_user_outlined
                          : Icons.fact_check_outlined,
                      color: state.prepared
                          ? context.colorScheme.primary
                          : context.colorScheme.onSurfaceVariant,
                    ),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Text(
                        l.tlsInspectionReadiness,
                        style: context.textTheme.titleMedium?.toSoftBold,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 10),
                _requirementRow(
                  l.tlsInspectionRequirementAuthority,
                  state.authority.validNow,
                ),
                _requirementRow(
                  l.tlsInspectionRequirementRisk,
                  state.policy.riskAcknowledged,
                ),
                _requirementRow(
                  l.tlsInspectionRequirementTrust,
                  state.trustSatisfied,
                ),
                _requirementRow(
                  l.tlsInspectionRequirementAllowlist,
                  state.policy.allowlist.isNotEmpty,
                ),
                _requirementRow(
                  l.tlsInspectionRequirementLeafCache,
                  state.leafCache.matchesAuthority(state.authority),
                ),
              ],
            ),
          ),
          const Divider(height: 1),
          SwitchListTile(
            value: state.prepared,
            onChanged: state.busy ? null : _togglePrepared,
            title: Text(l.tlsInspectionPrepared),
            subtitle: Text(
              state.prepared
                  ? l.tlsInspectionPreparedDesc
                  : l.tlsInspectionNotPreparedDesc,
            ),
          ),
        ],
      ),
    );
  }

  Widget _detailRow(String label, String value, {Widget? trailing}) {
    if (value.isEmpty) {
      return const SizedBox.shrink();
    }
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 5),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 150,
            child: Text(
              label,
              style: context.textTheme.bodySmall?.copyWith(
                color: context.colorScheme.onSurfaceVariant,
              ),
            ),
          ),
          Expanded(child: SelectableText(value)),
          ?trailing,
        ],
      ),
    );
  }

  Widget _authorityCard(TlsInspectionState state) {
    final l = context.appLocalizations;
    final authority = state.authority;
    final validity = authority.notBefore == null || authority.notAfter == null
        ? ''
        : '${authority.notBefore!.toLocal().show} → '
              '${authority.notAfter!.toLocal().show}';
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.workspace_premium_outlined),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    l.tlsInspectionAuthority,
                    style: context.textTheme.titleMedium?.toSoftBold,
                  ),
                ),
                Chip(label: Text(_authorityStateLabel(authority.state))),
              ],
            ),
            const SizedBox(height: 12),
            if (authority.state == 'missing')
              FilledButton.icon(
                onPressed: state.busy ? null : _createAuthority,
                icon: const Icon(Icons.add_moderator_outlined),
                label: Text(l.tlsInspectionCreateAuthority),
              )
            else if (authority.exists) ...[
              _detailRow(
                l.tlsInspectionFingerprint,
                authority.fingerprintSha256,
                trailing: IconButton(
                  tooltip: context.appLocalizations.copy,
                  onPressed: () =>
                      _copyFingerprint(authority.fingerprintSha256),
                  icon: const Icon(Icons.copy_outlined),
                ),
              ),
              _detailRow(l.tlsInspectionSubject, authority.subject),
              _detailRow(l.tlsInspectionSerial, authority.serialNumber),
              _detailRow(l.tlsInspectionAlgorithm, authority.algorithm),
              _detailRow(l.tlsInspectionValidity, validity),
              _detailRow(
                l.tlsInspectionStorage,
                authority.keyStorage == 'app-data-file'
                    ? l.tlsInspectionStorageAppSandbox
                    : authority.keyStorage,
              ),
              const SizedBox(height: 8),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  FilledButton.tonalIcon(
                    onPressed: authority.validNow && !state.busy
                        ? _exportCertificate
                        : null,
                    icon: const Icon(Icons.download_outlined),
                    label: Text(l.tlsInspectionExportCertificate),
                  ),
                  OutlinedButton.icon(
                    onPressed: state.busy ? null : _rotateAuthority,
                    icon: const Icon(Icons.refresh_outlined),
                    label: Text(l.tlsInspectionRotateAuthority),
                  ),
                  OutlinedButton.icon(
                    onPressed: state.busy ? null : _deleteAuthority,
                    icon: const Icon(Icons.delete_outline),
                    label: Text(l.tlsInspectionDeleteAuthority),
                  ),
                ],
              ),
            ],
            const SizedBox(height: 12),
            Text(
              l.tlsInspectionPrivateKeyNeverExported,
              style: context.textTheme.bodySmall?.copyWith(
                color: context.colorScheme.onSurfaceVariant,
              ),
            ),
            const SizedBox(height: 4),
            Text(
              l.tlsInspectionPolicyNotBackedUp,
              style: context.textTheme.bodySmall?.copyWith(
                color: context.colorScheme.onSurfaceVariant,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _trustCard(TlsInspectionState state) {
    final l = context.appLocalizations;
    final trust = state.platformTrust;
    final usesPlatformVerification = state.platformTrustRequired;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            LayoutBuilder(
              builder: (context, constraints) {
                final title = Row(
                  children: [
                    const Icon(Icons.admin_panel_settings_outlined),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Text(
                        l.tlsInspectionTrust,
                        style: context.textTheme.titleMedium?.toSoftBold,
                      ),
                    ),
                  ],
                );
                if (!usesPlatformVerification) {
                  return title;
                }
                final badge = Chip(
                  label: Text(_platformTrustStateLabel(trust.state)),
                );
                if (constraints.maxWidth < 400) {
                  return Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [title, const SizedBox(height: 8), badge],
                  );
                }
                return Row(
                  children: [
                    Expanded(child: title),
                    badge,
                  ],
                );
              },
            ),
            const SizedBox(height: 8),
            Text(
              usesPlatformVerification
                  ? l.tlsInspectionPlatformTrustDesc
                  : l.tlsInspectionTrustDesc,
            ),
            const SizedBox(height: 8),
            Text(
              usesPlatformVerification
                  ? l.tlsInspectionPlatformTrustLimitations
                  : l.tlsInspectionTrustLimitations,
              style: context.textTheme.bodySmall?.copyWith(
                color: context.colorScheme.error,
              ),
            ),
            const SizedBox(height: 12),
            if (usesPlatformVerification) ...[
              ListTile(
                contentPadding: EdgeInsets.zero,
                leading: Icon(
                  state.platformTrusted
                      ? Icons.verified_outlined
                      : trust.state == CertificateTrustState.unavailable
                      ? Icons.sync_problem_outlined
                      : Icons.gpp_maybe_outlined,
                  color: state.platformTrusted
                      ? context.colorScheme.primary
                      : context.colorScheme.onSurfaceVariant,
                ),
                title: Text(_platformTrustStateLabel(trust.state)),
                subtitle: Text(
                  trust.errorCode.isEmpty
                      ? l.tlsInspectionPlatformTrustFingerprintMatch
                      : _platformTrustErrorLabel(trust.errorCode),
                ),
              ),
              _detailRow(
                l.tlsInspectionPlatformTrustStore,
                _platformTrustStoreLabel(trust.store),
              ),
              if (trust.checkedAt != null)
                _detailRow(
                  l.tlsInspectionPlatformTrustLastChecked,
                  trust.checkedAt!.toLocal().showFull,
                ),
              if (trust.platformVersion > 0)
                _detailRow(
                  l.tlsInspectionPlatformVersion,
                  '${trust.platformVersion}',
                ),
              if (trust.limitations.isNotEmpty)
                _detailRow(
                  l.tlsInspectionPlatformTrustConstraints,
                  trust.limitations
                      .map(_platformTrustConstraintLabel)
                      .join('\n'),
                ),
              const SizedBox(height: 8),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  if (!state.platformTrusted &&
                      trust.installMode != CertificateInstallMode.unsupported)
                    FilledButton.tonalIcon(
                      onPressed: state.authority.validNow && !state.busy
                          ? _installPlatformTrust
                          : null,
                      icon: Icon(
                        trust.installMode == CertificateInstallMode.settings
                            ? Icons.settings_outlined
                            : Icons.install_mobile_outlined,
                      ),
                      label: Text(
                        trust.installMode == CertificateInstallMode.settings
                            ? l.tlsInspectionPlatformTrustExportAndOpenSettings
                            : l.tlsInspectionPlatformTrustInstall,
                      ),
                    ),
                  OutlinedButton.icon(
                    onPressed: state.authority.validNow && !state.busy
                        ? _refreshPlatformTrust
                        : null,
                    icon: const Icon(Icons.refresh_outlined),
                    label: Text(l.tlsInspectionPlatformTrustCheckAgain),
                  ),
                  if (trust.installMode == CertificateInstallMode.settings)
                    TextButton.icon(
                      onPressed: state.busy ? null : _openPlatformTrustSettings,
                      icon: const Icon(Icons.open_in_new_outlined),
                      label: Text(l.tlsInspectionPlatformTrustOpenSettings),
                    ),
                ],
              ),
            ] else ...[
              ListTile(
                contentPadding: EdgeInsets.zero,
                leading: Icon(
                  state.manuallyTrusted
                      ? Icons.verified_outlined
                      : Icons.help_outline,
                  color: state.manuallyTrusted
                      ? context.colorScheme.primary
                      : context.colorScheme.onSurfaceVariant,
                ),
                title: Text(
                  state.manuallyTrusted
                      ? l.tlsInspectionTrustConfirmed
                      : l.tlsInspectionTrustUnconfirmed,
                ),
                subtitle: state.policy.manuallyTrustedAt == null
                    ? null
                    : Text(state.policy.manuallyTrustedAt!.toLocal().showFull),
              ),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  FilledButton.tonalIcon(
                    onPressed: state.authority.validNow && !state.busy
                        ? _confirmManualTrust
                        : null,
                    icon: const Icon(Icons.verified_user_outlined),
                    label: Text(l.tlsInspectionConfirmTrust),
                  ),
                  if (state.policy.manuallyTrustedFingerprint.isNotEmpty)
                    TextButton(
                      onPressed: state.busy
                          ? null
                          : () => _run(
                              ref
                                  .read(tlsInspectionProvider.notifier)
                                  .clearManualTrust,
                            ),
                      child: Text(l.tlsInspectionClearTrust),
                    ),
                ],
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _leafCacheCard(TlsInspectionState state) {
    final l = context.appLocalizations;
    final cache = state.leafCache;
    final ready = cache.matchesAuthority(state.authority);
    final effectiveState = ready
        ? 'ready'
        : cache.state == 'disabled'
        ? 'disabled'
        : 'unavailable';
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  Icons.enhanced_encryption_outlined,
                  color: ready
                      ? context.colorScheme.primary
                      : context.colorScheme.onSurfaceVariant,
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    l.tlsInspectionLeafCache,
                    style: context.textTheme.titleMedium?.toSoftBold,
                  ),
                ),
                Chip(label: Text(_leafCacheStateLabel(effectiveState))),
              ],
            ),
            const SizedBox(height: 8),
            Text(l.tlsInspectionLeafCacheDesc),
            const SizedBox(height: 12),
            if (ready) ...[
              _detailRow(
                l.tlsInspectionLeafCacheEntries,
                '${cache.entryCount} / ${cache.capacity}',
              ),
              if (cache.leafValiditySeconds > 0)
                _detailRow(
                  l.tlsInspectionLeafCacheValidity,
                  l.tlsInspectionLeafCacheValidityOneDay,
                ),
              _detailRow(l.tlsInspectionAlgorithm, cache.algorithm),
              _detailRow(
                l.tlsInspectionStorage,
                cache.keyStorage == 'app-data-file'
                    ? l.tlsInspectionStorageAppSandbox
                    : cache.keyStorage,
              ),
              _detailRow(
                l.tlsInspectionLeafCachePolicyDigest,
                cache.policyDigest,
              ),
              if (cache.updatedAt != null)
                _detailRow(
                  l.tlsInspectionLeafCacheLastUpdated,
                  cache.updatedAt!.toLocal().showFull,
                ),
            ] else
              ListTile(
                contentPadding: EdgeInsets.zero,
                leading: const Icon(Icons.hourglass_empty_outlined),
                title: Text(_leafCacheStateLabel(effectiveState)),
                subtitle: Text(_leafCacheIssueLabel(cache.issue)),
              ),
            const SizedBox(height: 8),
            Text(
              l.tlsInspectionLeafCacheNoExport,
              style: context.textTheme.bodySmall?.copyWith(
                color: context.colorScheme.onSurfaceVariant,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _riskCard(TlsInspectionState state) {
    final l = context.appLocalizations;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  Icons.warning_amber_outlined,
                  color: context.colorScheme.error,
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    l.tlsInspectionRisk,
                    style: context.textTheme.titleMedium?.toSoftBold,
                  ),
                ),
                if (state.policy.riskAcknowledged)
                  Chip(
                    avatar: const Icon(Icons.check, size: 18),
                    label: Text(l.tlsInspectionRiskAcknowledged),
                  ),
              ],
            ),
            const SizedBox(height: 8),
            Text(l.tlsInspectionRiskDesc),
            if (!state.policy.riskAcknowledged) ...[
              const SizedBox(height: 12),
              FilledButton.tonal(
                onPressed: _acknowledgeRisk,
                child: Text(l.tlsInspectionAcknowledgeRisk),
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _ruleCard({
    required String title,
    required String description,
    required bool exclusion,
    required List<TlsInspectionDomainRule> rules,
  }) {
    final l = context.appLocalizations;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  exclusion
                      ? Icons.block_outlined
                      : Icons.domain_verification_outlined,
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    title,
                    style: context.textTheme.titleMedium?.toSoftBold,
                  ),
                ),
                IconButton(
                  tooltip: l.tlsInspectionAddDomain,
                  onPressed: () => _addRule(exclusion),
                  icon: const Icon(Icons.add),
                ),
              ],
            ),
            const SizedBox(height: 4),
            Text(description),
            const SizedBox(height: 10),
            if (rules.isEmpty)
              Padding(
                padding: const EdgeInsets.symmetric(vertical: 12),
                child: Text(
                  l.tlsInspectionNoRules,
                  style: context.textTheme.bodyMedium?.copyWith(
                    color: context.colorScheme.onSurfaceVariant,
                  ),
                ),
              )
            else
              for (final rule in rules)
                ListTile(
                  contentPadding: EdgeInsets.zero,
                  dense: true,
                  leading: Icon(
                    rule.scope == TlsInspectionRuleScope.exact
                        ? Icons.filter_1_outlined
                        : Icons.account_tree_outlined,
                  ),
                  title: Text(rule.host),
                  subtitle: Text(
                    rule.scope == TlsInspectionRuleScope.exact
                        ? l.tlsInspectionExactDomain
                        : l.tlsInspectionDomainAndSubdomains,
                  ),
                  trailing: IconButton(
                    tooltip: context.appLocalizations.delete,
                    onPressed: () => _run(
                      () => ref
                          .read(tlsInspectionProvider.notifier)
                          .removeRule(exclusion: exclusion, rule: rule),
                    ),
                    icon: const Icon(Icons.close),
                  ),
                ),
            if (exclusion) ...[
              const SizedBox(height: 6),
              Text(
                l.tlsInspectionExclusionWins,
                style: context.textTheme.bodySmall?.copyWith(
                  color: context.colorScheme.onSurfaceVariant,
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final l = context.appLocalizations;
    final state = ref.watch(tlsInspectionProvider);
    return CommonScaffold(
      title: l.tlsInspection,
      actions: [
        IconButton(
          tooltip: context.appLocalizations.update,
          onPressed: state.loading
              ? null
              : () => unawaited(
                  ref.read(tlsInspectionProvider.notifier).reload(),
                ),
          icon: const Icon(Icons.refresh),
        ),
      ],
      body: LayoutBuilder(
        builder: (context, constraints) {
          final width = constraints.maxWidth > 960
              ? 960.0
              : constraints.maxWidth;
          return Center(
            child: SizedBox(
              width: width,
              height: constraints.maxHeight,
              child: ListView(
                padding: EdgeInsets.fromLTRB(
                  12,
                  12,
                  12,
                  24 + BottomInsetScope.of(context),
                ),
                children: [
                  _boundaryCard(state),
                  const SizedBox(height: 10),
                  _readinessCard(state),
                  const SizedBox(height: 10),
                  _authorityCard(state),
                  const SizedBox(height: 10),
                  _trustCard(state),
                  const SizedBox(height: 10),
                  _leafCacheCard(state),
                  const SizedBox(height: 16),
                  const TlsHandshakeCard(),
                  const SizedBox(height: 10),
                  const TlsInspectionRuntimeCard(),
                  const SizedBox(height: 10),
                  _riskCard(state),
                  const SizedBox(height: 10),
                  _ruleCard(
                    title: l.tlsInspectionAllowlist,
                    description: l.tlsInspectionAllowlistDesc,
                    exclusion: false,
                    rules: state.policy.allowlist,
                  ),
                  const SizedBox(height: 10),
                  _ruleCard(
                    title: l.tlsInspectionExclusions,
                    description: l.tlsInspectionExclusionsDesc,
                    exclusion: true,
                    rules: state.policy.exclusions,
                  ),
                  const SizedBox(height: 12),
                  ListTile(
                    leading: const Icon(Icons.info_outline),
                    title: Text(l.tlsInspectionFoundationOnly),
                  ),
                  if (state.errorCode.isNotEmpty)
                    ListTile(
                      leading: Icon(
                        Icons.error_outline,
                        color: context.colorScheme.error,
                      ),
                      title: Text(
                        _errorLabel(
                          TlsInspectionPolicyException(
                            state.errorCode,
                            state.errorCode,
                          ),
                        ),
                      ),
                      subtitle: Text(state.errorCode),
                    ),
                ],
              ),
            ),
          );
        },
      ),
    );
  }
}

class _TlsInspectionRuleDialog extends StatefulWidget {
  final String title;

  const _TlsInspectionRuleDialog({required this.title});

  @override
  State<_TlsInspectionRuleDialog> createState() =>
      _TlsInspectionRuleDialogState();
}

class _TlsInspectionRuleDialogState extends State<_TlsInspectionRuleDialog> {
  final _controller = TextEditingController();
  TlsInspectionRuleScope _scope = TlsInspectionRuleScope.exact;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final l = context.appLocalizations;
    return CommonDialog(
      title: widget.title,
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: Text(l.cancel),
        ),
        FilledButton(
          onPressed: () {
            final input = _controller.text.trim();
            if (input.isEmpty) {
              return;
            }
            Navigator.of(context).pop((input: input, scope: _scope));
          },
          child: Text(l.tlsInspectionAddDomain),
        ),
      ],
      child: SizedBox(
        width: 360,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              controller: _controller,
              autofocus: true,
              autocorrect: false,
              enableSuggestions: false,
              decoration: InputDecoration(
                labelText: l.tlsInspectionAddDomain,
                hintText: l.tlsInspectionDomainHint,
              ),
              onSubmitted: (_) => setState(() {}),
            ),
            const SizedBox(height: 14),
            DropdownButtonFormField<TlsInspectionRuleScope>(
              initialValue: _scope,
              decoration: InputDecoration(labelText: l.tlsInspectionRuleScope),
              items: [
                DropdownMenuItem(
                  value: TlsInspectionRuleScope.exact,
                  child: Text(l.tlsInspectionExactDomain),
                ),
                DropdownMenuItem(
                  value: TlsInspectionRuleScope.subdomains,
                  child: Text(l.tlsInspectionDomainAndSubdomains),
                ),
              ],
              onChanged: (value) {
                if (value != null) {
                  setState(() => _scope = value);
                }
              },
            ),
          ],
        ),
      ),
    );
  }
}
