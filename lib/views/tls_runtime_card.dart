import 'dart:async';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/core/core.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/providers.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

class TlsInspectionRuntimeCard extends ConsumerStatefulWidget {
  const TlsInspectionRuntimeCard({super.key});

  @override
  ConsumerState<TlsInspectionRuntimeCard> createState() =>
      _TlsInspectionRuntimeCardState();
}

class _TlsInspectionRuntimeCardState
    extends ConsumerState<TlsInspectionRuntimeCard>
    with WidgetsBindingObserver {
  bool _showPassword = false;
  Timer? _clipboardClearTimer;
  String? _copiedText;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _clipboardClearTimer?.cancel();
    unawaited(_clearCopiedText());
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      return;
    }
    if (_showPassword && mounted) {
      setState(() => _showPassword = false);
    }
    unawaited(_clearCopiedText());
  }

  Future<void> _clearCopiedText() async {
    final expected = _copiedText;
    _copiedText = null;
    _clipboardClearTimer?.cancel();
    _clipboardClearTimer = null;
    if (expected == null) {
      return;
    }
    try {
      final current = await Clipboard.getData(Clipboard.kTextPlain);
      if (current?.text == expected) {
        await Clipboard.setData(const ClipboardData(text: ''));
      }
    } catch (_) {}
  }

  String _phaseLabel(TlsInspectionRuntimePhase phase) {
    final l = context.appLocalizations;
    return switch (phase) {
      TlsInspectionRuntimePhase.stopped => l.tlsInspectionRuntimeStopped,
      TlsInspectionRuntimePhase.starting => l.tlsInspectionRuntimeStarting,
      TlsInspectionRuntimePhase.running => l.tlsInspectionRuntimeRunning,
      TlsInspectionRuntimePhase.stopping => l.tlsInspectionRuntimeStopping,
      TlsInspectionRuntimePhase.stopUnconfirmed =>
        l.tlsInspectionRuntimeStopUnconfirmed,
      TlsInspectionRuntimePhase.unavailable =>
        l.tlsInspectionRuntimeUnavailable,
    };
  }

  String _errorLabel(String code) {
    final l = context.appLocalizations;
    return switch (code) {
      'runtime_not_authorized' ||
      'runtime_confirmation_required' ||
      'runtime_identity_unavailable' => l.tlsInspectionRuntimeRequirements,
      'runtime_stop_unconfirmed' => l.tlsInspectionRuntimeStopError,
      'runtime_orphaned' ||
      'runtime_credentials_unavailable' => l.tlsInspectionRuntimeOrphaned,
      'core-disconnected' => l.tlsInspectionErrorCoreDisconnected,
      _ => l.tlsInspectionRuntimeError,
    };
  }

  Future<void> _start() async {
    final l = context.appLocalizations;
    final confirmed = await dialogs.showMessage(
      context: context,
      title: l.tlsInspectionRuntimeStartTitle,
      message: TextSpan(text: l.tlsInspectionRuntimeStartWarning),
      confirmText: l.tlsInspectionRuntimeStart,
    );
    if (confirmed != true || !mounted) {
      return;
    }
    try {
      await ref
          .read(tlsInspectionRuntimeProvider.notifier)
          .start(confirmed: true);
      if (mounted) {
        context.showNotifier(
          l.tlsInspectionRuntimeStarted,
          level: MessageLevel.success,
        );
      }
    } catch (error) {
      if (mounted) {
        final code = switch (error) {
          final CoreMethodException value => value.code,
          final TlsInspectionPolicyException value => value.code,
          _ => '',
        };
        context.showNotifier(_errorLabel(code), level: MessageLevel.error);
      }
    }
  }

  Future<void> _stop() async {
    try {
      await ref.read(tlsInspectionRuntimeProvider.notifier).stop();
      await _clearCopiedText();
      if (mounted) {
        setState(() => _showPassword = false);
        context.showNotifier(
          context.appLocalizations.tlsInspectionRuntimeStoppedNotice,
          level: MessageLevel.success,
        );
      }
    } catch (_) {
      if (mounted) {
        context.showNotifier(
          context.appLocalizations.tlsInspectionRuntimeStopError,
          level: MessageLevel.error,
        );
      }
    }
  }

  Future<void> _refresh() async {
    await ref.read(tlsInspectionRuntimeProvider.notifier).reconcile();
  }

  Future<void> _copyText(
    String content, {
    required String successMessage,
  }) async {
    try {
      await Clipboard.setData(ClipboardData(text: content));
    } catch (_) {
      if (mounted) {
        context.showNotifier(
          context.appLocalizations.tlsInspectionRuntimeCopyError,
          level: MessageLevel.error,
        );
      }
      return;
    }
    _copiedText = content;
    _clipboardClearTimer?.cancel();
    _clipboardClearTimer = Timer(
      const Duration(minutes: 1),
      () => unawaited(_clearCopiedText()),
    );
    if (mounted) {
      context.showNotifier(successMessage, level: MessageLevel.success);
    }
  }

  Future<void> _copySettings(TlsInspectionRuntimeStart access) async {
    final status = access.status;
    final hostAndPort = status.address.split(':');
    final content = [
      'type=HTTP CONNECT',
      'host=${hostAndPort.first}',
      'port=${hostAndPort.last}',
      'username=${access.username}',
      'password=${access.password}',
    ].join('\n');
    await _copyText(
      content,
      successMessage: context.appLocalizations.tlsInspectionRuntimeCopySuccess,
    );
  }

  Widget _copyButton({required String tooltip, required String value}) {
    return IconButton(
      tooltip: tooltip,
      onPressed: () => _copyText(
        value,
        successMessage: context.appLocalizations.copySuccess,
      ),
      icon: const Icon(Icons.copy_outlined),
    );
  }

  Widget _detailRow(String label, String value, {Widget? trailing}) {
    final labelStyle = context.textTheme.bodySmall?.copyWith(
      color: context.colorScheme.onSurfaceVariant,
    );
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 5),
      child: LayoutBuilder(
        builder: (context, constraints) {
          if (constraints.maxWidth < 320) {
            return Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  crossAxisAlignment: CrossAxisAlignment.center,
                  children: [
                    Expanded(child: Text(label, style: labelStyle)),
                    ?trailing,
                  ],
                ),
                const SizedBox(height: 2),
                SelectableText(value),
              ],
            );
          }
          return Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              SizedBox(width: 150, child: Text(label, style: labelStyle)),
              Expanded(child: SelectableText(value)),
              ?trailing,
            ],
          );
        },
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final l = context.appLocalizations;
    final foundation = ref.watch(tlsInspectionProvider);
    final runtime = ref.watch(tlsInspectionRuntimeProvider);
    ref.listen<TlsInspectionRuntimeState>(tlsInspectionRuntimeProvider, (
      previous,
      next,
    ) {
      if (next.access == null) {
        if (_showPassword && mounted) {
          setState(() => _showPassword = false);
        }
        unawaited(_clearCopiedText());
      }
    });
    final status = runtime.status;
    final access = runtime.access;
    final running = runtime.running && status != null && access != null;
    final canStart =
        foundation.prepared &&
        runtime.phase == TlsInspectionRuntimePhase.stopped &&
        !runtime.busy;
    final phaseColor = running
        ? context.colorScheme.primary
        : runtime.phase == TlsInspectionRuntimePhase.stopUnconfirmed
        ? context.colorScheme.error
        : context.colorScheme.onSurfaceVariant;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.lan_outlined, color: phaseColor),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    l.tlsInspectionRuntime,
                    style: context.textTheme.titleMedium?.toSoftBold,
                  ),
                ),
                Chip(label: Text(_phaseLabel(runtime.phase))),
              ],
            ),
            const SizedBox(height: 8),
            Text(l.tlsInspectionRuntimeDesc),
            const SizedBox(height: 6),
            Text(
              l.tlsInspectionRuntimeBoundary,
              style: context.textTheme.bodySmall?.copyWith(
                color: context.colorScheme.error,
              ),
            ),
            if (!foundation.prepared && !running) ...[
              const SizedBox(height: 12),
              ListTile(
                contentPadding: EdgeInsets.zero,
                leading: const Icon(Icons.fact_check_outlined),
                title: Text(l.tlsInspectionRuntimeRequirements),
              ),
            ],
            if (running) ...[
              const SizedBox(height: 12),
              _detailRow(
                l.tlsInspectionRuntimeAddress,
                status.address,
                trailing: _copyButton(
                  tooltip: l.tlsInspectionRuntimeCopyAddress,
                  value: status.address,
                ),
              ),
              _detailRow(
                l.tlsInspectionRuntimeUsername,
                access.username,
                trailing: _copyButton(
                  tooltip: l.tlsInspectionRuntimeCopyUsername,
                  value: access.username,
                ),
              ),
              _detailRow(
                l.tlsInspectionRuntimePassword,
                _showPassword ? access.password : '••••••••••••••••',
                trailing: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    _copyButton(
                      tooltip: l.tlsInspectionRuntimeCopyPassword,
                      value: access.password,
                    ),
                    IconButton(
                      tooltip: _showPassword
                          ? l.tlsInspectionRuntimeHidePassword
                          : l.tlsInspectionRuntimeShowPassword,
                      onPressed: () =>
                          setState(() => _showPassword = !_showPassword),
                      icon: Icon(
                        _showPassword
                            ? Icons.visibility_off_outlined
                            : Icons.visibility_outlined,
                      ),
                    ),
                  ],
                ),
              ),
              if (status.expiresAt != null)
                _detailRow(
                  l.tlsInspectionRuntimeExpires,
                  status.expiresAt!.toLocal().showFull,
                ),
              _detailRow(l.tlsInspectionRuntimeActive, '${status.active}'),
              _detailRow(l.tlsInspectionRuntimeAccepted, '${status.accepted}'),
              _detailRow(
                l.tlsInspectionRuntimeCompleted,
                '${status.completed}',
              ),
              _detailRow(l.tlsInspectionRuntimeFailed, '${status.failed}'),
              _detailRow(
                l.tlsInspectionRuntimeUploaded,
                status.uploaded.traffic.show,
              ),
              _detailRow(
                l.tlsInspectionRuntimeDownloaded,
                status.downloaded.traffic.show,
              ),
              const SizedBox(height: 8),
              Text(
                l.tlsInspectionRuntimeCredentialsWarning,
                style: context.textTheme.bodySmall?.copyWith(
                  color: context.colorScheme.onSurfaceVariant,
                ),
              ),
            ],
            if (runtime.errorCode.isNotEmpty) ...[
              const SizedBox(height: 10),
              ListTile(
                contentPadding: EdgeInsets.zero,
                leading: Icon(
                  Icons.error_outline,
                  color: context.colorScheme.error,
                ),
                title: Text(_errorLabel(runtime.errorCode)),
                subtitle: Text(runtime.errorCode),
              ),
            ],
            const SizedBox(height: 12),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                if (!running &&
                    runtime.phase != TlsInspectionRuntimePhase.stopUnconfirmed)
                  FilledButton.icon(
                    onPressed: canStart ? _start : null,
                    icon: const Icon(Icons.play_arrow),
                    label: Text(l.tlsInspectionRuntimeStart),
                  ),
                if (running ||
                    runtime.phase ==
                        TlsInspectionRuntimePhase.stopUnconfirmed ||
                    runtime.phase == TlsInspectionRuntimePhase.starting)
                  FilledButton.tonalIcon(
                    onPressed:
                        runtime.phase == TlsInspectionRuntimePhase.stopping
                        ? null
                        : _stop,
                    icon: const Icon(Icons.stop),
                    label: Text(l.tlsInspectionRuntimeStop),
                  ),
                OutlinedButton.icon(
                  onPressed: runtime.busy ? null : _refresh,
                  icon: const Icon(Icons.refresh_outlined),
                  label: Text(l.tlsInspectionRuntimeRefresh),
                ),
                if (running)
                  OutlinedButton.icon(
                    onPressed: () => _copySettings(access),
                    icon: const Icon(Icons.copy_outlined),
                    label: Text(l.tlsInspectionRuntimeCopySettings),
                  ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
