import 'dart:async';
import 'dart:convert';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/features/connection/quick_routing.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/providers.dart';
import 'package:fl_clash/state.dart';
import 'package:fl_clash/widgets/widgets.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

extension on HttpCaptureProtocol {
  String label(BuildContext context) {
    final l = context.appLocalizations;
    return switch (this) {
      HttpCaptureProtocol.http => l.httpCaptureProtocolHttp,
      HttpCaptureProtocol.tls => l.httpCaptureProtocolTls,
      HttpCaptureProtocol.quic => l.httpCaptureProtocolQuic,
      HttpCaptureProtocol.unknown => l.httpCaptureProtocolUnknown,
    };
  }

  IconData get icon => switch (this) {
    HttpCaptureProtocol.http => Icons.http_outlined,
    HttpCaptureProtocol.tls => Icons.lock_outline,
    HttpCaptureProtocol.quic => Icons.speed_outlined,
    HttpCaptureProtocol.unknown => Icons.help_outline,
  };

  Color color(BuildContext context) => switch (this) {
    HttpCaptureProtocol.http => context.colorScheme.primary,
    HttpCaptureProtocol.tls => context.colorScheme.tertiary,
    HttpCaptureProtocol.quic => context.colorScheme.secondary,
    HttpCaptureProtocol.unknown => context.colorScheme.outline,
  };
}

extension on HttpCaptureSource {
  String label(BuildContext context) {
    final l = context.appLocalizations;
    return switch (this) {
      HttpCaptureSource.connectionCandidate =>
        l.httpCaptureSourceConnectionCandidate,
      HttpCaptureSource.passiveCore => l.httpCaptureSourcePassiveCore,
      HttpCaptureSource.inspectedRuntime => l.httpCaptureSourceInspectedRuntime,
    };
  }

  IconData get icon => switch (this) {
    HttpCaptureSource.connectionCandidate => Icons.hub_outlined,
    HttpCaptureSource.passiveCore => Icons.memory_outlined,
    HttpCaptureSource.inspectedRuntime => Icons.security_outlined,
  };
}

class HttpCaptureView extends ConsumerStatefulWidget {
  const HttpCaptureView({super.key});

  @override
  ConsumerState<HttpCaptureView> createState() => _HttpCaptureViewState();
}

class _HttpCaptureViewState extends ConsumerState<HttpCaptureView> {
  String _query = '';
  HttpCaptureProtocol? _protocol;
  HttpCaptureSource? _source;
  bool _currentProfileOnly = true;

  @override
  void initState() {
    super.initState();
    unawaited(ref.read(httpCaptureProvider.notifier).reload());
  }

  String _evidenceLabel(BuildContext context, String evidence) {
    final l = context.appLocalizations;
    return switch (evidence) {
      'core-http1' => l.httpCaptureEvidenceCoreHttp1,
      'core-tls-client-hello' => l.httpCaptureEvidenceCoreTlsClientHello,
      'inspected-runtime' => l.httpCaptureEvidenceInspectedRuntime,
      'remote-scheme' => l.httpCaptureEvidenceRemoteScheme,
      'known-http-port' => l.httpCaptureEvidenceKnownHttpPort,
      'known-tls-port' => l.httpCaptureEvidenceKnownTlsPort,
      'known-quic-port' => l.httpCaptureEvidenceKnownQuicPort,
      'host-observed' => l.httpCaptureEvidenceHostObserved,
      'transport-only' => l.httpCaptureEvidenceTransportOnly,
      _ => evidence,
    };
  }

  String _runtimeFailureLabel(String value) {
    final l = context.appLocalizations;
    return switch (value) {
      'upstream-dial' => l.httpCaptureRuntimeFailureUpstreamDial,
      'upstream-tls' => l.httpCaptureRuntimeFailureUpstreamTls,
      'leaf' => l.httpCaptureRuntimeFailureLeaf,
      'downstream-tls' => l.httpCaptureRuntimeFailureDownstreamTls,
      'authorization-revoked' =>
        l.httpCaptureRuntimeFailureAuthorizationRevoked,
      'relay' => l.httpCaptureRuntimeFailureRelay,
      'capture-stopped' => l.httpCaptureRuntimeFailureCaptureStopped,
      'capture-interrupted' => l.httpCaptureRuntimeFailureCaptureInterrupted,
      _ => l.tlsInspectionRuntimeFailed,
    };
  }

  List<HttpCaptureEntry> _filter(
    List<HttpCaptureEntry> entries,
    int? profileId,
  ) {
    final terms = _query
        .trim()
        .toLowerCase()
        .split(RegExp(r'\s+'))
        .where((term) => term.isNotEmpty)
        .toList(growable: false);
    return entries
        .where((entry) {
          if (_currentProfileOnly &&
              profileId != null &&
              entry.profileId != null &&
              entry.profileId != profileId) {
            return false;
          }
          if (_protocol != null && entry.protocol != _protocol) {
            return false;
          }
          if (_source != null && entry.source != _source) {
            return false;
          }
          return terms.isEmpty || terms.every(entry.searchText.contains);
        })
        .toList(growable: false);
  }

  Future<void> _toggleCapture(bool enabled) async {
    final notifier = ref.read(httpCaptureProvider.notifier);
    if (enabled) {
      await notifier.stop();
      return;
    }
    final policy = ref.read(httpCaptureProvider).capturePolicy;
    if (!policy.isMetadataOnly && !await _confirmCaptureRisk()) {
      return;
    }
    await notifier.start();
  }

  Future<bool> _confirmCaptureRisk() async {
    final l = context.appLocalizations;
    final confirmed = await dialogs.showMessage(
      title: l.httpCaptureRiskTitle,
      message: TextSpan(text: l.httpCaptureRiskMessage),
    );
    return confirmed == true;
  }

  void _updateCapturePolicy(TlsInspectionCapturePolicy policy) {
    ref.read(httpCaptureProvider.notifier).updateCapturePolicy(policy);
  }

  Future<void> _setHeaderValues(
    TlsInspectionCapturePolicy policy,
    bool enabled,
  ) async {
    if (enabled && !await _confirmCaptureRisk()) {
      return;
    }
    _updateCapturePolicy(
      policy.copyWith(
        headerValues: enabled,
        sensitiveHeaderValues: enabled && policy.sensitiveHeaderValues,
      ),
    );
  }

  Future<void> _setSensitiveHeaderValues(
    TlsInspectionCapturePolicy policy,
    bool enabled,
  ) async {
    if (enabled && !await _confirmCaptureRisk()) {
      return;
    }
    _updateCapturePolicy(policy.copyWith(sensitiveHeaderValues: enabled));
  }

  Future<void> _setBodyMode(
    TlsInspectionCapturePolicy policy,
    TlsInspectionCaptureBodyMode mode,
  ) async {
    if (mode != TlsInspectionCaptureBodyMode.none &&
        !await _confirmCaptureRisk()) {
      return;
    }
    _updateCapturePolicy(
      policy.copyWith(
        bodyMode: mode,
        maxBodyBytes: mode == TlsInspectionCaptureBodyMode.none
            ? 0
            : policy.maxBodyBytes == 0
            ? defaultInspectionBodyBytes
            : policy.maxBodyBytes,
      ),
    );
  }

  Future<void> _editRedactedHeaders(TlsInspectionCapturePolicy policy) async {
    final l = context.appLocalizations;
    final controller = TextEditingController(
      text: policy.redactedHeaderNames.join(', '),
    );
    final value = await showDialog<String>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: Text(l.httpCaptureRedactedHeaders),
        content: TextField(
          controller: controller,
          autofocus: true,
          maxLines: 4,
          decoration: InputDecoration(
            hintText: l.httpCaptureRedactedHeadersHint,
            helperText: l.httpCaptureRedactedHeadersDesc,
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(),
            child: Text(l.cancel),
          ),
          FilledButton(
            onPressed: () => Navigator.of(dialogContext).pop(controller.text),
            child: Text(l.save),
          ),
        ],
      ),
    );
    controller.dispose();
    if (value == null || !mounted) {
      return;
    }
    final names = value
        .split(RegExp(r'[,\s]+'))
        .map((item) => item.trim().toLowerCase())
        .where((item) => item.isNotEmpty)
        .toList(growable: false);
    _updateCapturePolicy(policy.copyWith(redactedHeaderNames: names));
  }

  String _exportFileName(DateTime value) {
    final local = value.toLocal();
    String two(int number) => number.toString().padLeft(2, '0');
    return 'flclash-http-observation-'
        '${local.year}${two(local.month)}${two(local.day)}-'
        '${two(local.hour)}${two(local.minute)}${two(local.second)}.har';
  }

  Future<void> _export(List<HttpCaptureEntry> entries) async {
    if (entries.isEmpty) {
      return;
    }
    final l = context.appLocalizations;
    final result = await globalState.safeRun<bool>(() async {
      final exportedAt = DateTime.now();
      final content = encodeHttpCaptureHar(
        entries: entries,
        exportedAt: exportedAt,
        creatorVersion: globalState.packageInfo.version,
      );
      final value = await picker.saveFile(
        _exportFileName(exportedAt),
        Uint8List.fromList(utf8.encode(content)),
      );
      return value != null;
    }, title: l.httpCaptureExportHar);
    if (result == true && mounted) {
      context.showNotifier(
        l.httpCaptureExportSuccess,
        level: MessageLevel.success,
      );
    }
  }

  Future<void> _clear() async {
    final l = context.appLocalizations;
    final confirmed = await dialogs.showMessage(
      title: l.clearData,
      message: TextSpan(text: l.deleteTip(l.httpCapture)),
    );
    if (confirmed != true || !mounted) {
      return;
    }
    final profileId = ref.read(currentProfileIdProvider);
    await ref
        .read(httpCaptureProvider.notifier)
        .clear(profileId: _currentProfileOnly ? profileId : null);
  }

  Future<void> _remove(
    HttpCaptureEntry entry,
    BuildContext sheetContext,
  ) async {
    await ref.read(httpCaptureProvider.notifier).remove(entry.id);
    if (sheetContext.mounted) {
      Navigator.of(sheetContext).pop();
    }
  }

  Future<void> _copyEntry(HttpCaptureEntry entry) async {
    final content = const JsonEncoder.withIndent('  ').convert(entry.toJson());
    await Clipboard.setData(ClipboardData(text: content));
    if (mounted) {
      context.showNotifier(
        context.appLocalizations.copySuccess,
        level: MessageLevel.success,
      );
    }
  }

  Future<void> _copyHar(HttpCaptureEntry entry) async {
    await Clipboard.setData(
      ClipboardData(text: encodeHttpCaptureHar(entries: [entry])),
    );
    if (mounted) {
      context.showNotifier(
        context.appLocalizations.copySuccess,
        level: MessageLevel.success,
      );
    }
  }

  void _showDetails(HttpCaptureEntry entry) {
    unawaited(
      showSheet<void>(
        context: context,
        props: const SheetProps(isScrollControlled: true),
        builder: (sheetContext) {
          final l = sheetContext.appLocalizations;
          final observation = entry.observation;
          final http = entry.httpObservation;
          final response = entry.httpResponseObservation;
          final tls = entry.tlsObservation;
          final inspected = entry.inspectionRuntime;
          final runtimeTransactions =
              inspected?.httpTransactions ??
              const <TlsInspectionRuntimeHttpTransaction>[];
          final runtimeStreams =
              inspected?.http2Streams ??
              const <TlsInspectionRuntimeHttp2Stream>[];
          String completeness(bool value) =>
              value ? l.httpCaptureComplete : l.httpCaptureIncomplete;
          String presence(bool value) =>
              value ? l.httpCapturePresent : l.httpCaptureNotPresent;
          return AdaptiveSheetScaffold(
            title: l.details(l.httpCapture),
            actions: [
              IconButtonData(
                icon: Icons.copy_outlined,
                tooltip: '${l.copy} JSON',
                onPressed: () => unawaited(_copyEntry(entry)),
              ),
              IconButtonData(
                icon: Icons.file_copy_outlined,
                tooltip: '${l.copy} HAR',
                onPressed: () => unawaited(_copyHar(entry)),
              ),
              IconButtonData(
                icon: Icons.delete_outline,
                tooltip: l.delete,
                onPressed: () => unawaited(_remove(entry, sheetContext)),
              ),
            ],
            body: ListView(
              padding: const EdgeInsets.fromLTRB(16, 8, 16, 24),
              children: [
                _HttpCaptureDetailHeader(entry: entry),
                const SizedBox(height: 12),
                CommonCard(
                  type: CommonCardType.filled,
                  radius: AppCorner.md,
                  child: Padding(
                    padding: const EdgeInsets.all(14),
                    child: Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Icon(
                          Icons.info_outline,
                          color: sheetContext.colorScheme.primary,
                        ),
                        const SizedBox(width: 10),
                        Expanded(
                          child: Text(
                            inspected == null
                                ? l.httpCaptureHarWarning
                                : l.httpCaptureInspectedBoundary,
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 12),
                _HttpCaptureDetailRow(
                  label: l.httpCaptureEndpoint,
                  value: entry.origin,
                ),
                _HttpCaptureDetailRow(
                  label: l.httpCaptureSourceType,
                  value: entry.source.label(sheetContext),
                ),
                if (runtimeTransactions.isNotEmpty ||
                    runtimeStreams.isNotEmpty ||
                    entry.httpTimelineTruncated) ...[
                  const SizedBox(height: 12),
                  Row(
                    children: [
                      Expanded(
                        child: Text(
                          runtimeStreams.isNotEmpty
                              ? l.httpCaptureHttp2Streams
                              : l.httpCaptureTransactions,
                          style: sheetContext.textTheme.titleSmall?.toSoftBold,
                        ),
                      ),
                      Chip(
                        label: Text(
                          l.httpCaptureTransactionCount(
                            runtimeTransactions.length + runtimeStreams.length,
                          ),
                        ),
                      ),
                    ],
                  ),
                  if (entry.httpTimelineTruncated) ...[
                    const SizedBox(height: 8),
                    Container(
                      width: double.infinity,
                      padding: const EdgeInsets.all(10),
                      decoration: BoxDecoration(
                        color: sheetContext.colorScheme.errorContainer,
                        borderRadius: BorderRadius.circular(AppCorner.md),
                      ),
                      child: Row(
                        children: [
                          Icon(
                            Icons.warning_amber_rounded,
                            size: 18,
                            color: sheetContext.colorScheme.onErrorContainer,
                          ),
                          const SizedBox(width: 8),
                          Expanded(
                            child: Text(
                              l.httpCaptureTimelineTruncated,
                              style: TextStyle(
                                color:
                                    sheetContext.colorScheme.onErrorContainer,
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                  for (final transaction in runtimeTransactions) ...[
                    const SizedBox(height: 8),
                    _HttpCaptureTransactionCard(transaction: transaction),
                  ],
                  for (final stream in runtimeStreams) ...[
                    const SizedBox(height: 8),
                    _HttpCaptureStreamCard(stream: stream),
                  ],
                ],
                if (http != null &&
                    runtimeTransactions.isEmpty &&
                    runtimeStreams.isEmpty) ...[
                  if (http.method.isNotEmpty)
                    _HttpCaptureDetailRow(
                      label: l.httpCaptureRequestMethod,
                      value: http.method,
                    ),
                  if (http.target.isNotEmpty)
                    _HttpCaptureDetailRow(
                      label: l.httpCaptureRequestTarget,
                      value: http.target,
                    ),
                  if (http.version.isNotEmpty)
                    _HttpCaptureDetailRow(
                      label: l.httpCaptureHttpVersion,
                      value: http.version,
                    ),
                  if (http.headerNames.isNotEmpty)
                    _HttpCaptureDetailRow(
                      label: l.httpCaptureHeaderNames,
                      value: http.headerNames.join(', '),
                    ),
                  if (http.headers.isNotEmpty)
                    _HttpCaptureHeaderValues(
                      title: l.httpCaptureRequestHeaders,
                      headers: http.headers,
                    ),
                  _HttpCaptureDetailRow(
                    label: l.httpCaptureHeadersComplete,
                    value: completeness(http.headersComplete),
                  ),
                  if (http.targetTruncated)
                    _HttpCaptureDetailRow(
                      label: l.httpCaptureTargetTruncated,
                      value: presence(true),
                    ),
                  if (http.hostTruncated)
                    _HttpCaptureDetailRow(
                      label: l.httpCaptureHostTruncated,
                      value: presence(true),
                    ),
                  if (http.headerNamesTruncated)
                    _HttpCaptureDetailRow(
                      label: l.httpCaptureHeaderNamesTruncated,
                      value: presence(true),
                    ),
                ],
                if (response != null &&
                    runtimeTransactions.isEmpty &&
                    runtimeStreams.isEmpty) ...[
                  const SizedBox(height: 12),
                  Text(
                    l.httpCaptureResponse,
                    style: sheetContext.textTheme.titleSmall?.toSoftBold,
                  ),
                  const SizedBox(height: 4),
                  if (response.statusCode != 0)
                    _HttpCaptureDetailRow(
                      label: l.httpCaptureResponseStatus,
                      value: '${response.statusCode}',
                    ),
                  if (response.version.isNotEmpty)
                    _HttpCaptureDetailRow(
                      label: l.httpCaptureResponseHttpVersion,
                      value: response.version,
                    ),
                  if (response.informationalStatusCodes.isNotEmpty)
                    _HttpCaptureDetailRow(
                      label: l.httpCaptureInformationalStatusCodes,
                      value: response.informationalStatusCodes.join(', '),
                    ),
                  if (response.headerNames.isNotEmpty)
                    _HttpCaptureDetailRow(
                      label: l.httpCaptureResponseHeaderNames,
                      value: response.headerNames.join(', '),
                    ),
                  if (response.headers.isNotEmpty)
                    _HttpCaptureHeaderValues(
                      title: l.httpCaptureResponseHeaders,
                      headers: response.headers,
                    ),
                  _HttpCaptureDetailRow(
                    label: l.httpCaptureResponseHeadersComplete,
                    value: completeness(response.headersComplete),
                  ),
                  _HttpCaptureDetailRow(
                    label: l.httpCaptureResponseObservedBytes,
                    value: '${response.observedBytes} B',
                  ),
                  _HttpCaptureDetailRow(
                    label: l.httpCaptureResponseObservedAfter,
                    value: '${response.observedAfterMilliseconds} ms',
                  ),
                  _HttpCaptureDetailRow(
                    label: l.httpCaptureResponseTruncated,
                    value: presence(response.truncated),
                  ),
                  if (response.headerNamesTruncated)
                    _HttpCaptureDetailRow(
                      label: l.httpCaptureResponseHeaderNamesTruncated,
                      value: presence(true),
                    ),
                  if (response.informationalStatusCodesTruncated)
                    _HttpCaptureDetailRow(
                      label: l.httpCaptureInformationalStatusCodesTruncated,
                      value: presence(true),
                    ),
                ],
                if (tls != null) ...[
                  if (tls.serverName.isNotEmpty)
                    _HttpCaptureDetailRow(
                      label: l.httpCaptureTlsServerName,
                      value: tls.serverName,
                    ),
                  if (tls.alpn.isNotEmpty)
                    _HttpCaptureDetailRow(
                      label: l.httpCaptureTlsAlpn,
                      value: tls.alpn.join(', '),
                    ),
                  if (tls.supportedVersions.isNotEmpty)
                    _HttpCaptureDetailRow(
                      label: l.httpCaptureTlsVersions,
                      value: tls.supportedVersions.join(', '),
                    ),
                  if (tls.legacyVersion.isNotEmpty)
                    _HttpCaptureDetailRow(
                      label: l.httpCaptureTlsLegacyVersion,
                      value: tls.legacyVersion,
                    ),
                  _HttpCaptureDetailRow(
                    label: l.httpCaptureTlsEch,
                    value: presence(tls.encryptedClientHello),
                  ),
                  _HttpCaptureDetailRow(
                    label: l.httpCaptureClientHelloComplete,
                    value: completeness(tls.clientHelloComplete),
                  ),
                ],
                if (inspected != null) ...[
                  _HttpCaptureDetailRow(
                    label: l.httpCaptureRuntimeState,
                    value: switch (inspected.state) {
                      'running' => l.tlsInspectionRuntimeRunning,
                      'completed' => l.httpCaptureComplete,
                      'interrupted' => l.logbookHttpCaptureInterrupted,
                      _ => l.tlsInspectionRuntimeFailed,
                    },
                  ),
                  _HttpCaptureDetailRow(
                    label: l.httpCaptureRuntimeId,
                    value: inspected.runtimeId,
                  ),
                  if (inspected.downstreamTlsVersion.isNotEmpty)
                    _HttpCaptureDetailRow(
                      label: l.httpCaptureRuntimeDownstreamTls,
                      value: inspected.downstreamTlsVersion,
                    ),
                  if (inspected.upstreamTlsVersion.isNotEmpty)
                    _HttpCaptureDetailRow(
                      label: l.httpCaptureRuntimeUpstreamTls,
                      value: inspected.upstreamTlsVersion,
                    ),
                  if (inspected.alpn.isNotEmpty)
                    _HttpCaptureDetailRow(
                      label: l.httpCaptureTlsAlpn,
                      value: inspected.alpn,
                    ),
                  if (inspected.upstreamDialCompletedAfterMilliseconds > 0)
                    _HttpCaptureDetailRow(
                      label: l.httpCaptureConnectCompletedAfter,
                      value:
                          '${inspected.upstreamDialCompletedAfterMilliseconds} ms',
                    ),
                  if (inspected.upstreamTlsCompletedAfterMilliseconds > 0)
                    _HttpCaptureDetailRow(
                      label: l.httpCaptureUpstreamTlsCompletedAfter,
                      value:
                          '${inspected.upstreamTlsCompletedAfterMilliseconds} ms',
                    ),
                  if (inspected.downstreamTlsCompletedAfterMilliseconds > 0)
                    _HttpCaptureDetailRow(
                      label: l.httpCaptureDownstreamTlsCompletedAfter,
                      value:
                          '${inspected.downstreamTlsCompletedAfterMilliseconds} ms',
                    ),
                  if (inspected.http2GoAway case final goAway?) ...[
                    _HttpCaptureDetailRow(
                      label: l.httpCaptureHttp2GoAway,
                      value:
                          '${l.httpCaptureStreamId(goAway.lastStreamId)} · '
                          '${l.httpCaptureErrorCode(goAway.errorCode)} · '
                          '${goAway.observedAfterMilliseconds} ms',
                    ),
                  ],
                  if (inspected.completedAt != null)
                    _HttpCaptureDetailRow(
                      label: l.httpCaptureRuntimeCompletedAt,
                      value: inspected.completedAt!.toLocal().showFull,
                    ),
                  if (inspected.failureKind.isNotEmpty)
                    _HttpCaptureDetailRow(
                      label: l.httpCaptureRuntimeFailure,
                      value: _runtimeFailureLabel(inspected.failureKind),
                    ),
                ],
                if (observation != null) ...[
                  _HttpCaptureDetailRow(
                    label: l.httpCaptureObservedBytes,
                    value: '${observation.observedBytes} B',
                  ),
                  _HttpCaptureDetailRow(
                    label: l.httpCaptureTruncated,
                    value: presence(observation.truncated),
                  ),
                ],
                _HttpCaptureDetailRow(
                  label: l.httpCaptureObservationDelay,
                  value: '${entry.observationDelayMs} ms',
                ),
                _HttpCaptureDetailRow(
                  label: l.network,
                  value: entry.network.toUpperCase(),
                ),
                if (entry.sourceIP.isNotEmpty)
                  _HttpCaptureDetailRow(
                    label: l.source,
                    value: entry.sourcePort == 0
                        ? entry.sourceIP
                        : '${entry.sourceIP}:${entry.sourcePort}',
                  ),
                if (entry.process.isNotEmpty)
                  _HttpCaptureDetailRow(
                    label: l.process,
                    value: entry.uid == 0
                        ? entry.process
                        : '${entry.process} (${entry.uid})',
                  ),
                if (entry.processPath.isNotEmpty)
                  _HttpCaptureDetailRow(
                    label: l.httpCaptureProcessPath,
                    value: entry.processPath,
                  ),
                if (entry.ruleText.isNotEmpty)
                  _HttpCaptureDetailRow(label: l.rule, value: entry.ruleText),
                if (entry.chains.isNotEmpty)
                  _HttpCaptureDetailRow(
                    label: l.proxyChains,
                    value: entry.chains.join(' → '),
                  ),
                _HttpCaptureDetailRow(
                  label: l.time,
                  value: entry.startedAt.toLocal().showFull,
                ),
                _HttpCaptureDetailRow(
                  label: l.trafficUsage,
                  value:
                      '${entry.upload.traffic.show} ↑  '
                      '${entry.download.traffic.show} ↓',
                ),
                const SizedBox(height: 16),
                Align(
                  alignment: Alignment.centerRight,
                  child: QuickRoutingButton(trackerInfo: entry.toTrackerInfo()),
                ),
              ],
            ),
          );
        },
      ),
    );
  }

  Widget _buildCaptureCard(BuildContext context, HttpCaptureState state) {
    final l = context.appLocalizations;
    return CommonCard(
      type: CommonCardType.filled,
      radius: AppCorner.lg,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Container(
                  padding: const EdgeInsets.all(10),
                  decoration: BoxDecoration(
                    color: context.colorScheme.primaryContainer,
                    borderRadius: BorderRadius.circular(AppCorner.md),
                  ),
                  child: Icon(
                    Icons.http_outlined,
                    color: context.colorScheme.onPrimaryContainer,
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        l.httpCapture,
                        style: context.textTheme.titleMedium?.toSoftBold,
                      ),
                      const SizedBox(height: 4),
                      Text(
                        l.httpCaptureDesc,
                        style: context.textTheme.bodySmall?.copyWith(
                          color: context.colorScheme.onSurfaceVariant,
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(width: 12),
                FilledButton.icon(
                  key: const ValueKey('http-capture-toggle'),
                  onPressed: () => unawaited(_toggleCapture(state.enabled)),
                  icon: Icon(
                    state.enabled ? Icons.stop : Icons.fiber_manual_record,
                  ),
                  label: Text(state.enabled ? l.stop : l.start),
                ),
              ],
            ),
            const SizedBox(height: 14),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: context.colorScheme.surfaceContainerHighest,
                borderRadius: BorderRadius.circular(AppCorner.md),
              ),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Icon(
                    Icons.shield_outlined,
                    size: 20,
                    color: context.colorScheme.primary,
                  ),
                  const SizedBox(width: 10),
                  Expanded(child: Text(l.httpCaptureObservationOnly)),
                ],
              ),
            ),
            const SizedBox(height: 12),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                Chip(
                  avatar: Icon(
                    state.enabled
                        ? Icons.radio_button_checked
                        : Icons.radio_button_unchecked,
                    size: 18,
                  ),
                  label: Text(
                    state.enabled ? l.httpCaptureRunning : l.httpCaptureStopped,
                  ),
                ),
                Chip(
                  avatar: const Icon(Icons.visibility_outlined, size: 18),
                  label: Text('${state.sessionEntryCount}'),
                ),
                Chip(
                  avatar: const Icon(Icons.storage_outlined, size: 18),
                  label: Text('${state.entries.length}'),
                ),
                if (state.enabled || state.coreObserverActive)
                  Chip(
                    avatar: Icon(
                      state.coreObserverActive
                          ? state.enabled
                                ? Icons.memory_outlined
                                : Icons.privacy_tip_outlined
                          : Icons.hub_outlined,
                      size: 18,
                    ),
                    label: Text(
                      !state.enabled && state.coreObserverActive
                          ? l.httpCaptureCoreObserverStopping
                          : state.coreObserverActive
                          ? l.httpCaptureCoreObserverActive
                          : l.httpCaptureConnectionFallback,
                    ),
                  ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildCapturePolicyCard(BuildContext context, HttpCaptureState state) {
    final l = context.appLocalizations;
    final policy = state.capturePolicy;
    final enabled = !state.enabled;
    String bodyModeLabel(TlsInspectionCaptureBodyMode mode) => switch (mode) {
      TlsInspectionCaptureBodyMode.none => l.httpCaptureBodyNone,
      TlsInspectionCaptureBodyMode.text => l.httpCaptureBodyText,
      TlsInspectionCaptureBodyMode.all => l.httpCaptureBodyAll,
    };
    return CommonCard(
      type: CommonCardType.filled,
      radius: AppCorner.lg,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  Icons.privacy_tip_outlined,
                  color: context.colorScheme.primary,
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        l.httpCapturePrivacy,
                        style: context.textTheme.titleSmall?.toSoftBold,
                      ),
                      const SizedBox(height: 2),
                      Text(
                        state.enabled
                            ? l.httpCapturePolicyLocked
                            : l.httpCapturePrivacyDesc,
                        style: context.textTheme.bodySmall?.copyWith(
                          color: context.colorScheme.onSurfaceVariant,
                        ),
                      ),
                    ],
                  ),
                ),
                Chip(
                  avatar: Icon(
                    policy.isMetadataOnly
                        ? Icons.shield_outlined
                        : Icons.warning_amber_rounded,
                    size: 18,
                  ),
                  label: Text(
                    policy.isMetadataOnly
                        ? l.httpCaptureMetadataOnly
                        : l.httpCaptureContentEnabled,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              title: Text(l.httpCaptureHeaderValues),
              subtitle: Text(l.httpCaptureHeaderValuesDesc),
              value: policy.headerValues,
              onChanged: enabled
                  ? (value) => unawaited(_setHeaderValues(policy, value))
                  : null,
            ),
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              title: Text(l.httpCaptureSensitiveHeaderValues),
              subtitle: Text(l.httpCaptureSensitiveHeaderValuesDesc),
              value: policy.sensitiveHeaderValues,
              onChanged: enabled && policy.headerValues
                  ? (value) =>
                        unawaited(_setSensitiveHeaderValues(policy, value))
                  : null,
            ),
            const SizedBox(height: 8),
            LayoutBuilder(
              builder: (context, constraints) {
                final compact = constraints.maxWidth < 620;
                final mode =
                    DropdownButtonFormField<TlsInspectionCaptureBodyMode>(
                      initialValue: policy.bodyMode,
                      decoration: InputDecoration(
                        labelText: l.httpCaptureBodyMode,
                      ),
                      items: [
                        for (final value in TlsInspectionCaptureBodyMode.values)
                          DropdownMenuItem(
                            value: value,
                            child: Text(bodyModeLabel(value)),
                          ),
                      ],
                      onChanged: enabled
                          ? (value) {
                              if (value != null) {
                                unawaited(_setBodyMode(policy, value));
                              }
                            }
                          : null,
                    );
                final limit = DropdownButtonFormField<int>(
                  initialValue: policy.capturesBodies
                      ? policy.maxBodyBytes
                      : defaultInspectionBodyBytes,
                  decoration: InputDecoration(
                    labelText: l.httpCaptureBodyLimit,
                  ),
                  items: const [
                    DropdownMenuItem(value: 4 * 1024, child: Text('4 KiB')),
                    DropdownMenuItem(value: 16 * 1024, child: Text('16 KiB')),
                    DropdownMenuItem(value: 64 * 1024, child: Text('64 KiB')),
                  ],
                  onChanged: enabled && policy.capturesBodies
                      ? (value) {
                          if (value != null) {
                            _updateCapturePolicy(
                              policy.copyWith(maxBodyBytes: value),
                            );
                          }
                        }
                      : null,
                );
                if (compact) {
                  return Column(
                    children: [mode, const SizedBox(height: 12), limit],
                  );
                }
                return Row(
                  children: [
                    Expanded(child: mode),
                    const SizedBox(width: 12),
                    Expanded(child: limit),
                  ],
                );
              },
            ),
            const SizedBox(height: 8),
            ListTile(
              contentPadding: EdgeInsets.zero,
              leading: const Icon(Icons.visibility_off_outlined),
              title: Text(l.httpCaptureRedactedHeaders),
              subtitle: Text(
                policy.redactedHeaderNames.isEmpty
                    ? l.httpCaptureRedactedHeadersDesc
                    : policy.redactedHeaderNames.join(', '),
              ),
              trailing: const Icon(Icons.edit_outlined),
              enabled: enabled,
              onTap: enabled
                  ? () => unawaited(_editRedactedHeaders(policy))
                  : null,
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildSummary(BuildContext context, List<HttpCaptureEntry> entries) {
    int count(HttpCaptureProtocol protocol) =>
        entries.where((entry) => entry.protocol == protocol).length;
    return Wrap(
      spacing: 8,
      runSpacing: 8,
      children: [
        for (final protocol in HttpCaptureProtocol.values)
          _HttpCaptureMetric(protocol: protocol, value: count(protocol)),
      ],
    );
  }

  Widget _buildFilters(BuildContext context, int? profileId) {
    final l = context.appLocalizations;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SingleChildScrollView(
          scrollDirection: Axis.horizontal,
          child: Row(
            children: [
              FilterChip(
                selected: _protocol == null,
                label: Text(l.logbookAll),
                onSelected: (_) => setState(() => _protocol = null),
              ),
              const SizedBox(width: 8),
              for (final protocol in HttpCaptureProtocol.values) ...[
                FilterChip(
                  avatar: Icon(protocol.icon, size: 18),
                  selected: _protocol == protocol,
                  label: Text(protocol.label(context)),
                  onSelected: (_) => setState(() => _protocol = protocol),
                ),
                const SizedBox(width: 8),
              ],
            ],
          ),
        ),
        const SizedBox(height: 8),
        SingleChildScrollView(
          scrollDirection: Axis.horizontal,
          child: Row(
            children: [
              FilterChip(
                selected: _source == null,
                label: Text(l.logbookAll),
                onSelected: (_) => setState(() => _source = null),
              ),
              const SizedBox(width: 8),
              for (final source in HttpCaptureSource.values) ...[
                FilterChip(
                  avatar: Icon(source.icon, size: 18),
                  selected: _source == source,
                  label: Text(source.label(context)),
                  onSelected: (_) => setState(() => _source = source),
                ),
                const SizedBox(width: 8),
              ],
            ],
          ),
        ),
        if (profileId != null) ...[
          const SizedBox(height: 8),
          FilterChip(
            avatar: const Icon(Icons.person_outline, size: 18),
            selected: _currentProfileOnly,
            label: Text(
              _currentProfileOnly
                  ? l.httpCaptureCurrentProfile
                  : l.httpCaptureAllProfiles,
            ),
            onSelected: (value) {
              setState(() => _currentProfileOnly = value);
            },
          ),
        ],
      ],
    );
  }

  Widget _buildEntry(BuildContext context, HttpCaptureEntry entry) {
    final protocol = entry.protocol;
    final l = context.appLocalizations;
    return CommonCard(
      type: CommonCardType.filled,
      radius: AppCorner.lg,
      onPressed: () => _showDetails(entry),
      child: Padding(
        padding: const EdgeInsets.fromLTRB(14, 12, 8, 12),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Container(
              width: 42,
              height: 42,
              decoration: BoxDecoration(
                color: protocol.color(context).withValues(alpha: 0.14),
                borderRadius: BorderRadius.circular(AppCorner.md),
              ),
              child: Icon(protocol.icon, color: protocol.color(context)),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    entry.origin.isEmpty ? entry.endpointHost : entry.origin,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: context.textTheme.titleSmall?.toSoftBold,
                  ),
                  const SizedBox(height: 4),
                  Text(
                    '${protocol.label(context)} · '
                    '${_evidenceLabel(context, entry.evidence)}',
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: context.textTheme.bodySmall?.copyWith(
                      color: context.colorScheme.onSurfaceVariant,
                    ),
                  ),
                  if (entry.httpObservation case final http?) ...[
                    const SizedBox(height: 6),
                    Text(
                      [
                        '${http.method} ${http.target}'.trim(),
                        if (entry.httpResponseObservation case final response?
                            when response.statusCode != 0)
                          '→ ${response.statusCode}',
                        if (entry.httpTransactionCount > 1)
                          '· ${l.httpCaptureTransactionCount(entry.httpTransactionCount)}',
                        if (entry.httpTimelineTruncated)
                          '· ${l.httpCaptureTimelineTruncated}',
                      ].join(' '),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: context.textTheme.bodySmall?.toSoftBold,
                    ),
                  ] else if (entry.tlsObservation case final tls?) ...[
                    const SizedBox(height: 6),
                    Text(
                      [
                        if (tls.serverName.isNotEmpty) tls.serverName,
                        if (tls.alpn.isNotEmpty) tls.alpn.join(', '),
                      ].join(' · '),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: context.textTheme.bodySmall?.toSoftBold,
                    ),
                  ] else if (entry.inspectionRuntime case final inspected?) ...[
                    const SizedBox(height: 6),
                    Text(
                      [
                        switch (inspected.state) {
                          'running' =>
                            context
                                .appLocalizations
                                .tlsInspectionRuntimeRunning,
                          'completed' =>
                            context.appLocalizations.httpCaptureComplete,
                          'interrupted' =>
                            context
                                .appLocalizations
                                .logbookHttpCaptureInterrupted,
                          _ =>
                            context.appLocalizations.tlsInspectionRuntimeFailed,
                        },
                        if (inspected.downstreamTlsVersion.isNotEmpty)
                          inspected.downstreamTlsVersion,
                        if (inspected.upstreamTlsVersion.isNotEmpty)
                          inspected.upstreamTlsVersion,
                        if (inspected.alpn.isNotEmpty) inspected.alpn,
                      ].join(' · '),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: context.textTheme.bodySmall?.toSoftBold,
                    ),
                  ],
                  if (entry.process.isNotEmpty ||
                      entry.ruleText.isNotEmpty) ...[
                    const SizedBox(height: 6),
                    Text(
                      [
                        if (entry.process.isNotEmpty) entry.process,
                        if (entry.ruleText.isNotEmpty) entry.ruleText,
                      ].join(' · '),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: context.textTheme.bodySmall,
                    ),
                  ],
                  const SizedBox(height: 6),
                  Text(
                    '${entry.observedAt.toLocal().showFull} · '
                    '${entry.upload.traffic.show} ↑ '
                    '${entry.download.traffic.show} ↓',
                    style: context.textTheme.labelSmall?.copyWith(
                      color: context.colorScheme.onSurfaceVariant,
                    ),
                  ),
                ],
              ),
            ),
            QuickRoutingButton(trackerInfo: entry.toTrackerInfo()),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final l = context.appLocalizations;
    final state = ref.watch(httpCaptureProvider);
    final profileId = ref.watch(currentProfileIdProvider);
    final filtered = _filter(state.entries, profileId);

    return CommonScaffold(
      title: l.httpCapture,
      searchState: AppBarSearchState(
        onSearch: (query) => setState(() => _query = query),
      ),
      actions: [
        IconButton(
          tooltip: l.httpCaptureExportHar,
          onPressed: filtered.isEmpty
              ? null
              : () => unawaited(_export(filtered)),
          icon: const Icon(Icons.file_download_outlined),
        ),
        IconButton(
          tooltip: l.update,
          onPressed: () =>
              unawaited(ref.read(httpCaptureProvider.notifier).reload()),
          icon: const Icon(Icons.refresh),
        ),
        IconButton(
          tooltip: l.clearData,
          onPressed: state.entries.isEmpty ? null : () => unawaited(_clear()),
          icon: const Icon(Icons.delete_sweep_outlined),
        ),
      ],
      body: LayoutBuilder(
        builder: (context, constraints) {
          final width = constraints.maxWidth > 1040
              ? 1040.0
              : constraints.maxWidth;
          return Center(
            child: SizedBox(
              width: width,
              height: constraints.maxHeight,
              child: CustomScrollView(
                slivers: [
                  SliverPadding(
                    padding: const EdgeInsets.fromLTRB(12, 12, 12, 0),
                    sliver: SliverToBoxAdapter(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          _buildCaptureCard(context, state),
                          const SizedBox(height: 12),
                          _buildCapturePolicyCard(context, state),
                          const SizedBox(height: 12),
                          _buildSummary(context, filtered),
                          const SizedBox(height: 12),
                          _buildFilters(context, profileId),
                        ],
                      ),
                    ),
                  ),
                  if (filtered.isEmpty)
                    SliverFillRemaining(
                      hasScrollBody: false,
                      child: NullStatus(
                        label: l.httpCaptureEmpty,
                        description: l.httpCaptureObservationOnly,
                        illustration: NullStatusIllustration.requests,
                      ),
                    )
                  else
                    SliverPadding(
                      padding: EdgeInsets.fromLTRB(
                        12,
                        12,
                        12,
                        24 + BottomInsetScope.of(context),
                      ),
                      sliver: SliverList.builder(
                        itemCount: filtered.length,
                        itemBuilder: (context, index) {
                          return Padding(
                            padding: EdgeInsets.only(
                              bottom: index == filtered.length - 1 ? 0 : 8,
                            ),
                            child: _buildEntry(context, filtered[index]),
                          );
                        },
                      ),
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

class _HttpCaptureTransactionCard extends StatelessWidget {
  final TlsInspectionRuntimeHttpTransaction transaction;

  const _HttpCaptureTransactionCard({required this.transaction});

  @override
  Widget build(BuildContext context) {
    final l = context.appLocalizations;
    return _HttpCaptureExchangeCard(
      badge: '${transaction.sequence}',
      title: '${l.httpCaptureTransaction} #${transaction.sequence}',
      request: transaction.request,
      requestBody: transaction.requestBody,
      response: transaction.response,
      responseBody: transaction.responseBody,
      requestObservedAfterMilliseconds:
          transaction.requestObservedAfterMilliseconds,
      requestCompletedAfterMilliseconds:
          transaction.requestCompletedAfterMilliseconds,
      responseCompletedAfterMilliseconds:
          transaction.responseCompletedAfterMilliseconds,
    );
  }
}

class _HttpCaptureStreamCard extends StatelessWidget {
  final TlsInspectionRuntimeHttp2Stream stream;

  const _HttpCaptureStreamCard({required this.stream});

  String _stateLabel(BuildContext context) {
    final l = context.appLocalizations;
    return switch (stream.state) {
      'open' => l.httpCaptureStreamOpen,
      'request-ended' => l.httpCaptureStreamRequestEnded,
      'response-ended' => l.httpCaptureStreamResponseEnded,
      'closed' => l.httpCaptureStreamClosed,
      'reset' => l.httpCaptureStreamReset,
      _ => stream.state,
    };
  }

  @override
  Widget build(BuildContext context) {
    final l = context.appLocalizations;
    return _HttpCaptureExchangeCard(
      badge: '${stream.streamId}',
      title: '${l.httpCaptureHttp2Stream} ${stream.streamId}',
      subtitle: [
        _stateLabel(context),
        if (stream.resetCode != 0) l.httpCaptureErrorCode(stream.resetCode),
      ].join(' · '),
      request: stream.request,
      requestBody: stream.requestBody,
      response: stream.response,
      responseBody: stream.responseBody,
      requestObservedAfterMilliseconds: stream.requestObservedAfterMilliseconds,
      requestCompletedAfterMilliseconds:
          stream.requestCompletedAfterMilliseconds,
      responseCompletedAfterMilliseconds:
          stream.responseCompletedAfterMilliseconds,
    );
  }
}

class _HttpCaptureExchangeCard extends StatelessWidget {
  final String badge;
  final String title;
  final String subtitle;
  final HttpProtocolObservation request;
  final TlsInspectionRuntimeHttpBody? requestBody;
  final HttpResponseProtocolObservation? response;
  final TlsInspectionRuntimeHttpBody? responseBody;
  final int requestObservedAfterMilliseconds;
  final int requestCompletedAfterMilliseconds;
  final int responseCompletedAfterMilliseconds;

  const _HttpCaptureExchangeCard({
    required this.badge,
    required this.title,
    this.subtitle = '',
    required this.request,
    this.requestBody,
    this.response,
    this.responseBody,
    required this.requestObservedAfterMilliseconds,
    required this.requestCompletedAfterMilliseconds,
    required this.responseCompletedAfterMilliseconds,
  });

  @override
  Widget build(BuildContext context) {
    final l = context.appLocalizations;
    final currentResponse = response;
    String completeness(bool value) =>
        value ? l.httpCaptureComplete : l.httpCaptureIncomplete;
    String presence(bool value) =>
        value ? l.httpCapturePresent : l.httpCaptureNotPresent;
    final summary = [
      '${request.method} ${request.target}'.trim(),
      if (currentResponse != null && currentResponse.statusCode != 0)
        '→ ${currentResponse.statusCode}',
    ].join(' ');
    return CommonCard(
      type: CommonCardType.filled,
      radius: AppCorner.md,
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Container(
                  constraints: const BoxConstraints(minWidth: 32),
                  height: 32,
                  padding: const EdgeInsets.symmetric(horizontal: 7),
                  alignment: Alignment.center,
                  decoration: BoxDecoration(
                    color: context.colorScheme.primaryContainer,
                    borderRadius: BorderRadius.circular(AppCorner.sm),
                  ),
                  child: Text(
                    badge,
                    style: context.textTheme.labelLarge?.copyWith(
                      color: context.colorScheme.onPrimaryContainer,
                    ),
                  ),
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        title,
                        style: context.textTheme.titleSmall?.toSoftBold,
                      ),
                      if (subtitle.isNotEmpty) ...[
                        const SizedBox(height: 2),
                        Text(
                          subtitle,
                          style: context.textTheme.labelMedium?.copyWith(
                            color: context.colorScheme.onSurfaceVariant,
                          ),
                        ),
                      ],
                      if (summary.isNotEmpty) ...[
                        const SizedBox(height: 2),
                        SelectableText(
                          summary,
                          style: context.textTheme.bodySmall,
                        ),
                      ],
                    ],
                  ),
                ),
              ],
            ),
            const SizedBox(height: 10),
            _HttpCaptureTimingWaterfall(
              requestObservedAfterMilliseconds:
                  requestObservedAfterMilliseconds,
              requestCompletedAfterMilliseconds:
                  requestCompletedAfterMilliseconds,
              responseObservedAfterMilliseconds:
                  currentResponse?.observedAfterMilliseconds ?? 0,
              responseCompletedAfterMilliseconds:
                  responseCompletedAfterMilliseconds,
            ),
            _HttpCaptureDetailRow(
              label: l.httpCaptureRequestObservedAfter,
              value: '$requestObservedAfterMilliseconds ms',
            ),
            if (requestCompletedAfterMilliseconds > 0)
              _HttpCaptureDetailRow(
                label: l.httpCaptureRequestCompletedAfter,
                value: '$requestCompletedAfterMilliseconds ms',
              ),
            if (request.version.isNotEmpty)
              _HttpCaptureDetailRow(
                label: l.httpCaptureHttpVersion,
                value: request.version,
              ),
            if (request.headerNames.isNotEmpty)
              _HttpCaptureDetailRow(
                label: l.httpCaptureHeaderNames,
                value: request.headerNames.join(', '),
              ),
            if (request.headers.isNotEmpty)
              _HttpCaptureHeaderValues(
                title: l.httpCaptureRequestHeaders,
                headers: request.headers,
              ),
            _HttpCaptureDetailRow(
              label: l.httpCaptureHeadersComplete,
              value: completeness(request.headersComplete),
            ),
            if (request.targetTruncated)
              _HttpCaptureDetailRow(
                label: l.httpCaptureTargetTruncated,
                value: presence(true),
              ),
            if (request.hostTruncated)
              _HttpCaptureDetailRow(
                label: l.httpCaptureHostTruncated,
                value: presence(true),
              ),
            if (request.headerNamesTruncated)
              _HttpCaptureDetailRow(
                label: l.httpCaptureHeaderNamesTruncated,
                value: presence(true),
              ),
            if (request.headerValuesTruncated)
              _HttpCaptureDetailRow(
                label: l.httpCaptureHeaderValuesTruncated,
                value: presence(true),
              ),
            if (request.headers.isNotEmpty)
              _HttpCaptureCookiePreview(
                title: l.httpCaptureRequestCookies,
                headers: request.headers,
                request: true,
              ),
            if (requestBody != null)
              _HttpCaptureBodyPreview(
                title: l.httpCaptureRequestBody,
                body: requestBody!,
              ),
            if (currentResponse != null) ...[
              const Divider(),
              if (currentResponse.statusCode != 0)
                _HttpCaptureDetailRow(
                  label: l.httpCaptureResponseStatus,
                  value: '${currentResponse.statusCode}',
                ),
              if (currentResponse.version.isNotEmpty)
                _HttpCaptureDetailRow(
                  label: l.httpCaptureResponseHttpVersion,
                  value: currentResponse.version,
                ),
              if (currentResponse.informationalStatusCodes.isNotEmpty)
                _HttpCaptureDetailRow(
                  label: l.httpCaptureInformationalStatusCodes,
                  value: currentResponse.informationalStatusCodes.join(', '),
                ),
              if (currentResponse.headerNames.isNotEmpty)
                _HttpCaptureDetailRow(
                  label: l.httpCaptureResponseHeaderNames,
                  value: currentResponse.headerNames.join(', '),
                ),
              if (currentResponse.headers.isNotEmpty)
                _HttpCaptureHeaderValues(
                  title: l.httpCaptureResponseHeaders,
                  headers: currentResponse.headers,
                ),
              _HttpCaptureDetailRow(
                label: l.httpCaptureResponseObservedAfter,
                value: '${currentResponse.observedAfterMilliseconds} ms',
              ),
              if (responseCompletedAfterMilliseconds > 0)
                _HttpCaptureDetailRow(
                  label: l.httpCaptureResponseCompletedAfter,
                  value: '$responseCompletedAfterMilliseconds ms',
                ),
              _HttpCaptureDetailRow(
                label: l.httpCaptureResponseHeadersComplete,
                value: completeness(currentResponse.headersComplete),
              ),
              if (currentResponse.truncated)
                _HttpCaptureDetailRow(
                  label: l.httpCaptureResponseTruncated,
                  value: presence(true),
                ),
              if (currentResponse.headerNamesTruncated)
                _HttpCaptureDetailRow(
                  label: l.httpCaptureResponseHeaderNamesTruncated,
                  value: presence(true),
                ),
              if (currentResponse.headerValuesTruncated)
                _HttpCaptureDetailRow(
                  label: l.httpCaptureHeaderValuesTruncated,
                  value: presence(true),
                ),
              if (currentResponse.informationalStatusCodesTruncated)
                _HttpCaptureDetailRow(
                  label: l.httpCaptureInformationalStatusCodesTruncated,
                  value: presence(true),
                ),
              if (currentResponse.headers.isNotEmpty)
                _HttpCaptureCookiePreview(
                  title: l.httpCaptureResponseCookies,
                  headers: currentResponse.headers,
                  request: false,
                ),
              if (responseBody != null)
                _HttpCaptureBodyPreview(
                  title: l.httpCaptureResponseBody,
                  body: responseBody!,
                ),
            ],
          ],
        ),
      ),
    );
  }
}

class _HttpCaptureTimingWaterfall extends StatelessWidget {
  final int requestObservedAfterMilliseconds;
  final int requestCompletedAfterMilliseconds;
  final int responseObservedAfterMilliseconds;
  final int responseCompletedAfterMilliseconds;

  const _HttpCaptureTimingWaterfall({
    required this.requestObservedAfterMilliseconds,
    required this.requestCompletedAfterMilliseconds,
    required this.responseObservedAfterMilliseconds,
    required this.responseCompletedAfterMilliseconds,
  });

  @override
  Widget build(BuildContext context) {
    final l = context.appLocalizations;
    final send = requestCompletedAfterMilliseconds > 0
        ? requestCompletedAfterMilliseconds - requestObservedAfterMilliseconds
        : 0;
    final waitStart = requestCompletedAfterMilliseconds > 0
        ? requestCompletedAfterMilliseconds
        : requestObservedAfterMilliseconds;
    final wait = responseObservedAfterMilliseconds > waitStart
        ? responseObservedAfterMilliseconds - waitStart
        : 0;
    final receive =
        responseCompletedAfterMilliseconds > responseObservedAfterMilliseconds
        ? responseCompletedAfterMilliseconds - responseObservedAfterMilliseconds
        : 0;
    final total = requestObservedAfterMilliseconds + send + wait + receive;
    if (total <= 0) {
      return const SizedBox.shrink();
    }
    Widget segment(int value, Color color) => Expanded(
      flex: value.clamp(1, 0x7fffffff).toInt(),
      child: Container(height: 8, color: color),
    );
    final labels = <String>[
      if (send > 0) '${l.httpCaptureTimingSend} $send ms',
      if (wait > 0) '${l.httpCaptureTimingWait} $wait ms',
      if (receive > 0) '${l.httpCaptureTimingReceive} $receive ms',
    ];
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          ClipRRect(
            borderRadius: BorderRadius.circular(99),
            child: Row(
              children: [
                if (requestObservedAfterMilliseconds > 0)
                  segment(
                    requestObservedAfterMilliseconds,
                    context.colorScheme.surfaceContainerHighest,
                  ),
                if (send > 0) segment(send, context.colorScheme.primary),
                if (wait > 0) segment(wait, context.colorScheme.tertiary),
                if (receive > 0)
                  segment(receive, context.colorScheme.secondary),
              ],
            ),
          ),
          if (labels.isNotEmpty) ...[
            const SizedBox(height: 6),
            Text(
              labels.join(' · '),
              style: context.textTheme.labelSmall?.copyWith(
                color: context.colorScheme.onSurfaceVariant,
              ),
            ),
          ],
        ],
      ),
    );
  }
}

class _HttpCaptureHeaderValues extends StatelessWidget {
  final String title;
  final List<HttpHeaderObservation> headers;

  const _HttpCaptureHeaderValues({required this.title, required this.headers});

  @override
  Widget build(BuildContext context) {
    final l = context.appLocalizations;
    return ExpansionTile(
      tilePadding: EdgeInsets.zero,
      childrenPadding: const EdgeInsets.only(bottom: 8),
      title: Text(title),
      subtitle: Text(l.httpCaptureHeaderValueCount(headers.length)),
      children: [
        for (final header in headers)
          ListTile(
            dense: true,
            contentPadding: const EdgeInsets.symmetric(horizontal: 8),
            title: SelectableText(header.name),
            subtitle: SelectableText(
              header.redacted
                  ? l.httpCaptureRedacted
                  : header.value.isEmpty
                  ? l.httpCaptureEmptyValue
                  : header.value,
            ),
            trailing: header.truncated
                ? Tooltip(
                    message: l.httpCaptureTruncated,
                    child: const Icon(Icons.content_cut_outlined, size: 18),
                  )
                : null,
          ),
      ],
    );
  }
}

class _HttpCaptureCookiePreview extends StatelessWidget {
  final String title;
  final List<HttpHeaderObservation> headers;
  final bool request;

  const _HttpCaptureCookiePreview({
    required this.title,
    required this.headers,
    required this.request,
  });

  List<(String, String)> _cookies() {
    final result = <(String, String)>[];
    final target = request ? 'cookie' : 'set-cookie';
    for (final header in headers.where(
      (value) => value.name == target && !value.redacted,
    )) {
      final parts = request ? header.value.split(';') : <String>[header.value];
      for (final part in parts) {
        final separator = part.indexOf('=');
        if (separator <= 0) {
          continue;
        }
        result.add((
          part.substring(0, separator).trim(),
          part.substring(separator + 1).trim(),
        ));
      }
    }
    return result;
  }

  @override
  Widget build(BuildContext context) {
    final values = _cookies();
    if (values.isEmpty) {
      return const SizedBox.shrink();
    }
    return ExpansionTile(
      tilePadding: EdgeInsets.zero,
      title: Text(title),
      subtitle: Text('${values.length}'),
      children: [
        for (final value in values)
          _HttpCaptureDetailRow(label: value.$1, value: value.$2),
      ],
    );
  }
}

class _HttpCaptureBodyPreview extends StatelessWidget {
  final String title;
  final TlsInspectionRuntimeHttpBody body;

  const _HttpCaptureBodyPreview({required this.title, required this.body});

  @override
  Widget build(BuildContext context) {
    final l = context.appLocalizations;
    final bytes = body.decodedBytes;
    final formFields = body.formFields;
    return ExpansionTile(
      tilePadding: EdgeInsets.zero,
      childrenPadding: const EdgeInsets.only(bottom: 8),
      title: Text(title),
      subtitle: Text(
        [
          body.kind.toUpperCase(),
          if (body.contentType.isNotEmpty) body.contentType,
          '${body.capturedBytes}/${body.observedBytes} B',
          if (body.truncated) l.httpCaptureTruncated,
        ].join(' · '),
      ),
      children: [
        if (body.omittedReason.isNotEmpty)
          _HttpCaptureDetailRow(
            label: l.httpCaptureOmitted,
            value: body.omittedReason,
          )
        else if (body.kind == 'form' && formFields.isNotEmpty)
          for (final field in formFields.entries)
            _HttpCaptureDetailRow(label: field.key, value: field.value)
        else if (body.kind == 'image' && bytes != null)
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 8),
            child: ClipRRect(
              borderRadius: BorderRadius.circular(AppCorner.md),
              child: Image.memory(
                bytes,
                height: 220,
                width: double.infinity,
                fit: BoxFit.contain,
                errorBuilder: (context, error, stackTrace) => Padding(
                  padding: const EdgeInsets.all(16),
                  child: Text(l.httpCaptureImagePreviewFailed),
                ),
              ),
            ),
          )
        else if (body.prettyText.isNotEmpty)
          Container(
            width: double.infinity,
            constraints: const BoxConstraints(maxHeight: 360),
            margin: const EdgeInsets.symmetric(horizontal: 8),
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: context.colorScheme.surfaceContainerHighest,
              borderRadius: BorderRadius.circular(AppCorner.md),
            ),
            child: SingleChildScrollView(
              child: SelectableText(
                body.prettyText,
                style: context.textTheme.bodySmall?.copyWith(
                  fontFamily: 'JetBrainsMono',
                ),
              ),
            ),
          )
        else
          _HttpCaptureDetailRow(
            label: l.httpCaptureBodyEncoding,
            value: body.encoding.isEmpty
                ? l.httpCaptureNotPresent
                : body.encoding,
          ),
      ],
    );
  }
}

class _HttpCaptureMetric extends StatelessWidget {
  final HttpCaptureProtocol protocol;
  final int value;

  const _HttpCaptureMetric({required this.protocol, required this.value});

  @override
  Widget build(BuildContext context) {
    return Chip(
      avatar: Icon(protocol.icon, size: 18, color: protocol.color(context)),
      label: Text('${protocol.label(context)} · $value'),
    );
  }
}

class _HttpCaptureDetailHeader extends StatelessWidget {
  final HttpCaptureEntry entry;

  const _HttpCaptureDetailHeader({required this.entry});

  @override
  Widget build(BuildContext context) {
    final protocol = entry.protocol;
    return CommonCard(
      type: CommonCardType.filled,
      radius: AppCorner.md,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(protocol.icon, color: protocol.color(context)),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  SelectableText(
                    entry.origin.isEmpty ? entry.endpointHost : entry.origin,
                    style: context.textTheme.titleMedium?.toSoftBold,
                  ),
                  const SizedBox(height: 4),
                  Text(
                    '${protocol.label(context)} · ${entry.source.label(context)}',
                    style: context.textTheme.bodySmall?.copyWith(
                      color: context.colorScheme.onSurfaceVariant,
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _HttpCaptureDetailRow extends StatelessWidget {
  final String label;
  final String value;

  const _HttpCaptureDetailRow({required this.label, required this.value});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 7),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 128,
            child: Text(
              label,
              style: context.textTheme.labelMedium?.copyWith(
                color: context.colorScheme.onSurfaceVariant,
              ),
            ),
          ),
          const SizedBox(width: 12),
          Expanded(child: SelectableText(value)),
        ],
      ),
    );
  }
}
