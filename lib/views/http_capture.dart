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

class HttpCaptureView extends ConsumerStatefulWidget {
  const HttpCaptureView({super.key});

  @override
  ConsumerState<HttpCaptureView> createState() => _HttpCaptureViewState();
}

class _HttpCaptureViewState extends ConsumerState<HttpCaptureView> {
  String _query = '';
  HttpCaptureProtocol? _protocol;
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
      'remote-scheme' => l.httpCaptureEvidenceRemoteScheme,
      'known-http-port' => l.httpCaptureEvidenceKnownHttpPort,
      'known-tls-port' => l.httpCaptureEvidenceKnownTlsPort,
      'known-quic-port' => l.httpCaptureEvidenceKnownQuicPort,
      'host-observed' => l.httpCaptureEvidenceHostObserved,
      'transport-only' => l.httpCaptureEvidenceTransportOnly,
      _ => evidence,
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
          return terms.isEmpty || terms.every(entry.searchText.contains);
        })
        .toList(growable: false);
  }

  Future<void> _toggleCapture(bool enabled) async {
    final notifier = ref.read(httpCaptureProvider.notifier);
    if (enabled) {
      await notifier.stop();
    } else {
      await notifier.start();
    }
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
                        Expanded(child: Text(l.httpCaptureHarWarning)),
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 12),
                _HttpCaptureDetailRow(
                  label: l.httpCaptureEndpoint,
                  value: entry.origin,
                ),
                if (http != null) ...[
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
                if (response != null) ...[
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
                    protocol.label(context),
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
