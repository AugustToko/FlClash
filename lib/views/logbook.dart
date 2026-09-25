import 'dart:async';
import 'dart:convert';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/core/core.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/features/connection/quick_routing.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/providers.dart';
import 'package:fl_clash/state.dart';
import 'package:fl_clash/views/backup_and_restore.dart';
import 'package:fl_clash/views/config/scripts.dart';
import 'package:fl_clash/views/http_capture.dart';
import 'package:fl_clash/views/dns_diagnostics.dart';
import 'package:fl_clash/views/profiles/profiles.dart';
import 'package:fl_clash/views/proxies/providers.dart';
import 'package:fl_clash/views/resources.dart';
import 'package:fl_clash/widgets/widgets.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

extension on LogbookCategory {
  String label(BuildContext context) {
    final l = context.appLocalizations;
    return switch (this) {
      LogbookCategory.core => l.logbookCore,
      LogbookCategory.profile => l.logbookProfile,
      LogbookCategory.routing => l.logbookRouting,
      LogbookCategory.network => l.logbookNetwork,
      LogbookCategory.provider => l.logbookProvider,
      LogbookCategory.dns => l.logbookDns,
      LogbookCategory.script => l.logbookScript,
      LogbookCategory.system => l.logbookSystem,
    };
  }

  IconData get icon {
    return switch (this) {
      LogbookCategory.core => Icons.memory_outlined,
      LogbookCategory.profile => Icons.description_outlined,
      LogbookCategory.routing => Icons.alt_route,
      LogbookCategory.network => Icons.wifi_tethering_outlined,
      LogbookCategory.provider => Icons.cloud_sync_outlined,
      LogbookCategory.dns => Icons.dns_outlined,
      LogbookCategory.script => Icons.code_outlined,
      LogbookCategory.system => Icons.computer_outlined,
    };
  }
}

String _logbookEventTitle(BuildContext context, LogbookEvent event) {
  final l = context.appLocalizations;
  return switch (event.eventType) {
    'core.start.completed' => l.logbookCoreStarted,
    'core.start.superseded' => l.logbookCoreStartSuperseded,
    'core.start.failed' => l.logbookCoreStartFailed,
    'core.restart.completed' => l.logbookCoreRestarted,
    'core.restart.profile-apply-failed' => l.logbookCoreRestartWarning,
    'core.restart.failed' => l.logbookCoreRestartFailed,
    'core.crash.requested' => l.logbookCoreCrashRequested,
    'profile.apply.completed' => l.logbookProfileApplied,
    'profile.apply.failed' => l.logbookProfileApplyFailed,
    'profile.apply.exception' => l.logbookProfileApplyException,
    'network.connectivity.changed' => l.logbookConnectivityChanged,
    'routing.quick-route.verification' => switch (event.details['status']) {
      'verified' => l.logbookQuickRouteVerified,
      'approximate' => l.logbookQuickRouteApproximate,
      'mismatch' => l.logbookQuickRouteMismatch,
      'unavailable' => l.logbookQuickRouteUnavailable,
      _ => switch (event.severity) {
        LogbookSeverity.success => l.logbookQuickRouteVerified,
        LogbookSeverity.warning => l.logbookQuickRouteApproximate,
        LogbookSeverity.error => l.logbookQuickRouteMismatch,
        LogbookSeverity.info => event.title,
      },
    },
    'provider.external.update' => switch (event.details['status']) {
      'running' => l.logbookProviderUpdateRunning,
      'completed' => l.logbookProviderUpdated,
      'failed' => l.logbookProviderUpdateFailed,
      _ => event.title,
    },
    'provider.external.sideload' => switch (event.details['status']) {
      'running' => l.logbookProviderImportRunning,
      'completed' => l.logbookProviderImported,
      'failed' => l.logbookProviderImportFailed,
      _ => event.title,
    },
    'provider.geo.update' => switch (event.details['status']) {
      'running' => l.logbookGeoUpdateRunning,
      'completed' => l.logbookGeoUpdated,
      'skipped' => l.logbookGeoSkipped,
      'failed' => l.logbookGeoUpdateFailed,
      _ => event.title,
    },
    'system.backup' => switch (event.details['status']) {
      'running' => l.logbookBackupRunning,
      'completed' => l.logbookBackupCompleted,
      'cancelled' => l.logbookBackupCancelled,
      'failed' => l.logbookBackupFailed,
      _ => event.title,
    },
    'system.restore' => switch (event.details['status']) {
      'running' => l.logbookRestoreRunning,
      'completed' => l.logbookRestoreCompleted,
      'failed' => l.logbookRestoreFailed,
      _ => event.title,
    },
    'script.evaluate' => switch (event.details['status']) {
      'running' => l.logbookScriptEvaluateRunning,
      'completed' => l.logbookScriptEvaluated,
      'failed' => l.logbookScriptEvaluateFailed,
      _ => event.title,
    },
    'http.capture.session' => switch (event.details['status']) {
      'running' => l.logbookHttpCaptureRunning,
      'completed' => l.logbookHttpCaptureCompleted,
      'interrupted' => l.logbookHttpCaptureInterrupted,
      _ => event.title,
    },
    'dns.query' => switch (event.details['status']) {
      'running' => l.logbookDnsQueryRunning,
      'completed' => l.logbookDnsQueryCompleted,
      'failed' => l.logbookDnsQueryFailed,
      _ => event.title,
    },
    _ => event.title,
  };
}

String _logbookEventMessage(BuildContext context, LogbookEvent event) {
  if (event.eventType != 'http.capture.session') {
    return event.message;
  }
  final l = context.appLocalizations;
  return switch (event.details['status']) {
    'running' => l.httpCaptureObservationOnly,
    'completed' =>
      '${l.entriesCount((event.details['count'] as num?) ?? 0)} · ${event.details['durationMs'] ?? 0} ms',
    'interrupted' => l.logbookHttpCaptureInterrupted,
    _ => event.message,
  };
}

extension on LogbookSeverity {
  String label(BuildContext context) {
    final l = context.appLocalizations;
    return switch (this) {
      LogbookSeverity.info => l.logbookInfo,
      LogbookSeverity.success => l.logbookSuccess,
      LogbookSeverity.warning => l.logbookWarning,
      LogbookSeverity.error => l.logbookError,
    };
  }

  IconData get icon {
    return switch (this) {
      LogbookSeverity.info => Icons.info_outline,
      LogbookSeverity.success => Icons.check_circle_outline,
      LogbookSeverity.warning => Icons.warning_amber_outlined,
      LogbookSeverity.error => Icons.error_outline,
    };
  }

  Color color(BuildContext context) {
    final scheme = context.colorScheme;
    return switch (this) {
      LogbookSeverity.info => scheme.primary,
      LogbookSeverity.success => scheme.tertiary,
      LogbookSeverity.warning => scheme.secondary,
      LogbookSeverity.error => scheme.error,
    };
  }
}

class LogbookView extends ConsumerStatefulWidget {
  const LogbookView({super.key});

  @override
  ConsumerState<LogbookView> createState() => _LogbookViewState();
}

class _LogbookViewState extends ConsumerState<LogbookView> {
  String _query = '';
  LogbookCategory? _category;
  LogbookSeverity? _severity;
  bool _currentProfileOnly = true;

  @override
  void initState() {
    super.initState();
    unawaited(ref.read(logbookProvider.notifier).reload());
  }

  Future<void> _refresh() {
    return ref.read(logbookProvider.notifier).reload();
  }

  String _exportFileName(DateTime value) {
    final local = value.toLocal();
    String two(int number) => number.toString().padLeft(2, '0');
    return 'flclash-logbook-'
        '${local.year}${two(local.month)}${two(local.day)}-'
        '${two(local.hour)}${two(local.minute)}${two(local.second)}.json';
  }

  Future<void> _export(List<LogbookEvent> events) async {
    final l = context.appLocalizations;
    final result = await globalState.safeRun<bool>(() async {
      final exportedAt = DateTime.now();
      final content = encodeLogbookExport(
        events: events,
        exportedAt: exportedAt,
      );
      final value = await picker.saveFile(
        _exportFileName(exportedAt),
        Uint8List.fromList(utf8.encode(content)),
      );
      return value != null;
    }, title: l.exportLogs);
    if (result == true && mounted) {
      context.showNotifier(l.exportSuccess, level: MessageLevel.success);
    }
  }

  Future<void> _copyEvent(LogbookEvent event) async {
    await Clipboard.setData(
      ClipboardData(text: encodeLogbookExport(events: [event])),
    );
    if (mounted) {
      context.showNotifier(
        context.appLocalizations.copySuccess,
        level: MessageLevel.success,
      );
    }
  }

  Widget? _sourceView(LogbookEvent event) {
    if (event.eventType == 'routing.quick-route.verification' &&
        event.profileId != null) {
      return QuickRoutingDiagnosticsPage(profileId: event.profileId!);
    }
    if (event.eventType.startsWith('profile.')) {
      return const ProfilesView();
    }
    if (event.eventType.startsWith('provider.external.')) {
      return const ProvidersView();
    }
    if (event.eventType == 'provider.geo.update') {
      return const ResourcesView();
    }
    if (event.eventType.startsWith('script.')) {
      return const ScriptsView();
    }
    if (event.eventType == 'dns.query') {
      final name = event.details['name'];
      final queryType = event.details['queryType'];
      final resolver = event.details['requestedResolver'];
      return DnsDiagnosticsView(
        initialName: name is String ? name : '',
        initialQueryType: DnsDiagnosticQueryType.fromWireName(
          queryType is String ? queryType : '',
        ),
        initialResolver: DnsDiagnosticResolver.fromWireName(
          resolver is String ? resolver : '',
        ),
      );
    }
    if (event.eventType == 'system.backup' ||
        event.eventType == 'system.restore') {
      return const BackupAndRestore();
    }
    if (event.eventType == 'http.capture.session') {
      return const HttpCaptureView();
    }
    return null;
  }

  Future<void> _openSource(
    LogbookEvent event,
    BuildContext sheetContext,
  ) async {
    final source = _sourceView(event);
    if (source == null) {
      return;
    }
    Navigator.of(sheetContext).pop();
    await Future<void>.delayed(Duration.zero);
    if (!mounted) {
      return;
    }
    await BaseNavigator.push<void>(context, source);
  }

  Future<void> _removeEvent(
    LogbookEvent event,
    BuildContext sheetContext,
  ) async {
    final l = context.appLocalizations;
    final confirmed = await dialogs.showMessage(
      title: l.delete,
      message: TextSpan(text: l.deleteTip(l.logbook)),
    );
    if (confirmed != true) {
      return;
    }
    await ref.read(logbookProvider.notifier).remove(event.id);
    if (sheetContext.mounted) {
      Navigator.of(sheetContext).pop();
    }
  }

  Future<void> _clear() async {
    final l = context.appLocalizations;
    final confirmed = await dialogs.showMessage(
      title: l.clearLogbook,
      message: TextSpan(text: l.clearLogbookTip),
    );
    if (confirmed != true || !mounted) {
      return;
    }
    final profileId = ref.read(currentProfileIdProvider);
    await ref
        .read(logbookProvider.notifier)
        .clear(profileId: _currentProfileOnly ? profileId : null);
  }

  List<LogbookEvent> _filter(List<LogbookEvent> events, int? profileId) {
    final terms = _query
        .trim()
        .toLowerCase()
        .split(RegExp(r'\s+'))
        .where((term) => term.isNotEmpty)
        .toList(growable: false);
    return events
        .where((event) {
          if (_currentProfileOnly &&
              profileId != null &&
              event.profileId != null &&
              event.profileId != profileId) {
            return false;
          }
          if (_category != null && event.category != _category) {
            return false;
          }
          if (_severity != null && event.severity != _severity) {
            return false;
          }
          return terms.isEmpty || terms.every(event.searchText.contains);
        })
        .toList(growable: false);
  }

  String _dayLabel(DateTime value) {
    final local = value.toLocal();
    String two(int number) => number.toString().padLeft(2, '0');
    return '${local.year}-${two(local.month)}-${two(local.day)}';
  }

  void _showDetails(LogbookEvent event) {
    unawaited(
      showSheet<void>(
        context: context,
        props: const SheetProps(isScrollControlled: true),
        builder: (context) {
          final l = context.appLocalizations;
          final source = _sourceView(event);
          return AdaptiveSheetScaffold(
            title: l.details(l.logbook),
            actions: [
              if (source != null)
                IconButtonData(
                  icon: Icons.open_in_new,
                  tooltip: '${l.view} · ${l.source}',
                  onPressed: () => unawaited(_openSource(event, context)),
                ),
              IconButtonData(
                icon: Icons.copy_outlined,
                tooltip: l.copy,
                onPressed: () => unawaited(_copyEvent(event)),
              ),
              IconButtonData(
                icon: Icons.delete_outline,
                tooltip: l.delete,
                onPressed: () => unawaited(_removeEvent(event, context)),
              ),
            ],
            body: ListView(
              padding: const EdgeInsets.fromLTRB(16, 8, 16, 24),
              children: [
                _LogbookDetailsHeader(event: event),
                const SizedBox(height: 12),
                _LogbookDetailRow(
                  label: l.time,
                  value: event.updatedAt.toLocal().showFull,
                ),
                _LogbookDetailRow(
                  label: l.status,
                  value: event.severity.label(context),
                ),
                _LogbookDetailRow(
                  label: l.logbook,
                  value: event.category.label(context),
                ),
                _LogbookDetailRow(label: 'TYPE', value: event.eventType),
                if (event.profileId != null)
                  _LogbookDetailRow(
                    label: l.profile,
                    value: '${event.profileId}',
                  ),
                if (event.correlationId.isNotEmpty)
                  _LogbookDetailRow(
                    label: 'CORRELATION',
                    value: event.correlationId,
                  ),
                if (event.details.isNotEmpty) ...[
                  const SizedBox(height: 16),
                  Text(
                    l.details(l.content),
                    style: context.textTheme.titleMedium,
                  ),
                  const SizedBox(height: 8),
                  for (final detail in event.details.entries)
                    _LogbookDetailRow(
                      label: detail.key,
                      value: '${detail.value}',
                    ),
                ],
              ],
            ),
          );
        },
      ),
    );
  }

  Widget _buildSummary(List<LogbookEvent> events) {
    final l = context.appLocalizations;
    int count(LogbookSeverity severity) =>
        events.where((event) => event.severity == severity).length;
    return Card(
      margin: const EdgeInsets.fromLTRB(12, 12, 12, 4),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  Icons.auto_stories_outlined,
                  color: context.colorScheme.primary,
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(l.logbook, style: context.textTheme.titleMedium),
                      Text(
                        l.logbookLocalNotice,
                        style: context.textTheme.bodySmall?.copyWith(
                          color: context.colorScheme.onSurfaceVariant,
                        ),
                      ),
                    ],
                  ),
                ),
                Text(
                  '${events.length}',
                  style: context.textTheme.headlineSmall?.toSoftBold,
                ),
              ],
            ),
            const SizedBox(height: 14),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                _LogbookMetric(
                  icon: LogbookSeverity.error.icon,
                  label: l.logbookError,
                  value: count(LogbookSeverity.error),
                  color: LogbookSeverity.error.color(context),
                ),
                _LogbookMetric(
                  icon: LogbookSeverity.warning.icon,
                  label: l.logbookWarning,
                  value: count(LogbookSeverity.warning),
                  color: LogbookSeverity.warning.color(context),
                ),
                _LogbookMetric(
                  icon: LogbookSeverity.success.icon,
                  label: l.logbookSuccess,
                  value: count(LogbookSeverity.success),
                  color: LogbookSeverity.success.color(context),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildFilters(int? profileId) {
    final l = context.appLocalizations;
    return Padding(
      padding: const EdgeInsets.fromLTRB(12, 8, 12, 4),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: Row(
              children: [
                FilterChip(
                  selected: _category == null,
                  label: Text(l.logbookAll),
                  onSelected: (_) => setState(() => _category = null),
                ),
                const SizedBox(width: 8),
                for (final category in LogbookCategory.values) ...[
                  FilterChip(
                    avatar: Icon(category.icon, size: 18),
                    selected: _category == category,
                    label: Text(category.label(context)),
                    onSelected: (_) => setState(() => _category = category),
                  ),
                  const SizedBox(width: 8),
                ],
              ],
            ),
          ),
          const SizedBox(height: 8),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              FilterChip(
                selected: _severity == null,
                label: Text(l.logbookAll),
                onSelected: (_) => setState(() => _severity = null),
              ),
              for (final severity in LogbookSeverity.values)
                FilterChip(
                  avatar: Icon(
                    severity.icon,
                    size: 18,
                    color: severity.color(context),
                  ),
                  selected: _severity == severity,
                  label: Text(severity.label(context)),
                  onSelected: (_) => setState(() => _severity = severity),
                ),
              if (profileId != null)
                FilterChip(
                  avatar: const Icon(Icons.person_outline, size: 18),
                  selected: _currentProfileOnly,
                  label: Text(l.profile),
                  onSelected: (value) {
                    setState(() => _currentProfileOnly = value);
                  },
                ),
            ],
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final l = context.appLocalizations;
    final events = ref.watch(logbookProvider);
    final profileId = ref.watch(currentProfileIdProvider);
    final filtered = _filter(events, profileId);

    return CommonScaffold(
      title: l.logbook,
      searchState: AppBarSearchState(
        onSearch: (query) => setState(() => _query = query),
      ),
      actions: [
        IconButton(
          tooltip: l.exportLogs,
          onPressed: filtered.isEmpty
              ? null
              : () => unawaited(_export(filtered)),
          icon: const Icon(Icons.file_download_outlined),
        ),
        IconButton(
          tooltip: l.update,
          onPressed: () => unawaited(_refresh()),
          icon: const Icon(Icons.refresh),
        ),
        IconButton(
          tooltip: l.clearLogbook,
          onPressed: events.isEmpty ? null : () => unawaited(_clear()),
          icon: const Icon(Icons.delete_sweep_outlined),
        ),
      ],
      body: LayoutBuilder(
        builder: (context, constraints) {
          final contentWidth = constraints.maxWidth > 1040
              ? 1040.0
              : constraints.maxWidth;
          return Center(
            child: SizedBox(
              width: contentWidth,
              height: constraints.maxHeight,
              child: RefreshIndicator(
                onRefresh: _refresh,
                child: CustomScrollView(
                  slivers: [
                    SliverToBoxAdapter(child: _buildSummary(filtered)),
                    SliverToBoxAdapter(child: _buildFilters(profileId)),
                    if (filtered.isEmpty)
                      SliverFillRemaining(
                        hasScrollBody: false,
                        child: Center(
                          child: NullStatus(
                            illustration: NullStatusIllustration.logs,
                            label: l.logbookEmpty,
                          ),
                        ),
                      )
                    else
                      SliverPadding(
                        padding: EdgeInsets.fromLTRB(
                          12,
                          4,
                          12,
                          20 + BottomInsetScope.of(context),
                        ),
                        sliver: SliverList.builder(
                          itemCount: filtered.length,
                          itemBuilder: (context, index) {
                            final event = filtered[index];
                            final previous = index == 0
                                ? null
                                : filtered[index - 1];
                            final showDay =
                                previous == null ||
                                _dayLabel(previous.updatedAt) !=
                                    _dayLabel(event.updatedAt);
                            return Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                if (showDay)
                                  Padding(
                                    padding: const EdgeInsets.fromLTRB(
                                      8,
                                      14,
                                      8,
                                      6,
                                    ),
                                    child: Text(
                                      _dayLabel(event.updatedAt),
                                      style: context.textTheme.labelLarge
                                          ?.copyWith(
                                            color: context
                                                .colorScheme
                                                .onSurfaceVariant,
                                          ),
                                    ),
                                  ),
                                _LogbookTimelineItem(
                                  event: event,
                                  onTap: () => _showDetails(event),
                                  isLast: index == filtered.length - 1,
                                ),
                              ],
                            );
                          },
                        ),
                      ),
                  ],
                ),
              ),
            ),
          );
        },
      ),
    );
  }
}

class _LogbookMetric extends StatelessWidget {
  final IconData icon;
  final String label;
  final int value;
  final Color color;

  const _LogbookMetric({
    required this.icon,
    required this.label,
    required this.value,
    required this.color,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 7),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 17, color: color),
          const SizedBox(width: 6),
          Text('$label $value', style: context.textTheme.labelMedium),
        ],
      ),
    );
  }
}

class _LogbookTimelineItem extends StatelessWidget {
  final LogbookEvent event;
  final VoidCallback onTap;
  final bool isLast;

  const _LogbookTimelineItem({
    required this.event,
    required this.onTap,
    required this.isLast,
  });

  @override
  Widget build(BuildContext context) {
    final color = event.severity.color(context);
    return IntrinsicHeight(
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          SizedBox(
            width: 38,
            child: Column(
              children: [
                Container(
                  width: 28,
                  height: 28,
                  decoration: BoxDecoration(
                    color: color.withValues(alpha: 0.14),
                    shape: BoxShape.circle,
                    border: Border.all(color: color.withValues(alpha: 0.45)),
                  ),
                  child: Icon(event.category.icon, size: 16, color: color),
                ),
                if (!isLast)
                  Expanded(
                    child: Container(
                      width: 2,
                      color: context.colorScheme.outlineVariant,
                    ),
                  ),
              ],
            ),
          ),
          Expanded(
            child: Card(
              margin: const EdgeInsets.only(left: 4, bottom: 10),
              clipBehavior: Clip.antiAlias,
              child: InkWell(
                onTap: onTap,
                child: Padding(
                  padding: const EdgeInsets.all(14),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Expanded(
                            child: Text(
                              _logbookEventTitle(context, event),
                              style: context.textTheme.titleSmall?.toSoftBold,
                            ),
                          ),
                          Text(
                            event.updatedAt.toLocal().showTime,
                            style: context.textTheme.bodySmall?.copyWith(
                              color: context.colorScheme.onSurfaceVariant,
                            ),
                          ),
                        ],
                      ),
                      if (_logbookEventMessage(context, event).isNotEmpty) ...[
                        const SizedBox(height: 6),
                        Text(
                          _logbookEventMessage(context, event),
                          maxLines: 3,
                          overflow: TextOverflow.ellipsis,
                          style: context.textTheme.bodyMedium,
                        ),
                      ],
                      const SizedBox(height: 10),
                      Wrap(
                        spacing: 6,
                        runSpacing: 6,
                        children: [
                          CommonChip(label: event.category.label(context)),
                          CommonChip(label: event.severity.label(context)),
                          if (event.profileId != null)
                            CommonChip(label: 'P${event.profileId}'),
                        ],
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _LogbookDetailsHeader extends StatelessWidget {
  final LogbookEvent event;

  const _LogbookDetailsHeader({required this.event});

  @override
  Widget build(BuildContext context) {
    final color = event.severity.color(context);
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Container(
              width: 42,
              height: 42,
              decoration: BoxDecoration(
                color: color.withValues(alpha: 0.12),
                shape: BoxShape.circle,
              ),
              child: Icon(event.category.icon, color: color),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  SelectableText(
                    _logbookEventTitle(context, event),
                    style: context.textTheme.titleMedium?.toSoftBold,
                  ),
                  if (event.message.isNotEmpty) ...[
                    const SizedBox(height: 6),
                    SelectableText(event.message),
                  ],
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _LogbookDetailRow extends StatelessWidget {
  final String label;
  final String value;

  const _LogbookDetailRow({required this.label, required this.value});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 7),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 112,
            child: Text(
              label,
              style: context.textTheme.labelMedium?.copyWith(
                color: context.colorScheme.onSurfaceVariant,
              ),
            ),
          ),
          Expanded(child: SelectableText(value)),
        ],
      ),
    );
  }
}
