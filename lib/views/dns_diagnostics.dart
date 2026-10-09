import 'dart:async';
import 'dart:convert';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/core/core.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/providers.dart';
import 'package:fl_clash/widgets/widgets.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

typedef DnsDiagnosticQueryReader =
    Future<CoreDnsQueryResult> Function({
      required String name,
      required DnsDiagnosticQueryType queryType,
      required DnsDiagnosticResolver resolver,
      required Duration timeout,
    });

class DnsDiagnosticsView extends ConsumerStatefulWidget {
  final String initialName;
  final DnsDiagnosticQueryType initialQueryType;
  final DnsDiagnosticResolver initialResolver;
  final DnsDiagnosticQueryReader? queryReader;

  const DnsDiagnosticsView({
    super.key,
    this.initialName = '',
    this.initialQueryType = DnsDiagnosticQueryType.a,
    this.initialResolver = DnsDiagnosticResolver.defaultResolver,
    @visibleForTesting this.queryReader,
  });

  @override
  ConsumerState<DnsDiagnosticsView> createState() => _DnsDiagnosticsViewState();
}

class _DnsDiagnosticsViewState extends ConsumerState<DnsDiagnosticsView> {
  late final TextEditingController _nameController;
  late DnsDiagnosticQueryType _queryType;
  late DnsDiagnosticResolver _resolver;
  CoreDnsQueryResult? _result;
  Object? _error;
  bool _loading = false;

  @override
  void initState() {
    super.initState();
    _nameController = TextEditingController(text: widget.initialName);
    _queryType = widget.initialQueryType;
    _resolver = widget.initialResolver;
  }

  @override
  void dispose() {
    _nameController.dispose();
    super.dispose();
  }

  String _resolverLabel(BuildContext context, DnsDiagnosticResolver resolver) {
    final l = context.appLocalizations;
    return switch (resolver) {
      DnsDiagnosticResolver.defaultResolver => l.dnsResolverDefault,
      DnsDiagnosticResolver.system => l.dnsResolverSystem,
      DnsDiagnosticResolver.proxy => l.dnsResolverProxy,
      DnsDiagnosticResolver.direct => l.dnsResolverDirect,
    };
  }

  String _warningLabel(BuildContext context, String warning) {
    final l = context.appLocalizations;
    return switch (warning) {
      'default-resolver-unavailable' => l.dnsWarningDefaultResolverUnavailable,
      'no-answer-records' => l.dnsWarningNoAnswer,
      'truncated-response' => l.dnsWarningTruncated,
      _ => warning,
    };
  }

  String _errorText(Object error) {
    if (error is CoreMethodException) {
      return error.message;
    }
    return compactError(error);
  }

  Future<CoreDnsQueryResult> _readQuery(String name) {
    final reader = widget.queryReader;
    if (reader != null) {
      return reader(
        name: name,
        queryType: _queryType,
        resolver: _resolver,
        timeout: const Duration(seconds: 5),
      );
    }
    return ref
        .read(coreHandlerProvider)
        .queryDns(
          name: name,
          queryType: _queryType,
          resolver: _resolver,
          timeout: const Duration(seconds: 5),
        );
  }

  void _recordQuery({
    required String name,
    required String correlationId,
    required String status,
    required int durationMs,
    CoreDnsQueryResult? result,
    Object? error,
  }) {
    final severity = switch (status) {
      'completed' =>
        result?.complete == true &&
                result?.status == 'NOERROR' &&
                result?.warnings.isEmpty == true
            ? LogbookSeverity.success
            : LogbookSeverity.warning,
      'failed' => LogbookSeverity.error,
      _ => LogbookSeverity.info,
    };
    String? failureKind;
    if (error is CoreMethodException) {
      final details = error.details;
      if (details is Map && details['failureKind'] is String) {
        failureKind = details['failureKind'] as String;
      } else {
        failureKind = error.code;
      }
    } else if (error != null) {
      failureKind = error.runtimeType.toString();
    }
    unawaited(
      ref
          .read(logbookProvider.notifier)
          .record(
            profileId: ref.read(currentProfileIdProvider),
            category: LogbookCategory.dns,
            severity: severity,
            eventType: 'dns.query',
            title: 'dns.query',
            message: '$name · ${_queryType.wireName} · $durationMs ms',
            correlationId: correlationId,
            details: {
              'status': status,
              'name': name,
              'queryType': _queryType.wireName,
              'requestedResolver': _resolver.wireName,
              'resolver': result?.resolver.wireName ?? _resolver.wireName,
              'durationMs': durationMs,
              if (result != null) ...{
                'rcode': result.rcode,
                'responseStatus': result.status,
                'answerCount': result.answers.length,
                'authorityCount': result.authority.length,
                'additionalCount': result.additional.length,
                'complete': result.complete,
                'warningCount': result.warnings.length,
              },
              'failureKind': ?failureKind,
            },
          ),
    );
  }

  Future<void> _runQuery() async {
    final name = _nameController.text.trim();
    if (name.isEmpty || _loading) {
      return;
    }
    FocusScope.of(context).unfocus();
    final startedAt = DateTime.now();
    final correlationId = 'dns-query:${startedAt.microsecondsSinceEpoch}';
    setState(() {
      _loading = true;
      _error = null;
    });
    _recordQuery(
      name: name,
      correlationId: correlationId,
      status: 'running',
      durationMs: 0,
    );
    try {
      final result = await _readQuery(name);
      if (!mounted) {
        return;
      }
      setState(() {
        _result = result;
        _error = null;
      });
      _recordQuery(
        name: result.name,
        correlationId: correlationId,
        status: 'completed',
        durationMs: result.durationMs,
        result: result,
      );
    } catch (error, stackTrace) {
      commonPrint.log(
        'DNS diagnostic query failed: ${compactError(error)}, $stackTrace',
        logLevel: coreFailureLogLevel(error),
      );
      if (!mounted) {
        return;
      }
      final durationMs = DateTime.now().difference(startedAt).inMilliseconds;
      setState(() {
        _result = null;
        _error = error;
      });
      _recordQuery(
        name: name,
        correlationId: correlationId,
        status: 'failed',
        durationMs: durationMs,
        error: error,
      );
    } finally {
      if (mounted) {
        setState(() => _loading = false);
      }
    }
  }

  Future<void> _copyResult() async {
    final result = _result;
    if (result == null) {
      return;
    }
    final content = const JsonEncoder.withIndent('  ').convert(result.toJson());
    await Clipboard.setData(ClipboardData(text: content));
    if (mounted) {
      context.showNotifier(
        context.appLocalizations.copySuccess,
        level: MessageLevel.success,
      );
    }
  }

  Widget _buildQueryCard(BuildContext context) {
    final l = context.appLocalizations;
    return CommonCard(
      type: CommonCardType.filled,
      radius: AppCorner.lg,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(l.dnsDiagnosticsDesc, style: context.textTheme.bodyMedium),
            const SizedBox(height: 16),
            TextField(
              key: const ValueKey('dns-diagnostics-name'),
              controller: _nameController,
              textInputAction: TextInputAction.search,
              autocorrect: false,
              enableSuggestions: false,
              decoration: InputDecoration(
                labelText: l.dnsQueryName,
                prefixIcon: const Icon(Icons.language_outlined),
                border: const OutlineInputBorder(),
              ),
              onSubmitted: (_) => unawaited(_runQuery()),
            ),
            const SizedBox(height: 16),
            LayoutBuilder(
              builder: (context, constraints) {
                final compact = constraints.maxWidth < 620;
                final typeMenu = DropdownMenu<DnsDiagnosticQueryType>(
                  key: const ValueKey('dns-diagnostics-type'),
                  initialSelection: _queryType,
                  expandedInsets: EdgeInsets.zero,
                  label: Text(l.dnsRecordType),
                  dropdownMenuEntries: [
                    for (final type in DnsDiagnosticQueryType.values)
                      DropdownMenuEntry(value: type, label: type.wireName),
                  ],
                  onSelected: (value) {
                    if (value != null) {
                      setState(() => _queryType = value);
                    }
                  },
                );
                final resolverMenu = DropdownMenu<DnsDiagnosticResolver>(
                  key: const ValueKey('dns-diagnostics-resolver'),
                  initialSelection: _resolver,
                  expandedInsets: EdgeInsets.zero,
                  label: Text(l.dnsResolver),
                  dropdownMenuEntries: [
                    for (final resolver in DnsDiagnosticResolver.values)
                      DropdownMenuEntry(
                        value: resolver,
                        label: _resolverLabel(context, resolver),
                      ),
                  ],
                  onSelected: (value) {
                    if (value != null) {
                      setState(() => _resolver = value);
                    }
                  },
                );
                if (compact) {
                  return Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      typeMenu,
                      const SizedBox(height: 12),
                      resolverMenu,
                    ],
                  );
                }
                return Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Expanded(child: typeMenu),
                    const SizedBox(width: 12),
                    Expanded(child: resolverMenu),
                  ],
                );
              },
            ),
            const SizedBox(height: 16),
            Align(
              alignment: Alignment.centerRight,
              child: FilledButton.icon(
                key: const ValueKey('dns-diagnostics-run'),
                onPressed: _loading ? null : () => unawaited(_runQuery()),
                icon: _loading
                    ? const SizedBox.square(
                        dimension: 18,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Icon(Icons.travel_explore_outlined),
                label: Text(l.dnsRunQuery),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildSummary(BuildContext context, CoreDnsQueryResult result) {
    final l = context.appLocalizations;
    final flags = <String>[
      if (result.authoritative) 'AA',
      if (result.truncated) 'TC',
      if (result.recursionAvailable) 'RA',
      if (result.authenticatedData) 'AD',
      if (result.checkingDisabled) 'CD',
    ];
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
                Expanded(
                  child: Text(
                    l.dnsQueryResult,
                    style: context.textTheme.titleMedium?.toSoftBold,
                  ),
                ),
                IconButton(
                  tooltip: l.copy,
                  onPressed: () => unawaited(_copyResult()),
                  icon: const Icon(Icons.copy_outlined),
                ),
              ],
            ),
            SelectableText(
              '${result.queryType.wireName} · ${result.questionName}',
              style: context.textTheme.bodyLarge?.toSoftBold,
            ),
            const SizedBox(height: 10),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                Chip(
                  avatar: Icon(
                    result.status == 'NOERROR'
                        ? Icons.check_circle_outline
                        : Icons.error_outline,
                    size: 18,
                  ),
                  label: Text('${result.status} (${result.rcode})'),
                ),
                Chip(
                  avatar: const Icon(Icons.dns_outlined, size: 18),
                  label: Text(_resolverLabel(context, result.resolver)),
                ),
                Chip(
                  avatar: const Icon(Icons.timer_outlined, size: 18),
                  label: Text('${result.durationMs} ms'),
                ),
                Chip(
                  avatar: const Icon(Icons.list_alt_outlined, size: 18),
                  label: Text('${result.recordCount}'),
                ),
                if (flags.isNotEmpty)
                  Chip(
                    avatar: const Icon(Icons.flag_outlined, size: 18),
                    label: Text('${l.dnsResponseFlags}: ${flags.join(' ')}'),
                  ),
              ],
            ),
            if (result.requestedResolver != result.resolver) ...[
              const SizedBox(height: 10),
              Text(
                '${l.dnsResolver}: '
                '${_resolverLabel(context, result.requestedResolver)} → '
                '${_resolverLabel(context, result.resolver)}',
                style: context.textTheme.bodySmall,
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildWarnings(BuildContext context, CoreDnsQueryResult result) {
    if (result.warnings.isEmpty) {
      return const SizedBox.shrink();
    }
    return CommonCard(
      type: CommonCardType.filled,
      radius: AppCorner.lg,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            for (final warning in result.warnings)
              Padding(
                padding: const EdgeInsets.symmetric(vertical: 3),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Icon(
                      Icons.warning_amber_rounded,
                      size: 20,
                      color: context.colorScheme.tertiary,
                    ),
                    const SizedBox(width: 8),
                    Expanded(child: Text(_warningLabel(context, warning))),
                  ],
                ),
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildRecordSection(
    BuildContext context,
    String title,
    List<CoreDnsRecord> records,
  ) {
    if (records.isEmpty) {
      return const SizedBox.shrink();
    }
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(4, 8, 4, 8),
          child: Text(title, style: context.textTheme.titleSmall?.toSoftBold),
        ),
        CommonCard(
          type: CommonCardType.filled,
          radius: AppCorner.lg,
          child: Column(
            children: [
              for (var index = 0; index < records.length; index++) ...[
                ListTile(
                  leading: CircleAvatar(
                    radius: 20,
                    child: Text(
                      records[index].type,
                      style: context.textTheme.labelSmall,
                    ),
                  ),
                  title: SelectableText(records[index].name),
                  subtitle: SelectableText(records[index].data),
                  trailing: Text('TTL ${records[index].ttl}'),
                  contentPadding: const EdgeInsets.symmetric(
                    horizontal: 16,
                    vertical: 4,
                  ),
                ),
                if (index != records.length - 1) const Divider(height: 0),
              ],
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildError(BuildContext context, Object error) {
    final l = context.appLocalizations;
    return CommonCard(
      type: CommonCardType.filled,
      radius: AppCorner.lg,
      isError: true,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(Icons.error_outline, color: context.colorScheme.error),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    l.dnsQueryFailed,
                    style: context.textTheme.titleSmall?.toSoftBold,
                  ),
                  const SizedBox(height: 6),
                  SelectableText(_errorText(error)),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildResult(BuildContext context) {
    final error = _error;
    if (error != null) {
      return _buildError(context, error);
    }
    final result = _result;
    if (result == null) {
      return SizedBox(
        height: 300,
        child: NullStatus(
          label: context.appLocalizations.dnsDiagnostics,
          description: context.appLocalizations.dnsDiagnosticsDesc,
          illustration: NullStatusIllustration.data,
        ),
      );
    }
    final l = context.appLocalizations;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        _buildSummary(context, result),
        if (result.warnings.isNotEmpty) ...[
          const SizedBox(height: 12),
          _buildWarnings(context, result),
        ],
        if (!result.hasRecords) ...[
          const SizedBox(height: 16),
          Center(child: Text(l.dnsNoRecords)),
        ],
        _buildRecordSection(context, l.dnsAnswerSection, result.answers),
        _buildRecordSection(context, l.dnsAuthoritySection, result.authority),
        _buildRecordSection(context, l.dnsAdditionalSection, result.additional),
      ],
    );
  }

  @override
  Widget build(BuildContext context) {
    return CommonScaffold(
      title: context.appLocalizations.dnsDiagnostics,
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
                  16,
                  16,
                  16,
                  24 + BottomInsetScope.of(context),
                ),
                children: [
                  _buildQueryCard(context),
                  const SizedBox(height: 16),
                  _buildResult(context),
                ],
              ),
            ),
          );
        },
      ),
    );
  }
}
