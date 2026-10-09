import json
import re
from pathlib import Path

from http_inspection_ui_models import ROOT


WIDGET_SOURCE = r'''import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../generated/l10n.dart';
import '../models/models.dart';
import '../providers/http_capture.dart';

class HttpCapturePolicyAction extends ConsumerWidget {
  const HttpCapturePolicyAction({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final state = ref.watch(httpCaptureProvider);
    final locked = state.capturing ||
        state.operation != HttpCaptureOperation.idle;
    return IconButton(
      tooltip: S.of(context).httpCapturePrivacyTitle,
      onPressed: locked
          ? null
          : () async {
              final policy = await showHttpCapturePolicyDialog(
                context,
                state.capturePolicy,
              );
              if (policy != null && context.mounted) {
                ref
                    .read(httpCaptureProvider.notifier)
                    .updateCapturePolicy(policy);
              }
            },
      icon: Icon(
        state.capturePolicy.isMetadataOnly
            ? Icons.privacy_tip_outlined
            : Icons.privacy_tip,
      ),
    );
  }
}

Future<TlsInspectionCapturePolicy?> showHttpCapturePolicyDialog(
  BuildContext context,
  TlsInspectionCapturePolicy initial,
) {
  return showDialog<TlsInspectionCapturePolicy>(
    context: context,
    barrierDismissible: false,
    builder: (context) => _HttpCapturePolicyDialog(initial: initial),
  );
}

class _HttpCapturePolicyDialog extends StatefulWidget {
  const _HttpCapturePolicyDialog({required this.initial});

  final TlsInspectionCapturePolicy initial;

  @override
  State<_HttpCapturePolicyDialog> createState() =>
      _HttpCapturePolicyDialogState();
}

class _HttpCapturePolicyDialogState
    extends State<_HttpCapturePolicyDialog> {
  late bool _headerValues;
  late bool _sensitiveHeaderValues;
  late TlsInspectionCaptureBodyMode _bodyMode;
  late int _maxBodyBytes;
  late final TextEditingController _redactedHeaderNamesController;

  @override
  void initState() {
    super.initState();
    final policy = widget.initial.normalized();
    _headerValues = policy.headerValues;
    _sensitiveHeaderValues = policy.sensitiveHeaderValues;
    _bodyMode = policy.bodyMode;
    _maxBodyBytes = policy.maxBodyBytes <= 0
        ? defaultInspectionBodyBytes
        : policy.maxBodyBytes;
    _redactedHeaderNamesController = TextEditingController(
      text: policy.redactedHeaderNames.join(', '),
    );
  }

  @override
  void dispose() {
    _redactedHeaderNamesController.dispose();
    super.dispose();
  }

  TlsInspectionCapturePolicy _policy() {
    final names = _redactedHeaderNamesController.text
        .split(RegExp(r'[,\n]'))
        .map((value) => value.trim())
        .where((value) => value.isNotEmpty)
        .toList(growable: false);
    return TlsInspectionCapturePolicy(
      headerValues: _headerValues,
      sensitiveHeaderValues:
          _headerValues && _sensitiveHeaderValues,
      redactedHeaderNames: names,
      bodyMode: _bodyMode,
      maxBodyBytes: _bodyMode == TlsInspectionCaptureBodyMode.none
          ? 0
          : _maxBodyBytes,
    ).normalized();
  }

  @override
  Widget build(BuildContext context) {
    final l10n = S.of(context);
    final material = MaterialLocalizations.of(context);
    return AlertDialog(
      title: Text(l10n.httpCapturePrivacyTitle),
      content: SizedBox(
        width: 560,
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Text(l10n.httpCapturePrivacyDescription),
              const SizedBox(height: 12),
              SwitchListTile.adaptive(
                contentPadding: EdgeInsets.zero,
                title: Text(l10n.httpCaptureHeaderValues),
                subtitle: Text(l10n.httpCaptureHeaderValuesDescription),
                value: _headerValues,
                onChanged: (value) {
                  setState(() {
                    _headerValues = value;
                    if (!value) {
                      _sensitiveHeaderValues = false;
                    }
                  });
                },
              ),
              SwitchListTile.adaptive(
                contentPadding: EdgeInsets.zero,
                title: Text(l10n.httpCaptureSensitiveHeaders),
                subtitle: Text(
                  l10n.httpCaptureSensitiveHeadersDescription,
                ),
                value: _sensitiveHeaderValues,
                onChanged: _headerValues
                    ? (value) => setState(
                          () => _sensitiveHeaderValues = value,
                        )
                    : null,
              ),
              if (_sensitiveHeaderValues)
                Padding(
                  padding: const EdgeInsets.only(bottom: 12),
                  child: MaterialBanner(
                    padding: const EdgeInsets.all(12),
                    leading: const Icon(Icons.warning_amber_rounded),
                    content: Text(l10n.httpCaptureSensitiveWarning),
                    actions: const <Widget>[],
                  ),
                ),
              TextField(
                controller: _redactedHeaderNamesController,
                enabled: _headerValues,
                decoration: InputDecoration(
                  labelText: l10n.httpCaptureRedactedHeaders,
                  helperText: l10n.httpCaptureRedactedHeadersHint,
                  border: const OutlineInputBorder(),
                ),
              ),
              const SizedBox(height: 16),
              DropdownButtonFormField<TlsInspectionCaptureBodyMode>(
                initialValue: _bodyMode,
                decoration: InputDecoration(
                  labelText: l10n.httpCaptureBodyMode,
                  border: const OutlineInputBorder(),
                ),
                items: [
                  DropdownMenuItem(
                    value: TlsInspectionCaptureBodyMode.none,
                    child: Text(l10n.httpCaptureBodyNone),
                  ),
                  DropdownMenuItem(
                    value: TlsInspectionCaptureBodyMode.text,
                    child: Text(l10n.httpCaptureBodyText),
                  ),
                  DropdownMenuItem(
                    value: TlsInspectionCaptureBodyMode.all,
                    child: Text(l10n.httpCaptureBodyAll),
                  ),
                ],
                onChanged: (value) {
                  if (value != null) {
                    setState(() => _bodyMode = value);
                  }
                },
              ),
              if (_bodyMode != TlsInspectionCaptureBodyMode.none) ...[
                const SizedBox(height: 16),
                DropdownButtonFormField<int>(
                  initialValue: _maxBodyBytes,
                  decoration: InputDecoration(
                    labelText: l10n.httpCaptureBodyLimit,
                    border: const OutlineInputBorder(),
                  ),
                  items: const [
                    DropdownMenuItem(value: 4096, child: Text('4 KiB')),
                    DropdownMenuItem(value: 16384, child: Text('16 KiB')),
                    DropdownMenuItem(value: 32768, child: Text('32 KiB')),
                    DropdownMenuItem(value: 65536, child: Text('64 KiB')),
                  ],
                  onChanged: (value) {
                    if (value != null) {
                      setState(() => _maxBodyBytes = value);
                    }
                  },
                ),
              ],
            ],
          ),
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: Text(material.cancelButtonLabel),
        ),
        FilledButton(
          onPressed: () => Navigator.of(context).pop(_policy()),
          child: Text(material.okButtonLabel),
        ),
      ],
    );
  }
}

class HttpInspectionDetailsSection extends StatelessWidget {
  const HttpInspectionDetailsSection({
    super.key,
    required this.record,
  });

  final HttpCaptureRecord record;

  @override
  Widget build(BuildContext context) {
    final observation = record.entry.tlsObservation;
    if (observation == null) {
      return const SizedBox.shrink();
    }
    final hasHttp1Values = observation.httpTransactions.any(
      (value) =>
          value.request.headers.isNotEmpty ||
          value.response?.headers.isNotEmpty == true ||
          value.requestBody != null ||
          value.responseBody != null,
    );
    final sections = <Widget>[
      _CapturePolicySummary(policy: observation.capturePolicy),
      if (_hasTiming(observation)) _TimingWaterfall(observation: observation),
      if (observation.http2Streams.isNotEmpty)
        _Http2StreamSection(observation: observation),
      if (hasHttp1Values)
        _Http1CapturedValuesSection(observation: observation),
    ];
    if (sections.isEmpty) {
      return const SizedBox.shrink();
    }
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const SizedBox(height: 12),
        ...sections.map(
          (value) => Padding(
            padding: const EdgeInsets.only(bottom: 12),
            child: value,
          ),
        ),
      ],
    );
  }

  static bool _hasTiming(TlsInspectionRuntimeObservation value) {
    return value.upstreamDialCompletedAfterMilliseconds > 0 ||
        value.upstreamTlsCompletedAfterMilliseconds > 0 ||
        value.downstreamTlsCompletedAfterMilliseconds > 0 ||
        value.httpTransactions.isNotEmpty ||
        value.http2Streams.isNotEmpty;
  }
}

class _CapturePolicySummary extends StatelessWidget {
  const _CapturePolicySummary({required this.policy});

  final TlsInspectionCapturePolicy policy;

  @override
  Widget build(BuildContext context) {
    final l10n = S.of(context);
    final chips = <Widget>[
      Chip(
        avatar: const Icon(Icons.http, size: 16),
        label: Text(
          policy.headerValues
              ? l10n.httpCaptureHeaderValues
              : l10n.httpCapturePolicyMetadataOnly,
        ),
      ),
      if (policy.capturesSensitiveValues)
        Chip(
          avatar: const Icon(Icons.warning_amber_rounded, size: 16),
          label: Text(l10n.httpCaptureSensitiveHeaders),
        ),
      if (policy.capturesBodies)
        Chip(
          avatar: const Icon(Icons.data_object, size: 16),
          label: Text(
            '${_bodyModeLabel(l10n, policy.bodyMode)} · '
            '${policy.maxBodyBytes ~/ 1024} KiB',
          ),
        ),
    ];
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              l10n.httpCapturePrivacyTitle,
              style: Theme.of(context).textTheme.titleSmall,
            ),
            const SizedBox(height: 8),
            Wrap(spacing: 8, runSpacing: 8, children: chips),
          ],
        ),
      ),
    );
  }

  String _bodyModeLabel(
    S l10n,
    TlsInspectionCaptureBodyMode value,
  ) {
    return switch (value) {
      TlsInspectionCaptureBodyMode.none => l10n.httpCaptureBodyNone,
      TlsInspectionCaptureBodyMode.text => l10n.httpCaptureBodyText,
      TlsInspectionCaptureBodyMode.all => l10n.httpCaptureBodyAll,
    };
  }
}

class _TimingWaterfall extends StatelessWidget {
  const _TimingWaterfall({required this.observation});

  final TlsInspectionRuntimeObservation observation;

  @override
  Widget build(BuildContext context) {
    final l10n = S.of(context);
    final firstRequest = observation.httpTransactions.isNotEmpty
        ? observation.httpTransactions.first.requestObservedAfterMilliseconds
        : observation.http2Streams.isNotEmpty
            ? observation.http2Streams.first
                .requestObservedAfterMilliseconds
            : 0;
    final firstResponse = observation.httpTransactions.isNotEmpty
        ? observation.httpTransactions.first.response
                ?.observedAfterMilliseconds ??
            0
        : observation.http2Streams.isNotEmpty
            ? observation.http2Streams.first.response
                    ?.observedAfterMilliseconds ??
                0
            : 0;
    final completed = observation.httpTransactions.isNotEmpty
        ? observation.httpTransactions.first
            .responseCompletedAfterMilliseconds
        : observation.http2Streams.isNotEmpty
            ? observation.http2Streams.first
                .responseCompletedAfterMilliseconds
            : 0;
    final phases = <_TimingPhase>[
      if (observation.upstreamDialCompletedAfterMilliseconds > 0)
        _TimingPhase(
          l10n.httpCaptureUpstreamConnect,
          0,
          observation.upstreamDialCompletedAfterMilliseconds,
        ),
      if (observation.upstreamTlsCompletedAfterMilliseconds > 0)
        _TimingPhase(
          l10n.httpCaptureUpstreamTls,
          observation.upstreamDialCompletedAfterMilliseconds,
          observation.upstreamTlsCompletedAfterMilliseconds,
        ),
      if (observation.downstreamTlsCompletedAfterMilliseconds > 0)
        _TimingPhase(
          l10n.httpCaptureDownstreamTls,
          observation.upstreamTlsCompletedAfterMilliseconds,
          observation.downstreamTlsCompletedAfterMilliseconds,
        ),
      if (firstRequest > 0)
        _TimingPhase(
          l10n.httpCaptureRequestStarted,
          observation.downstreamTlsCompletedAfterMilliseconds,
          firstRequest,
        ),
      if (firstResponse > 0)
        _TimingPhase(
          l10n.httpCaptureTtfb,
          firstRequest,
          firstResponse,
        ),
      if (completed > 0)
        _TimingPhase(
          l10n.httpCaptureDownload,
          firstResponse,
          completed,
        ),
    ].where((value) => value.end >= value.start).toList(growable: false);
    if (phases.isEmpty) {
      return const SizedBox.shrink();
    }
    final maximum = phases.fold<int>(
      1,
      (value, phase) => math.max(value, phase.end),
    );
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              l10n.httpCaptureTiming,
              style: Theme.of(context).textTheme.titleSmall,
            ),
            const SizedBox(height: 8),
            for (final phase in phases)
              Padding(
                padding: const EdgeInsets.symmetric(vertical: 3),
                child: _TimingRow(phase: phase, maximum: maximum),
              ),
          ],
        ),
      ),
    );
  }
}

class _TimingPhase {
  const _TimingPhase(this.label, this.start, this.end);

  final String label;
  final int start;
  final int end;
}

class _TimingRow extends StatelessWidget {
  const _TimingRow({required this.phase, required this.maximum});

  final _TimingPhase phase;
  final int maximum;

  @override
  Widget build(BuildContext context) {
    final start = phase.start.clamp(0, maximum);
    final end = phase.end.clamp(start, maximum);
    return Row(
      children: [
        SizedBox(width: 132, child: Text(phase.label)),
        Expanded(
          child: LayoutBuilder(
            builder: (context, constraints) {
              final left = constraints.maxWidth * start / maximum;
              final width = math.max(
                2.0,
                constraints.maxWidth * (end - start) / maximum,
              );
              return SizedBox(
                height: 16,
                child: Stack(
                  children: [
                    Positioned.fill(
                      child: DecoratedBox(
                        decoration: BoxDecoration(
                          color: Theme.of(context)
                              .colorScheme
                              .surfaceContainerHighest,
                          borderRadius: BorderRadius.circular(4),
                        ),
                      ),
                    ),
                    Positioned(
                      left: left,
                      width: math.min(width, constraints.maxWidth - left),
                      top: 2,
                      bottom: 2,
                      child: DecoratedBox(
                        decoration: BoxDecoration(
                          color: Theme.of(context).colorScheme.primary,
                          borderRadius: BorderRadius.circular(3),
                        ),
                      ),
                    ),
                  ],
                ),
              );
            },
          ),
        ),
        const SizedBox(width: 8),
        SizedBox(
          width: 74,
          child: Text(
            '${phase.start}–${phase.end} ms',
            textAlign: TextAlign.end,
          ),
        ),
      ],
    );
  }
}

class _Http1CapturedValuesSection extends StatelessWidget {
  const _Http1CapturedValuesSection({required this.observation});

  final TlsInspectionRuntimeObservation observation;

  @override
  Widget build(BuildContext context) {
    final l10n = S.of(context);
    return Card(
      clipBehavior: Clip.antiAlias,
      child: ExpansionTile(
        leading: const Icon(Icons.http),
        title: Text(l10n.httpCaptureCapturedData),
        subtitle: Text(
          '${observation.httpTransactions.length} HTTP/1.1',
        ),
        children: [
          for (final transaction in observation.httpTransactions)
            _ExchangeInspector(
              title:
                  '#${transaction.sequence} · ${transaction.request.method} '
                  '${transaction.request.target}',
              request: transaction.request,
              requestBody: transaction.requestBody,
              response: transaction.response,
              responseBody: transaction.responseBody,
            ),
        ],
      ),
    );
  }
}

class _Http2StreamSection extends StatelessWidget {
  const _Http2StreamSection({required this.observation});

  final TlsInspectionRuntimeObservation observation;

  @override
  Widget build(BuildContext context) {
    final l10n = S.of(context);
    return Card(
      clipBehavior: Clip.antiAlias,
      child: ExpansionTile(
        initiallyExpanded: true,
        leading: const Icon(Icons.account_tree_outlined),
        title: Text('HTTP/2 ${l10n.httpCaptureStreams}'),
        subtitle: Text(
          '${observation.http2Streams.length}'
          '${observation.http2StreamsTruncated ? ' · ${l10n.httpCaptureTruncated}' : ''}',
        ),
        children: [
          if (observation.http2GoAway case final goAway?)
            ListTile(
              leading: const Icon(Icons.stop_circle_outlined),
              title: Text(l10n.httpCaptureGoAway),
              subtitle: Text(
                'last=${goAway.lastStreamId} · error=${goAway.errorCode} · '
                '${goAway.observedAfterMilliseconds} ms',
              ),
            ),
          for (final stream in observation.http2Streams)
            _ExchangeInspector(
              title:
                  '${l10n.httpCaptureStream} ${stream.streamId} · '
                  '${stream.request.method} ${stream.request.target}',
              subtitle:
                  '${l10n.httpCaptureStreamState}: ${stream.state}'
                  '${stream.resetCode == 0 ? '' : ' · RST=${stream.resetCode}'}',
              request: stream.request,
              requestBody: stream.requestBody,
              response: stream.response,
              responseBody: stream.responseBody,
            ),
        ],
      ),
    );
  }
}

class _ExchangeInspector extends StatelessWidget {
  const _ExchangeInspector({
    required this.title,
    this.subtitle,
    required this.request,
    this.requestBody,
    this.response,
    this.responseBody,
  });

  final String title;
  final String? subtitle;
  final HttpProtocolObservation request;
  final TlsInspectionRuntimeHttpBody? requestBody;
  final HttpResponseProtocolObservation? response;
  final TlsInspectionRuntimeHttpBody? responseBody;

  @override
  Widget build(BuildContext context) {
    final l10n = S.of(context);
    return ExpansionTile(
      tilePadding: const EdgeInsets.symmetric(horizontal: 16),
      childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
      title: Text(title, maxLines: 2, overflow: TextOverflow.ellipsis),
      subtitle: subtitle == null ? null : Text(subtitle!),
      children: [
        _MessageInspector(
          title: l10n.httpCaptureRequest,
          headerNames: request.headerNames,
          headers: request.headers,
          body: requestBody,
        ),
        if (response != null || responseBody != null) ...[
          const SizedBox(height: 8),
          _MessageInspector(
            title: response == null
                ? l10n.httpCaptureResponse
                : '${l10n.httpCaptureResponse} · ${response!.statusCode}',
            headerNames: response?.headerNames ?? const <String>[],
            headers: response?.headers ?? const <HttpHeaderObservation>[],
            body: responseBody,
          ),
        ],
      ],
    );
  }
}

class _MessageInspector extends StatelessWidget {
  const _MessageInspector({
    required this.title,
    required this.headerNames,
    required this.headers,
    required this.body,
  });

  final String title;
  final List<String> headerNames;
  final List<HttpHeaderObservation> headers;
  final TlsInspectionRuntimeHttpBody? body;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return DecoratedBox(
      decoration: BoxDecoration(
        border: Border.all(color: theme.colorScheme.outlineVariant),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(title, style: theme.textTheme.titleSmall),
            if (headers.isNotEmpty || headerNames.isNotEmpty) ...[
              const SizedBox(height: 8),
              _HeaderPreview(headerNames: headerNames, headers: headers),
            ],
            if (body != null) ...[
              const SizedBox(height: 12),
              HttpInspectionBodyPreview(body: body!),
            ],
          ],
        ),
      ),
    );
  }
}

class _HeaderPreview extends StatelessWidget {
  const _HeaderPreview({
    required this.headerNames,
    required this.headers,
  });

  final List<String> headerNames;
  final List<HttpHeaderObservation> headers;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    if (headers.isEmpty) {
      return Wrap(
        spacing: 6,
        runSpacing: 6,
        children: [
          for (final name in headerNames)
            Chip(
              visualDensity: VisualDensity.compact,
              label: Text(name),
            ),
        ],
      );
    }
    return Table(
      columnWidths: const {
        0: FlexColumnWidth(2),
        1: FlexColumnWidth(5),
      },
      defaultVerticalAlignment: TableCellVerticalAlignment.top,
      children: [
        for (final header in headers)
          TableRow(
            children: [
              Padding(
                padding: const EdgeInsets.only(right: 12, bottom: 4),
                child: SelectableText(
                  header.name,
                  style: theme.textTheme.bodySmall?.copyWith(
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
              Padding(
                padding: const EdgeInsets.only(bottom: 4),
                child: SelectableText(
                  header.redacted
                      ? '<redacted>'
                      : '${header.value}${header.truncated ? '…' : ''}',
                  style: theme.textTheme.bodySmall,
                ),
              ),
            ],
          ),
      ],
    );
  }
}

class HttpInspectionBodyPreview extends StatelessWidget {
  const HttpInspectionBodyPreview({
    super.key,
    required this.body,
  });

  final TlsInspectionRuntimeHttpBody body;

  @override
  Widget build(BuildContext context) {
    final l10n = S.of(context);
    final theme = Theme.of(context);
    final metadata = [
      body.kind,
      if (body.contentType.isNotEmpty) body.contentType,
      '${l10n.httpCaptureCapturedBytes}: ${body.capturedBytes}',
      '${l10n.httpCaptureObservedBytes}: ${body.observedBytes}',
      if (body.truncated) l10n.httpCaptureTruncated,
    ].join(' · ');
    Widget content;
    if (body.omitted) {
      content = Text('${l10n.httpCaptureOmitted}: ${body.omittedReason}');
    } else if (body.kind == 'image' && body.decodedBytes != null) {
      content = ConstrainedBox(
        constraints: const BoxConstraints(maxHeight: 320),
        child: Image.memory(
          body.decodedBytes!,
          fit: BoxFit.contain,
          errorBuilder: (context, error, stackTrace) =>
              Text(l10n.httpCaptureBinaryBody),
        ),
      );
    } else if (body.kind == 'form' && body.formFields.isNotEmpty) {
      content = Table(
        columnWidths: const {
          0: FlexColumnWidth(2),
          1: FlexColumnWidth(4),
        },
        children: [
          for (final entry in body.formFields.entries)
            TableRow(
              children: [
                Padding(
                  padding: const EdgeInsets.only(right: 8, bottom: 4),
                  child: SelectableText(entry.key),
                ),
                Padding(
                  padding: const EdgeInsets.only(bottom: 4),
                  child: SelectableText(entry.value),
                ),
              ],
            ),
        ],
      );
    } else if (body.text.isNotEmpty) {
      content = Container(
        constraints: const BoxConstraints(maxHeight: 360),
        padding: const EdgeInsets.all(10),
        decoration: BoxDecoration(
          color: theme.colorScheme.surfaceContainerHighest,
          borderRadius: BorderRadius.circular(6),
        ),
        child: SingleChildScrollView(
          child: SelectableText(
            body.prettyText,
            style: theme.textTheme.bodySmall?.copyWith(
              fontFamily: 'monospace',
            ),
          ),
        ),
      );
    } else {
      content = Text(l10n.httpCaptureBinaryBody);
    }
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Text(metadata, style: theme.textTheme.labelSmall),
        const SizedBox(height: 6),
        content,
      ],
    );
  }
}
'''


TRANSLATIONS = {
    "intl_en.arb": {
        "httpCapturePrivacyTitle": "Capture privacy",
        "httpCapturePrivacyDescription": "Metadata is captured by default. Header values and bodies require explicit authorization for each capture session.",
        "httpCaptureHeaderValues": "Header values",
        "httpCaptureHeaderValuesDescription": "Retain bounded request and response header values. Sensitive values remain redacted unless separately enabled.",
        "httpCaptureSensitiveHeaders": "Sensitive header values",
        "httpCaptureSensitiveHeadersDescription": "Allow Authorization, Cookie, tokens and similar credentials to be retained.",
        "httpCaptureSensitiveWarning": "This may expose credentials and session tokens. Use only on traffic you are authorized to inspect and clear records when finished.",
        "httpCaptureBodyMode": "Body capture",
        "httpCaptureBodyNone": "Metadata only",
        "httpCaptureBodyText": "Text, JSON and forms",
        "httpCaptureBodyAll": "All supported types",
        "httpCaptureBodyLimit": "Per-message limit",
        "httpCaptureRedactedHeaders": "Always-redacted header names",
        "httpCaptureRedactedHeadersHint": "Comma-separated, for example x-internal-secret",
        "httpCapturePolicyMetadataOnly": "Metadata only",
        "httpCaptureCapturedData": "Captured values and bodies",
        "httpCaptureCapturedBytes": "captured",
        "httpCaptureObservedBytes": "observed",
        "httpCaptureOmitted": "Omitted",
        "httpCaptureTruncated": "truncated",
        "httpCaptureGoAway": "GOAWAY",
        "httpCaptureStreams": "streams",
        "httpCaptureStream": "Stream",
        "httpCaptureStreamState": "State",
        "httpCaptureTiming": "Timing waterfall",
        "httpCaptureUpstreamConnect": "Upstream connect",
        "httpCaptureUpstreamTls": "Upstream TLS",
        "httpCaptureDownstreamTls": "Client TLS",
        "httpCaptureRequestStarted": "Request start",
        "httpCaptureTtfb": "TTFB",
        "httpCaptureDownload": "Download",
        "httpCaptureRequest": "Request",
        "httpCaptureResponse": "Response",
        "httpCaptureBinaryBody": "Binary payload preview is unavailable. The bounded payload remains available in export when authorized."
    },
    "intl_zh_CN.arb": {
        "httpCapturePrivacyTitle": "捕获隐私",
        "httpCapturePrivacyDescription": "默认仅捕获元数据。每次捕获会话都必须显式授权，才会保留 Header 值和 Body。",
        "httpCaptureHeaderValues": "Header 值",
        "httpCaptureHeaderValuesDescription": "限量保留请求和响应 Header 值；敏感值默认仍会脱敏。",
        "httpCaptureSensitiveHeaders": "敏感 Header 值",
        "httpCaptureSensitiveHeadersDescription": "允许保留 Authorization、Cookie、令牌和类似凭据。",
        "httpCaptureSensitiveWarning": "这可能暴露凭据和会话令牌。只检查你获准调试的流量，并在完成后清空记录。",
        "httpCaptureBodyMode": "Body 捕获",
        "httpCaptureBodyNone": "仅元数据",
        "httpCaptureBodyText": "文本、JSON 和表单",
        "httpCaptureBodyAll": "所有支持类型",
        "httpCaptureBodyLimit": "单消息容量上限",
        "httpCaptureRedactedHeaders": "始终脱敏的 Header 名称",
        "httpCaptureRedactedHeadersHint": "逗号分隔，例如 x-internal-secret",
        "httpCapturePolicyMetadataOnly": "仅元数据",
        "httpCaptureCapturedData": "已捕获值与 Body",
        "httpCaptureCapturedBytes": "已捕获",
        "httpCaptureObservedBytes": "已观察",
        "httpCaptureOmitted": "已省略",
        "httpCaptureTruncated": "已截断",
        "httpCaptureGoAway": "GOAWAY",
        "httpCaptureStreams": "Stream",
        "httpCaptureStream": "Stream",
        "httpCaptureStreamState": "状态",
        "httpCaptureTiming": "时序瀑布",
        "httpCaptureUpstreamConnect": "上游连接",
        "httpCaptureUpstreamTls": "上游 TLS",
        "httpCaptureDownstreamTls": "客户端 TLS",
        "httpCaptureRequestStarted": "请求开始",
        "httpCaptureTtfb": "TTFB",
        "httpCaptureDownload": "下载",
        "httpCaptureRequest": "请求",
        "httpCaptureResponse": "响应",
        "httpCaptureBinaryBody": "无法直接预览二进制内容；经授权的限量数据仍可随导出结果保存。"
    },
    "intl_ja.arb": {
        "httpCapturePrivacyTitle": "キャプチャのプライバシー",
        "httpCapturePrivacyDescription": "既定ではメタデータのみを取得します。ヘッダー値と本文はキャプチャセッションごとの明示的な許可が必要です。",
        "httpCaptureHeaderValues": "ヘッダー値",
        "httpCaptureHeaderValuesDescription": "要求と応答のヘッダー値を上限付きで保持します。機密値は別途許可しない限りマスクされます。",
        "httpCaptureSensitiveHeaders": "機密ヘッダー値",
        "httpCaptureSensitiveHeadersDescription": "Authorization、Cookie、トークンなどの資格情報を保持します。",
        "httpCaptureSensitiveWarning": "資格情報やセッショントークンが露出する可能性があります。許可された通信だけを調査し、完了後は記録を消去してください。",
        "httpCaptureBodyMode": "本文キャプチャ",
        "httpCaptureBodyNone": "メタデータのみ",
        "httpCaptureBodyText": "テキスト、JSON、フォーム",
        "httpCaptureBodyAll": "対応するすべての形式",
        "httpCaptureBodyLimit": "メッセージごとの上限",
        "httpCaptureRedactedHeaders": "常にマスクするヘッダー名",
        "httpCaptureRedactedHeadersHint": "カンマ区切り（例: x-internal-secret）",
        "httpCapturePolicyMetadataOnly": "メタデータのみ",
        "httpCaptureCapturedData": "取得した値と本文",
        "httpCaptureCapturedBytes": "取得",
        "httpCaptureObservedBytes": "観測",
        "httpCaptureOmitted": "省略",
        "httpCaptureTruncated": "切り詰め",
        "httpCaptureGoAway": "GOAWAY",
        "httpCaptureStreams": "ストリーム",
        "httpCaptureStream": "ストリーム",
        "httpCaptureStreamState": "状態",
        "httpCaptureTiming": "タイミングウォーターフォール",
        "httpCaptureUpstreamConnect": "上流接続",
        "httpCaptureUpstreamTls": "上流 TLS",
        "httpCaptureDownstreamTls": "クライアント TLS",
        "httpCaptureRequestStarted": "要求開始",
        "httpCaptureTtfb": "TTFB",
        "httpCaptureDownload": "ダウンロード",
        "httpCaptureRequest": "要求",
        "httpCaptureResponse": "応答",
        "httpCaptureBinaryBody": "バイナリ本文は直接プレビューできません。許可された上限付きデータはエクスポートに残ります。"
    },
    "intl_ru.arb": {
        "httpCapturePrivacyTitle": "Конфиденциальность захвата",
        "httpCapturePrivacyDescription": "По умолчанию сохраняются только метаданные. Значения заголовков и тела требуют явного разрешения для каждого сеанса захвата.",
        "httpCaptureHeaderValues": "Значения заголовков",
        "httpCaptureHeaderValuesDescription": "Сохранять ограниченные значения заголовков запросов и ответов. Секретные значения остаются скрытыми без отдельного разрешения.",
        "httpCaptureSensitiveHeaders": "Секретные заголовки",
        "httpCaptureSensitiveHeadersDescription": "Разрешить сохранение Authorization, Cookie, токенов и подобных учётных данных.",
        "httpCaptureSensitiveWarning": "Это может раскрыть учётные данные и токены сеанса. Проверяйте только разрешённый трафик и очищайте записи после завершения.",
        "httpCaptureBodyMode": "Захват тела",
        "httpCaptureBodyNone": "Только метаданные",
        "httpCaptureBodyText": "Текст, JSON и формы",
        "httpCaptureBodyAll": "Все поддерживаемые типы",
        "httpCaptureBodyLimit": "Лимит на сообщение",
        "httpCaptureRedactedHeaders": "Всегда скрываемые заголовки",
        "httpCaptureRedactedHeadersHint": "Через запятую, например x-internal-secret",
        "httpCapturePolicyMetadataOnly": "Только метаданные",
        "httpCaptureCapturedData": "Сохранённые значения и тела",
        "httpCaptureCapturedBytes": "сохранено",
        "httpCaptureObservedBytes": "получено",
        "httpCaptureOmitted": "Пропущено",
        "httpCaptureTruncated": "усечено",
        "httpCaptureGoAway": "GOAWAY",
        "httpCaptureStreams": "потоки",
        "httpCaptureStream": "Поток",
        "httpCaptureStreamState": "Состояние",
        "httpCaptureTiming": "Временная диаграмма",
        "httpCaptureUpstreamConnect": "Подключение к серверу",
        "httpCaptureUpstreamTls": "TLS сервера",
        "httpCaptureDownstreamTls": "TLS клиента",
        "httpCaptureRequestStarted": "Начало запроса",
        "httpCaptureTtfb": "TTFB",
        "httpCaptureDownload": "Загрузка",
        "httpCaptureRequest": "Запрос",
        "httpCaptureResponse": "Ответ",
        "httpCaptureBinaryBody": "Предпросмотр двоичного тела недоступен. Разрешённые ограниченные данные остаются в экспорте."
    },
}


def write_widgets() -> None:
    (ROOT / "lib/views/http_inspection_widgets.dart").write_text(WIDGET_SOURCE)


def patch_http_capture_view() -> None:
    path = ROOT / "lib/views/http_capture.dart"
    text = path.read_text()
    import_line = "import 'http_inspection_widgets.dart';\n"
    if import_line not in text:
        imports = list(re.finditer(r"^import\s+['\"][^'\"]+['\"];\n", text, re.MULTILINE))
        if not imports:
            raise RuntimeError("no imports found in HTTP capture view")
        insert_at = imports[-1].end()
        text = text[:insert_at] + import_line + text[insert_at:]

    app_bar_start = text.find("AppBar(")
    if app_bar_start < 0:
        raise RuntimeError("HTTP capture AppBar not found")
    body_start = text.find("body:", app_bar_start)
    app_bar_scope = text[app_bar_start:body_start if body_start >= 0 else None]
    action_match = re.search(r"actions\s*:\s*(?:<Widget>)?\[", app_bar_scope)
    if action_match is None:
        raise RuntimeError("HTTP capture AppBar actions not found")
    action_insert = app_bar_start + action_match.end()
    if "HttpCapturePolicyAction" not in app_bar_scope:
        text = (
            text[:action_insert]
            + "\n          const HttpCapturePolicyAction(),"
            + text[action_insert:]
        )

    timeline_index = text.find("_HttpTransactionTimelineSection(")
    if timeline_index < 0:
        raise RuntimeError("HTTP transaction timeline integration point missing")
    scope = text[timeline_index:timeline_index + 500]
    record_match = re.search(r"record\s*:\s*([^,\n]+)", scope)
    if record_match is None:
        raise RuntimeError("HTTP transaction timeline record expression missing")
    record_expression = record_match.group(1).strip()
    line_start = text.rfind("\n", 0, timeline_index) + 1
    indentation = text[line_start:timeline_index]
    details = (
        f"{indentation}HttpInspectionDetailsSection(\n"
        f"{indentation}  record: {record_expression},\n"
        f"{indentation}),\n"
    )
    if "HttpInspectionDetailsSection(" not in text:
        text = text[:line_start] + details + text[line_start:]
    path.write_text(text)


def patch_localizations() -> None:
    for filename, additions in TRANSLATIONS.items():
        path = ROOT / "arb" / filename
        data = json.loads(path.read_text())
        for key, value in additions.items():
            data[key] = value
        path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2) + "\n",
        )


def patch_all() -> None:
    write_widgets()
    patch_http_capture_view()
    patch_localizations()
