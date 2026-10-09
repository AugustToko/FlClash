import re
from pathlib import Path

from http_inspection_ui_models import ROOT


MODEL_TEST = r'''import 'package:fl_clash/models/models.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('HTTP inspection privacy models', () {
    test('normalizes explicit capture policy', () {
      final policy = const TlsInspectionCapturePolicy(
        headerValues: true,
        sensitiveHeaderValues: true,
        redactedHeaderNames: [
          'X-Debug',
          'x-debug',
          'bad header',
        ],
        bodyMode: TlsInspectionCaptureBodyMode.all,
        maxBodyBytes: maximumInspectionBodyBytes + 1,
      ).normalized();

      expect(policy.headerValues, isTrue);
      expect(policy.sensitiveHeaderValues, isTrue);
      expect(policy.redactedHeaderNames, ['x-debug']);
      expect(policy.bodyMode, TlsInspectionCaptureBodyMode.all);
      expect(policy.maxBodyBytes, maximumInspectionBodyBytes);
      expect(
        TlsInspectionCapturePolicy.fromJson(policy.toJson()),
        policy,
      );
    });

    test('rejects sensitive header capture without explicit consent', () {
      expect(
        () => TlsInspectionRuntimeObservation.fromJson({
          'sessionId': 'a' * 32,
          'connectionId': 'b' * 32,
          'runtimeId': 'c' * 32,
          'host': 'api.example.com',
          'state': 'running',
          'startedAt': '2026-10-09T00:00:00Z',
          'alpn': 'h2',
          'capturePolicy': const TlsInspectionCapturePolicy(
            headerValues: true,
          ).toJson(),
          'http2Streams': [
            {
              'sequence': 1,
              'streamId': 1,
              'state': 'request-ended',
              'requestObservedAfterMilliseconds': 10,
              'requestCompletedAfterMilliseconds': 12,
              'request': {
                'method': 'GET',
                'target': '/',
                'version': 'HTTP/2',
                'host': 'api.example.com',
                'headerNames': ['authorization'],
                'headers': [
                  {
                    'name': 'authorization',
                    'value': 'Bearer secret',
                  },
                ],
                'headersComplete': true,
              },
            },
          ],
        }),
        throwsFormatException,
      );
    });

    test('parses concurrent HTTP/2 streams and structured bodies', () {
      final policy = const TlsInspectionCapturePolicy(
        headerValues: true,
        bodyMode: TlsInspectionCaptureBodyMode.all,
        maxBodyBytes: 16384,
      );
      final observation = TlsInspectionRuntimeObservation.fromJson({
        'sessionId': 'a' * 32,
        'connectionId': 'b' * 32,
        'runtimeId': 'c' * 32,
        'host': 'api.example.com',
        'state': 'completed',
        'startedAt': '2026-10-09T00:00:00Z',
        'completedAt': '2026-10-09T00:00:01Z',
        'alpn': 'h2',
        'upstreamDialCompletedAfterMilliseconds': 15,
        'upstreamTlsCompletedAfterMilliseconds': 45,
        'downstreamTlsCompletedAfterMilliseconds': 75,
        'capturePolicy': policy.toJson(),
        'http2Streams': [
          {
            'sequence': 1,
            'streamId': 1,
            'state': 'closed',
            'requestObservedAfterMilliseconds': 100,
            'requestCompletedAfterMilliseconds': 110,
            'responseCompletedAfterMilliseconds': 210,
            'request': {
              'method': 'POST',
              'target': '/v1/items',
              'version': 'HTTP/2',
              'host': 'api.example.com',
              'headerNames': ['content-type', 'authorization'],
              'headers': [
                {
                  'name': 'content-type',
                  'value': 'application/json',
                },
                {
                  'name': 'authorization',
                  'redacted': true,
                },
              ],
              'headersComplete': true,
            },
            'requestBody': {
              'kind': 'json',
              'contentType': 'application/json',
              'encoding': 'utf8',
              'text': '{"name":"FlClash"}',
              'capturedBytes': 18,
              'observedBytes': 18,
            },
            'response': {
              'version': 'HTTP/2',
              'statusCode': 201,
              'headerNames': ['content-type'],
              'headers': [
                {
                  'name': 'content-type',
                  'value': 'application/json',
                },
              ],
              'headersComplete': true,
              'observedBytes': 10,
              'observedAfterMilliseconds': 150,
            },
            'responseBody': {
              'kind': 'json',
              'contentType': 'application/json',
              'encoding': 'utf8',
              'text': '{"ok":true}',
              'capturedBytes': 11,
              'observedBytes': 11,
            },
          },
          {
            'sequence': 2,
            'streamId': 3,
            'state': 'closed',
            'requestObservedAfterMilliseconds': 120,
            'requestCompletedAfterMilliseconds': 120,
            'responseCompletedAfterMilliseconds': 170,
            'request': {
              'method': 'GET',
              'target': '/health',
              'version': 'HTTP/2',
              'host': 'api.example.com',
              'headersComplete': true,
            },
            'response': {
              'version': 'HTTP/2',
              'statusCode': 204,
              'headersComplete': true,
              'observedBytes': 4,
              'observedAfterMilliseconds': 160,
            },
          },
        ],
        'http2GoAway': {
          'lastStreamId': 3,
          'errorCode': 0,
          'observedAfterMilliseconds': 220,
        },
      });

      expect(observation.http2Streams, hasLength(2));
      expect(observation.http2Streams.first.streamId, 1);
      expect(observation.http2Streams.last.streamId, 3);
      expect(observation.effectiveHttpRequest?.target, '/v1/items');
      expect(observation.effectiveHttpResponse?.statusCode, 201);
      expect(observation.http2GoAway?.lastStreamId, 3);
      expect(
        observation.http2Streams.first.request.headers.last.redacted,
        isTrue,
      );
      expect(
        observation.http2Streams.first.responseBody?.prettyText,
        contains('\n'),
      );
      expect(
        TlsInspectionRuntimeObservation.fromJson(observation.toJson())
            .http2Streams
            .last
            .response
            ?.statusCode,
        204,
      );
    });

    test('parses bounded image body bytes', () {
      final body = TlsInspectionRuntimeHttpBody.fromJson({
        'kind': 'image',
        'contentType': 'image/png',
        'encoding': 'base64',
        'base64': 'iVBORw0KGgo=',
        'capturedBytes': 8,
        'observedBytes': 8,
      });
      expect(body.decodedBytes, hasLength(8));
      expect(body.hasPayload, isTrue);
    });
  });
}
'''


WIDGET_TEST = r'''import 'package:fl_clash/generated/l10n.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/views/http_inspection_widgets.dart';
import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_test/flutter_test.dart';

Widget _app(Widget child) {
  return MaterialApp(
    localizationsDelegates: const [
      S.delegate,
      GlobalMaterialLocalizations.delegate,
      GlobalWidgetsLocalizations.delegate,
      GlobalCupertinoLocalizations.delegate,
    ],
    supportedLocales: S.delegate.supportedLocales,
    home: Scaffold(body: child),
  );
}

void main() {
  testWidgets('privacy dialog defaults to metadata-only capture', (
    tester,
  ) async {
    TlsInspectionCapturePolicy? result;
    await tester.pumpWidget(
      _app(
        Builder(
          builder: (context) => FilledButton(
            onPressed: () async {
              result = await showHttpCapturePolicyDialog(
                context,
                TlsInspectionCapturePolicy.metadataOnly,
              );
            },
            child: const Text('open'),
          ),
        ),
      ),
    );
    await tester.tap(find.text('open'));
    await tester.pumpAndSettle();

    expect(find.byType(SwitchListTile), findsNWidgets(2));
    expect(find.text('Metadata only'), findsWidgets);
    await tester.tap(find.text('OK'));
    await tester.pumpAndSettle();

    expect(result, TlsInspectionCapturePolicy.metadataOnly);
  });

  testWidgets('body preview pretty prints JSON and reports bounds', (
    tester,
  ) async {
    const body = TlsInspectionRuntimeHttpBody(
      kind: 'json',
      contentType: 'application/json',
      encoding: 'utf8',
      text: '{"ok":true}',
      capturedBytes: 11,
      observedBytes: 22,
      truncated: true,
    );
    await tester.pumpWidget(
      _app(
        const Padding(
          padding: EdgeInsets.all(16),
          child: HttpInspectionBodyPreview(body: body),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.textContaining('captured: 11'), findsOneWidget);
    expect(find.textContaining('observed: 22'), findsOneWidget);
    expect(find.textContaining('"ok": true'), findsOneWidget);
    expect(find.textContaining('truncated'), findsOneWidget);
  });
}
'''


def patch_test_fakes() -> None:
    test_root = ROOT / "test"
    pattern = re.compile(
        r"(Future(?:Or)?<bool>\s+setObservationEnabled\(\s*"
        r"bool\s+enabled\s*,\s*String\s+sessionId\s*,?)(\s*\))",
        re.MULTILINE,
    )
    replacement = (
        r"\1\n    {TlsInspectionCapturePolicy policy = "
        r"TlsInspectionCapturePolicy.metadataOnly,}\2"
    )
    for path in test_root.rglob("*.dart"):
        text = path.read_text()
        updated = pattern.sub(replacement, text)
        if updated != text:
            path.write_text(updated)


def patch_core_expectations() -> None:
    path = ROOT / "test/core/tls_runtime_test.dart"
    if not path.exists():
        return
    text = path.read_text()
    # Existing controller tests compare the exact argument map. The bridge now
    # always supplies a normalized, explicit metadata-only policy by default.
    map_pattern = re.compile(
        r"(\{\s*['\"]enabled['\"]\s*:\s*(?:true|false)\s*,\s*"
        r"['\"]sessionId['\"]\s*:\s*[^,}\n]+)(\s*\})",
        re.MULTILINE,
    )

    def add_policy(match: re.Match[str]) -> str:
        value = match.group(0)
        if "policy" in value:
            return value
        return (
            match.group(1)
            + ", 'policy': TlsInspectionCapturePolicy.metadataOnly.toJson()"
            + match.group(2)
        )

    path.write_text(map_pattern.sub(add_policy, text))


def write_tests() -> None:
    (ROOT / "test/models/http_inspection_test.dart").write_text(MODEL_TEST)
    (ROOT / "test/views/http_inspection_widgets_test.dart").write_text(
        WIDGET_TEST,
    )
    patch_test_fakes()
    patch_core_expectations()
