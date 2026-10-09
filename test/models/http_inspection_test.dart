import 'package:fl_clash/models/models.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('capture policy normalizes custom redactions and capacity', () {
    final policy = const TlsInspectionCapturePolicy(
      headerValues: true,
      sensitiveHeaderValues: true,
      redactedHeaderNames: ['X-Private', 'x-private', 'bad header'],
      bodyMode: TlsInspectionCaptureBodyMode.all,
      maxBodyBytes: maximumInspectionBodyBytes + 1,
    ).normalized();

    expect(policy.headerValues, isTrue);
    expect(policy.sensitiveHeaderValues, isTrue);
    expect(policy.redactedHeaderNames, ['x-private']);
    expect(policy.maxBodyBytes, maximumInspectionBodyBytes);
    expect(TlsInspectionCapturePolicy.fromJson(policy.toJson()), policy);
  });

  test('header observations enforce bounded redacted values', () {
    final redacted = HttpHeaderObservation.fromJson({
      'name': 'authorization',
      'redacted': true,
    });
    expect(redacted.sensitive, isTrue);
    expect(redacted.hasVisibleValue, isFalse);
    expect(redacted.toJson(), isNot(contains('value')));

    expect(
      () => HttpHeaderObservation.fromJson({
        'name': 'authorization',
        'value': 'Bearer secret',
        'redacted': true,
      }),
      throwsFormatException,
    );
  });

  test('captured bodies provide JSON, form, and binary projections', () {
    final jsonBody = TlsInspectionRuntimeHttpBody.fromJson({
      'kind': 'json',
      'contentType': 'application/json',
      'encoding': 'utf8',
      'text': '{"ok":true}',
      'capturedBytes': 11,
      'observedBytes': 11,
    });
    expect(jsonBody.prettyText, contains('\n'));

    final formBody = TlsInspectionRuntimeHttpBody.fromJson({
      'kind': 'form',
      'contentType': 'application/x-www-form-urlencoded',
      'encoding': 'utf8',
      'text': 'name=flclash&mode=test',
      'capturedBytes': 22,
      'observedBytes': 22,
    });
    expect(formBody.formFields, {'name': 'flclash', 'mode': 'test'});

    final binaryBody = TlsInspectionRuntimeHttpBody.fromJson({
      'kind': 'image',
      'contentType': 'image/png',
      'encoding': 'base64',
      'base64': 'iVBORw==',
      'capturedBytes': 4,
      'observedBytes': 4,
    });
    expect(binaryBody.decodedBytes, hasLength(4));
  });
}
