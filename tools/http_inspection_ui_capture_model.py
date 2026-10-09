from pathlib import Path

from http_inspection_ui_models import ROOT, replace_once


def patch_capture_entry_getters() -> None:
    path = ROOT / "lib/models/http_capture.dart"
    text = path.read_text()
    text = text.replace(
        '''  int get httpTransactionCount =>
      tlsObservation?.httpTransactions.length ?? 0;

  bool get httpTransactionsTruncated =>
      tlsObservation?.httpTransactionsTruncated ?? false;

  List<TlsInspectionRuntimeHttpTransaction> get httpTransactions =>
      tlsObservation?.httpTransactions ??
      const <TlsInspectionRuntimeHttpTransaction>[];
''',
        '''  int get httpTransactionCount =>
      (tlsObservation?.httpTransactions.length ?? 0) +
      (tlsObservation?.http2Streams.length ?? 0);

  bool get httpTransactionsTruncated =>
      (tlsObservation?.httpTransactionsTruncated ?? false) ||
      (tlsObservation?.http2StreamsTruncated ?? false);

  List<TlsInspectionRuntimeHttpTransaction> get httpTransactions =>
      tlsObservation?.httpTransactions ??
      const <TlsInspectionRuntimeHttpTransaction>[];

  List<TlsInspectionRuntimeHttp2Stream> get http2Streams =>
      tlsObservation?.http2Streams ??
      const <TlsInspectionRuntimeHttp2Stream>[];
''',
        1,
    )
    text = text.replace(
        '''    final transactions = observation?.httpTransactions ??
        const <TlsInspectionRuntimeHttpTransaction>[];
    if (transactions.isEmpty) {
      return [_harEntry(record, record.entry.httpRequest, null, 0)];
    }
    return [
      for (final transaction in transactions)
        _harEntry(
          record,
          transaction.request,
          transaction.response,
          transaction.sequence,
        ),
    ];
''',
        '''    final transactions = observation?.httpTransactions ??
        const <TlsInspectionRuntimeHttpTransaction>[];
    final streams = observation?.http2Streams ??
        const <TlsInspectionRuntimeHttp2Stream>[];
    if (transactions.isEmpty && streams.isEmpty) {
      return [_harEntry(record, record.entry.httpRequest, null, 0)];
    }
    return [
      for (final transaction in transactions)
        _harEntry(
          record,
          transaction.request,
          transaction.response,
          transaction.sequence,
          requestBody: transaction.requestBody,
          responseBody: transaction.responseBody,
        ),
      for (final stream in streams)
        _harEntry(
          record,
          stream.request,
          stream.response,
          stream.sequence,
          requestBody: stream.requestBody,
          responseBody: stream.responseBody,
          streamId: stream.streamId,
          streamState: stream.state,
        ),
    ];
''',
        1,
    )
    text = text.replace(
        '''  Map<String, dynamic> _harEntry(
    HttpCaptureRecord record,
    HttpProtocolObservation? request,
    HttpResponseProtocolObservation? response,
    int transactionSequence,
  ) {
''',
        '''  Map<String, dynamic> _harEntry(
    HttpCaptureRecord record,
    HttpProtocolObservation? request,
    HttpResponseProtocolObservation? response,
    int transactionSequence, {
    TlsInspectionRuntimeHttpBody? requestBody,
    TlsInspectionRuntimeHttpBody? responseBody,
    int streamId = 0,
    String streamState = '',
  }) {
''',
        1,
    )
    text = text.replace(
        '''      'request': _harRequest(request),
      'response': _harResponse(response),
''',
        '''      'request': _harRequest(request, requestBody),
      'response': _harResponse(response, responseBody),
''',
        1,
    )
    text = text.replace(
        '''      'comment': _harComment(
        record,
        transactionSequence: transactionSequence,
      ),
''',
        '''      'comment': _harComment(
        record,
        transactionSequence: transactionSequence,
        streamId: streamId,
        streamState: streamState,
      ),
''',
        1,
    )
    text = text.replace(
        '''  Map<String, dynamic> _harRequest(HttpProtocolObservation? request) {
''',
        '''  Map<String, dynamic> _harRequest(
    HttpProtocolObservation? request,
    TlsInspectionRuntimeHttpBody? body,
  ) {
''',
        1,
    )
    text = text.replace(
        '''      'headers': [
        for (final name in request?.headerNames ?? const <String>[])
          {'name': name, 'value': ''},
      ],
''',
        '''      'headers': _harHeaders(
        request?.headerNames ?? const <String>[],
        request?.headers ?? const <HttpHeaderObservation>[],
      ),
''',
        1,
    )
    text = text.replace(
        '''      'bodySize': -1,
    };
  }

  Map<String, dynamic> _harResponse(
    HttpResponseProtocolObservation? response,
  ) {
''',
        '''      'bodySize': body?.observedBytes ?? -1,
      if (body != null) 'postData': _harPostData(body),
    };
  }

  Map<String, dynamic> _harResponse(
    HttpResponseProtocolObservation? response,
    TlsInspectionRuntimeHttpBody? body,
  ) {
''',
        1,
    )
    text = text.replace(
        '''      'headers': [
        for (final name in response?.headerNames ?? const <String>[])
          {'name': name, 'value': ''},
      ],
''',
        '''      'headers': _harHeaders(
        response?.headerNames ?? const <String>[],
        response?.headers ?? const <HttpHeaderObservation>[],
      ),
''',
        1,
    )
    text = text.replace(
        '''      'content': {'size': -1, 'mimeType': ''},
      'redirectURL': '',
      'headersSize': -1,
      'bodySize': -1,
''',
        '''      'content': _harContent(body),
      'redirectURL': '',
      'headersSize': -1,
      'bodySize': body?.observedBytes ?? -1,
''',
        1,
    )
    text = text.replace(
        '''  String _harComment(
    HttpCaptureRecord record, {
    required int transactionSequence,
  }) {
''',
        '''  String _harComment(
    HttpCaptureRecord record, {
    required int transactionSequence,
    int streamId = 0,
    String streamState = '',
  }) {
''',
        1,
    )
    text = text.replace(
        '''    if (transactionSequence > 0) {
      parts.add('HTTP transaction #$transactionSequence');
    }
''',
        '''    if (streamId > 0) {
      parts.add('HTTP/2 stream $streamId ($streamState)');
    } else if (transactionSequence > 0) {
      parts.add('HTTP transaction #$transactionSequence');
    }
''',
        1,
    )
    helper_marker = '''  String _harComment(
'''
    helpers = '''  List<Map<String, dynamic>> _harHeaders(
    List<String> names,
    List<HttpHeaderObservation> values,
  ) {
    if (values.isNotEmpty) {
      return [
        for (final header in values)
          {
            'name': header.name,
            'value': header.redacted ? '<redacted>' : header.value,
            if (header.truncated) '_truncated': true,
          },
      ];
    }
    return [
      for (final name in names) {'name': name, 'value': ''},
    ];
  }

  Map<String, dynamic> _harPostData(TlsInspectionRuntimeHttpBody body) {
    return {
      'mimeType': body.contentType,
      if (body.text.isNotEmpty) 'text': body.text,
      if (body.base64.isNotEmpty) 'text': body.base64,
      if (body.base64.isNotEmpty) 'encoding': 'base64',
      '_capturedBytes': body.capturedBytes,
      '_observedBytes': body.observedBytes,
      if (body.truncated) '_truncated': true,
      if (body.omittedReason.isNotEmpty)
        '_omittedReason': body.omittedReason,
    };
  }

  Map<String, dynamic> _harContent(TlsInspectionRuntimeHttpBody? body) {
    if (body == null) {
      return {'size': -1, 'mimeType': ''};
    }
    return {
      'size': body.observedBytes,
      'mimeType': body.contentType,
      if (body.text.isNotEmpty) 'text': body.text,
      if (body.base64.isNotEmpty) 'text': body.base64,
      if (body.base64.isNotEmpty) 'encoding': 'base64',
      '_capturedBytes': body.capturedBytes,
      if (body.truncated) '_truncated': true,
      if (body.omittedReason.isNotEmpty)
        '_omittedReason': body.omittedReason,
    };
  }

'''
    if helper_marker not in text:
        raise RuntimeError("HAR comment marker missing")
    text = text.replace(helper_marker, helpers + helper_marker, 1)
    path.write_text(text)


def patch_all() -> None:
    patch_capture_entry_getters()
