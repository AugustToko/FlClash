from pathlib import Path

from http_inspection_ui_models import ROOT, replace_once


def patch_core_interface() -> None:
    path = ROOT / "lib/core/interface.dart"
    replace_once(
        path,
        '''  Future<bool> setHttpObservationEnabled(bool enabled, String sessionId);
''',
        '''  Future<bool> setHttpObservationEnabled(
    bool enabled,
    String sessionId, {
    TlsInspectionCapturePolicy policy =
        TlsInspectionCapturePolicy.metadataOnly,
  });
''',
    )
    replace_once(
        path,
        '''  Future<bool> setHttpObservationEnabled(bool enabled, String sessionId) {
    return coreController.setHttpObservationEnabled(enabled, sessionId);
  }
''',
        '''  Future<bool> setHttpObservationEnabled(
    bool enabled,
    String sessionId, {
    TlsInspectionCapturePolicy policy =
        TlsInspectionCapturePolicy.metadataOnly,
  }) {
    return coreController.setHttpObservationEnabled(
      enabled,
      sessionId,
      policy: policy,
    );
  }
''',
    )


def patch_core_controller() -> None:
    path = ROOT / "lib/core/controller.dart"
    replace_once(
        path,
        '''  FutureOr<bool> setHttpObservationEnabled(
    bool enabled,
    String sessionId,
  ) {
    return invoke<bool>(
          method: 'setHttpObservationEnabled',
          params: {'enabled': enabled, 'sessionId': sessionId},
        ) ??
        false;
  }
''',
        '''  FutureOr<bool> setHttpObservationEnabled(
    bool enabled,
    String sessionId, {
    TlsInspectionCapturePolicy policy =
        TlsInspectionCapturePolicy.metadataOnly,
  }) {
    return invoke<bool>(
          method: 'setHttpObservationEnabled',
          params: {
            'enabled': enabled,
            'sessionId': sessionId,
            'policy': policy.normalized().toJson(),
          },
        ) ??
        false;
  }
''',
    )


def patch_provider_state() -> None:
    path = ROOT / "lib/providers/http_capture.dart"
    text = path.read_text()
    replacements = [
        (
            '''  const HttpCaptureState({
    this.records = const <HttpCaptureRecord>[],
    this.captureSessionId = '',
    this.operation = HttpCaptureOperation.idle,
    this.failure,
  });
''',
            '''  const HttpCaptureState({
    this.records = const <HttpCaptureRecord>[],
    this.captureSessionId = '',
    this.operation = HttpCaptureOperation.idle,
    this.capturePolicy = TlsInspectionCapturePolicy.metadataOnly,
    this.failure,
  });
''',
        ),
        (
            '''  final String captureSessionId;
  final HttpCaptureOperation operation;
  final HttpCaptureFailure? failure;
''',
            '''  final String captureSessionId;
  final HttpCaptureOperation operation;
  final TlsInspectionCapturePolicy capturePolicy;
  final HttpCaptureFailure? failure;
''',
        ),
        (
            '''    Object? captureSessionId = _unset,
    HttpCaptureOperation? operation,
    Object? failure = _unset,
  }) {
''',
            '''    Object? captureSessionId = _unset,
    HttpCaptureOperation? operation,
    TlsInspectionCapturePolicy? capturePolicy,
    Object? failure = _unset,
  }) {
''',
        ),
        (
            '''      operation: operation ?? this.operation,
      failure: identical(failure, _unset)
''',
            '''      operation: operation ?? this.operation,
      capturePolicy: capturePolicy ?? this.capturePolicy,
      failure: identical(failure, _unset)
''',
        ),
        (
            '''abstract interface class HttpCaptureCoreControl {
  Future<bool> setObservationEnabled(bool enabled, String sessionId);
}
''',
            '''abstract interface class HttpCaptureCoreControl {
  Future<bool> setObservationEnabled(
    bool enabled,
    String sessionId, {
    TlsInspectionCapturePolicy policy =
        TlsInspectionCapturePolicy.metadataOnly,
  });
}
''',
        ),
        (
            '''  Future<bool> setObservationEnabled(bool enabled, String sessionId) {
    return coreController.setHttpObservationEnabled(enabled, sessionId);
  }
''',
            '''  Future<bool> setObservationEnabled(
    bool enabled,
    String sessionId, {
    TlsInspectionCapturePolicy policy =
        TlsInspectionCapturePolicy.metadataOnly,
  }) {
    return coreController.setHttpObservationEnabled(
      enabled,
      sessionId,
      policy: policy,
    );
  }
''',
        ),
        (
            '''      final observationEnabled = await _coreControl.setObservationEnabled(
        true,
        captureSessionId,
      );
''',
            '''      final observationEnabled = await _coreControl.setObservationEnabled(
        true,
        captureSessionId,
        policy: _state.capturePolicy,
      );
''',
        ),
    ]
    for old, new in replacements:
        if old not in text:
            raise RuntimeError(f"missing provider state replacement: {old[:100]!r}")
        text = text.replace(old, new, 1)

    method_marker = '''  Future<void> startCapture() async {
'''
    method = '''  void updateCapturePolicy(TlsInspectionCapturePolicy policy) {
    if (_disposed ||
        _state.capturing ||
        _state.operation != HttpCaptureOperation.idle) {
      return;
    }
    final normalized = policy.normalized();
    if (normalized == _state.capturePolicy) {
      return;
    }
    _emit(_state.copyWith(capturePolicy: normalized));
  }

'''
    if method_marker not in text:
        raise RuntimeError("startCapture marker missing")
    text = text.replace(method_marker, method + method_marker, 1)
    path.write_text(text)


def patch_all() -> None:
    patch_core_interface()
    patch_core_controller()
    patch_provider_state()
