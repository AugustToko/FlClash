import re
from pathlib import Path

from http_inspection_ui_capture_model import patch_all as patch_capture_model
from http_inspection_ui_models import ROOT, patch_all as patch_models
from http_inspection_ui_state import patch_all as patch_state
from http_inspection_ui_tests import write_tests
from http_inspection_ui_widgets import patch_all as patch_widgets


def fix_capture_policy_model() -> None:
    path = ROOT / "lib/models/http_inspection.dart"
    text = path.read_text()
    text = text.replace(
        "maxBodyBytes.clamp(1, maximumInspectionBodyBytes);",
        "maxBodyBytes.clamp(1, maximumInspectionBodyBytes).toInt();",
    )
    path.write_text(text)


def fix_runtime_model_copy_and_validation() -> None:
    path = ROOT / "lib/models/tls_inspection_runtime.dart"
    text = path.read_text()

    header_copy_pattern = re.compile(
        r"(?P<indent>\s*)headerNames:\s*(?P<source>[A-Za-z_][A-Za-z0-9_]*)\.headerNames,\n"
        r"(?P=indent)headersComplete:",
    )

    def copy_headers(match: re.Match[str]) -> str:
        indent = match.group("indent")
        source = match.group("source")
        return (
            f"{indent}headerNames: {source}.headerNames,\n"
            f"{indent}headers: {source}.headers,\n"
            f"{indent}headersComplete:"
        )

    text = header_copy_pattern.sub(copy_headers, text)

    truncated_copy_pattern = re.compile(
        r"(?P<indent>\s*)headerNamesTruncated:\s*"
        r"(?P<source>[A-Za-z_][A-Za-z0-9_]*)\.headerNamesTruncated,\n"
    )

    def copy_truncation(match: re.Match[str]) -> str:
        indent = match.group("indent")
        source = match.group("source")
        return (
            f"{indent}headerNamesTruncated: {source}.headerNamesTruncated,\n"
            f"{indent}headerValuesTruncated: "
            f"{source}.headerValuesTruncated,\n"
        )

    text = truncated_copy_pattern.sub(copy_truncation, text)

    if "void _validateRuntimeStatus(" not in text:
        marker = "class TlsInspectionRuntimeStartParams {\n"
        validator = r'''void _validateRuntimeStatus(TlsInspectionRuntimeStatus status) {
  if ((status.mode != 'loopback-connect-http1' &&
          status.mode != 'loopback-connect-http1-h2') ||
      !status.clientAuthenticationRequired ||
      !status.hostAllowlistRequired ||
      !status.upstreamCertificateVerification ||
      !status.acceptsConnectOnly ||
      status.capturesPayload != status.capturePolicy.capturesBodies ||
      status.changesSystemProxy) {
    throw const FormatException('Unsafe runtime status');
  }
  if (status.running) {
    if (!RegExp(r'^[a-f0-9]{32}$').hasMatch(status.id) ||
        status.listenHost != '127.0.0.1' ||
        status.listenPort <= 0) {
      throw const FormatException('Running runtime status is invalid');
    }
  } else if (status.id.isNotEmpty || status.listenPort != 0) {
    throw const FormatException('Stopped runtime status is invalid');
  }
}

'''
        if marker not in text:
            raise RuntimeError("runtime start params marker missing")
        text = text.replace(marker, validator + marker, 1)

    path.write_text(text)


def fix_widget_implementation() -> None:
    path = ROOT / "lib/views/http_inspection_widgets.dart"
    text = path.read_text()
    old = '''                Padding(
                  padding: const EdgeInsets.only(bottom: 12),
                  child: MaterialBanner(
                    padding: const EdgeInsets.all(12),
                    leading: const Icon(Icons.warning_amber_rounded),
                    content: Text(l10n.httpCaptureSensitiveWarning),
                    actions: const <Widget>[],
                  ),
                ),
'''
    new = '''                Padding(
                  padding: const EdgeInsets.only(bottom: 12),
                  child: Card(
                    color: Theme.of(context).colorScheme.errorContainer,
                    child: ListTile(
                      leading: const Icon(Icons.warning_amber_rounded),
                      title: Text(l10n.httpCaptureSensitiveWarning),
                    ),
                  ),
                ),
'''
    if old not in text:
        raise RuntimeError("sensitive warning widget marker missing")
    text = text.replace(old, new, 1)
    path.write_text(text)


def fix_generated_tests() -> None:
    model_test = ROOT / "test/models/http_inspection_test.dart"
    text = model_test.read_text()
    text = text.replace("'a' * 32", "'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'")
    text = text.replace("'b' * 32", "'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'")
    text = text.replace("'c' * 32", "'cccccccccccccccccccccccccccccccc'")
    model_test.write_text(text)

    for path in (ROOT / "test").rglob("*.dart"):
        text = path.read_text()
        if "TlsInspectionCapturePolicy policy" not in text:
            continue
        package_import = "import 'package:fl_clash/models/models.dart';\n"
        if package_import not in text and "models/models.dart" not in text:
            import_matches = list(
                re.finditer(r"^import\s+['\"][^'\"]+['\"];\n", text, re.MULTILINE),
            )
            if not import_matches:
                text = package_import + text
            else:
                insert_at = import_matches[-1].end()
                text = text[:insert_at] + package_import + text[insert_at:]
            path.write_text(text)


def validate_patch_shape() -> None:
    required = {
        ROOT / "lib/models/http_inspection.dart": [
            "class TlsInspectionCapturePolicy",
            "class TlsInspectionRuntimeHttpBody",
        ],
        ROOT / "lib/models/tls_inspection_runtime.dart": [
            "class TlsInspectionRuntimeHttp2Stream",
            "http2Streams",
            "capturePolicy",
        ],
        ROOT / "lib/views/http_capture.dart": [
            "HttpCapturePolicyAction",
            "HttpInspectionDetailsSection",
        ],
        ROOT / "lib/views/http_inspection_widgets.dart": [
            "class HttpInspectionBodyPreview",
            "class _Http2StreamSection",
        ],
        ROOT / "lib/providers/http_capture.dart": [
            "updateCapturePolicy",
            "policy: _state.capturePolicy",
        ],
    }
    for path, markers in required.items():
        text = path.read_text()
        for marker in markers:
            if marker not in text:
                raise RuntimeError(f"missing expected marker {marker!r} in {path}")


def main() -> None:
    patch_models()
    patch_state()
    patch_capture_model()
    patch_widgets()
    write_tests()
    fix_capture_policy_model()
    fix_runtime_model_copy_and_validation()
    fix_widget_implementation()
    fix_generated_tests()
    validate_patch_shape()


if __name__ == "__main__":
    main()
