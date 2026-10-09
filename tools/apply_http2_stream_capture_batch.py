from pathlib import Path
import shutil
import subprocess

from http2_batch_common import ROOT, patch_all as patch_core
from http2_batch_http1 import patch_all as patch_http1
from http2_batch_tests import write_tests


def add_http1_watcher_compatibility() -> None:
    runtime_path = ROOT / "core/inspectionruntime/runtime.go"
    text = runtime_path.read_text()
    marker = "func (r *Runtime) relay(\n"
    compatibility = '''func (r *Runtime) watchHTTP1Timeline(
\tctx context.Context,
\tobservation *runtimeObservation,
\ttimeline *http1MetadataTimeline,
\tsignal <-chan struct{},
\tdone <-chan struct{},
) {
\tr.watchHTTPTimeline(ctx, observation, timeline, signal, done)
}

'''
    if marker not in text:
        raise RuntimeError("relay marker missing for HTTP/1 watcher compatibility")
    runtime_path.write_text(text.replace(marker, compatibility + marker, 1))


def main() -> None:
    patch_core()
    patch_http1()
    add_http1_watcher_compatibility()
    write_tests()

    # Keep the JSON test payload valid while the generator itself remains a
    # raw Python string that is easy to review.
    test_path = ROOT / "core/inspectionruntime/http2_timeline_test.go"
    test_path.write_text(
        test_path.read_text().replace(r'`{\"ok\":true}`', '`{"ok":true}`')
    )

    go_files = [
        "core/http_observer.go",
        "core/tls_inspection_runtime.go",
        "core/inspectionruntime/capture_policy.go",
        "core/inspectionruntime/capture_policy_test.go",
        "core/inspectionruntime/http1_metadata.go",
        "core/inspectionruntime/http1_timeline.go",
        "core/inspectionruntime/http2_headers.go",
        "core/inspectionruntime/http2_timeline.go",
        "core/inspectionruntime/http2_timeline_test.go",
        "core/inspectionruntime/runtime.go",
    ]
    subprocess.run(["gofmt", "-w", *go_files], cwd=ROOT, check=True)

    # The workflow and patch helpers are deliberately one-shot and must not
    # remain in the product branch after the generated changes pass tests.
    for helper in (
        ROOT / "tools/http2_batch_common.py",
        ROOT / "tools/http2_batch_http1.py",
        ROOT / "tools/http2_batch_tests.py",
    ):
        helper.unlink(missing_ok=True)
    shutil.rmtree(ROOT / "tools/__pycache__", ignore_errors=True)


if __name__ == "__main__":
    main()
