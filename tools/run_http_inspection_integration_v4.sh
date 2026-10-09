#!/usr/bin/env bash
set -euo pipefail

cat tools/http-inspection-ui.patch.gz.b64.part* \
  | base64 --decode \
  | gzip --decompress \
  > /tmp/http-inspection-ui.patch
test "$(sha256sum /tmp/http-inspection-ui.patch | cut -d' ' -f1)" = \
  "dc0b5e69568b411bf01932c77bd9c796e4b1658602aab1b03f2815fc31f5cc5b"

cat tools/http-inspection-widgets.patch.gz.b64.part* \
  | base64 --decode \
  | gzip --decompress \
  > /tmp/http-inspection-widgets.patch
test "$(sha256sum /tmp/http-inspection-widgets.patch | cut -d' ' -f1)" = \
  "1f0301e7c95cf2c6e0793d46e77b6c78acfc028f9070959997b6faf339ab5d4e"

cat tools/http-inspection-analyzer-fixes.patch.gz.b64.part* \
  | base64 --decode \
  | gzip --decompress \
  > /tmp/http-inspection-analyzer-fixes.patch
test "$(sha256sum /tmp/http-inspection-analyzer-fixes.patch | cut -d' ' -f1)" = \
  "b84574251acdca547264602bdc87093eca976b06b225f2631cd3f234e3309c5a"

for patch in \
  /tmp/http-inspection-ui.patch \
  /tmp/http-inspection-widgets.patch \
  /tmp/http-inspection-analyzer-fixes.patch; do
  git apply --check "$patch"
  git apply "$patch"
done

flutter pub get
yq -i '.hooks.user_defines.setup.build_assets = false | .hooks.user_defines.rust_api.build_assets = false' pubspec.yaml
dart run intl_utils:generate

dart format \
  lib/core/controller.dart \
  lib/core/interface.dart \
  lib/models/http_capture.dart \
  lib/models/http_inspection.dart \
  lib/models/models.dart \
  lib/models/tls_inspection_runtime.dart \
  lib/providers/http_capture.dart \
  lib/views/http_capture.dart \
  lib/views/http_inspection_widgets.dart \
  test/core/tls_runtime_test.dart \
  test/models/http_capture_test.dart \
  test/providers/http_capture_test.dart \
  test/views/http_capture_preview_test.dart

flutter analyze --no-fatal-infos \
  lib/core/controller.dart \
  lib/core/interface.dart \
  lib/models/http_capture.dart \
  lib/models/http_inspection.dart \
  lib/models/tls_inspection_runtime.dart \
  lib/providers/http_capture.dart \
  lib/views/http_capture.dart \
  lib/views/http_inspection_widgets.dart

flutter test --update-goldens test/views/http_capture_preview_test.dart
flutter test --reporter expanded \
  test/core/tls_runtime_test.dart \
  test/models/http_capture_test.dart \
  test/providers/http_capture_test.dart \
  test/views/http_capture_preview_test.dart
flutter test --reporter expanded

pushd core >/dev/null
test -z "$(gofmt -l ./inspectionruntime ./tls_inspection_runtime.go ./http_observer.go)" || {
  gofmt -l ./inspectionruntime ./tls_inspection_runtime.go ./http_observer.go >&2
  exit 1
}
CGO_ENABLED=0 go test -count=1 ./inspectionruntime
CGO_ENABLED=0 go vet ./inspectionruntime
popd >/dev/null

rm -f \
  .github/workflows/apply-http-inspection-final-v4.yml \
  .github/workflows/apply-http-inspection-final-v3.yml \
  .github/workflows/apply-http-inspection-final.yml \
  .github/workflows/apply-http-inspection-ui-batch-v2.yml \
  .github/workflows/apply-http-inspection-ui-batch.yml \
  .github/workflows/export-http-ui-source.yml \
  .github/workflows/inspect-http-capture-ui.yml \
  .github/workflows/verify-http-inspection-ui.yml \
  tools/apply_http_inspection_ui_batch.py \
  tools/apply_http_inspection_ui_batch_v2.py \
  tools/export_http_ui_source.txt \
  tools/http_inspection_ui_capture_model.py \
  tools/http_inspection_ui_models.py \
  tools/http_inspection_ui_state.py \
  tools/http_inspection_ui_tests.py \
  tools/http_inspection_ui_widgets.py \
  tools/inspect_http_capture_ui.txt \
  tools/verify_http_inspection_ui.txt \
  tools/http-inspection-ui.patch.gz.b64.complete \
  tools/http-inspection-ui.patch.gz.b64.part* \
  tools/http-inspection-widgets.patch.gz.b64.part* \
  tools/http-inspection-analyzer-fixes.patch.gz.b64.part* \
  tools/http-inspection-integration-v3.trigger \
  tools/http-inspection-integration-v4.trigger \
  tools/run_http_inspection_integration_v4.sh

git config user.name "FlClash Integration Bot"
git config user.email "actions@users.noreply.github.com"
git add -A
git diff --cached --check
git commit -m "feat(http): expose HTTP/2 streams and bounded payload inspection [http-inspection-integrated]"
git push origin HEAD:feat/http2-stream-capture-policy-20261009
