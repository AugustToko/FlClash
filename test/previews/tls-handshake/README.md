# Readable TLS safety previews

These files are real Flutter Widget renders using fixture data. They are not device screenshots, live traffic recordings, or generated UI mockups. The GIF contains independent ready, successful, and failed test scenarios.

The optional font mode does not change the default deterministic CI Goldens. It loads a locally supplied CJK font at runtime; no font files are distributed here.

Regenerate with a local Flutter SDK and a locally licensed CJK font:

```sh
FLCLASH_PREVIEW_FONT=/path/to/NotoSansCJK-Regular.ttc \
FLCLASH_PREVIEW_DIR="$PWD/build/readable-previews" \
FLUTTER_ROOT=/path/to/flutter \
flutter test --no-pub --concurrency=1 --update-goldens \
  test/views/tls_handshake_preview_test.dart \
  test/views/tls_inspection_preview_test.dart
```

Default CI baselines remain in `test/goldens/`. Human-readable previews are not used to approve network, trust-store, or platform behavior. The self-test only validates an in-memory TLS 1.2/1.3 exchange using the currently authorized local leaf certificate.
