import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';

final _fontPath = Platform.environment['FLCLASH_PREVIEW_FONT'] ?? '';
final _outputPath = Platform.environment['FLCLASH_PREVIEW_DIR'] ?? '';

bool get _readablePreview => _fontPath.isNotEmpty && _outputPath.isNotEmpty;

ThemeData? get codePreviewTheme =>
    _readablePreview ? ThemeData(fontFamily: 'FlClashPreview') : null;

Future<void> loadCodePreviewFonts() async {
  if (!_readablePreview) {
    return;
  }
  final loader = FontLoader('FlClashPreview')
    ..addFont(File(_fontPath).readAsBytes().then(ByteData.sublistView));
  await loader.load();
  final flutterRoot = Platform.environment['FLUTTER_ROOT'] ?? '';
  if (flutterRoot.isNotEmpty) {
    final icons = File(
      '$flutterRoot/bin/cache/artifacts/material_fonts/MaterialIcons-Regular.otf',
    );
    if (await icons.exists()) {
      await (FontLoader(
        'MaterialIcons',
      )..addFont(icons.readAsBytes().then(ByteData.sublistView))).load();
    }
  }
  await Directory(_outputPath).create(recursive: true);
}

Matcher matchesCodePreview(String baseline) {
  if (!_readablePreview) {
    return matchesGoldenFile(baseline);
  }
  final name = baseline.split('/').last;
  return matchesGoldenFile(Uri.file('$_outputPath/$name'));
}
