import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:setup_hooks/src/core_patch.dart';
import 'package:setup_hooks/src/error.dart';
import 'package:test/test.dart';

void main() {
  late Directory root;
  late Directory core;
  late Directory patches;
  late File source;

  ProcessResult git(List<String> arguments) => Process.runSync(
    'git',
    arguments,
    workingDirectory: core.path,
    stdoutEncoding: systemEncoding,
    stderrEncoding: systemEncoding,
  );

  setUp(() {
    root = Directory.systemTemp.createTempSync('setup_core_patch_');
    core = Directory(p.join(root.path, 'core', 'Clash.Meta'))
      ..createSync(recursive: true);
    patches = Directory(p.join(root.path, 'core', 'patches'))
      ..createSync(recursive: true);
    expect(git(['init', '-q']).exitCode, 0);
    expect(git(['config', 'user.name', 'Test']).exitCode, 0);
    expect(git(['config', 'user.email', 'test@example.invalid']).exitCode, 0);
    source = File(p.join(core.path, 'sample.txt'))
      ..writeAsStringSync('before\n');
    expect(git(['add', 'sample.txt']).exitCode, 0);
    expect(git(['commit', '-qm', 'base']).exitCode, 0);

    source.writeAsStringSync('after\n');
    final diff = git(['diff', '--binary', '--full-index']);
    expect(diff.exitCode, 0);
    File(
      p.join(patches.path, '0001-sample.patch'),
    ).writeAsStringSync(diff.stdout as String);
    expect(git(['checkout', '--', 'sample.txt']).exitCode, 0);
  });

  tearDown(() => root.deleteSync(recursive: true));

  test('applies every patch in lexical order', () {
    final inputs = applyCorePatches(rootDir: root.path);

    expect(source.readAsStringSync(), 'after\n');
    expect(inputs, [p.join(patches.path, '0001-sample.patch')]);
  });

  test('is idempotent after the patch is already present', () {
    applyCorePatches(rootDir: root.path);
    final inputs = applyCorePatches(rootDir: root.path);

    expect(source.readAsStringSync(), 'after\n');
    expect(inputs, hasLength(1));
  });

  test('rejects a source tree that matches neither side of the patch', () {
    source.writeAsStringSync('conflict\n');

    expect(
      () => applyCorePatches(rootDir: root.path),
      throwsA(
        isA<BuildException>().having(
          (error) => error.message,
          'message',
          contains('neither applies cleanly nor appears to be present'),
        ),
      ),
    );
  });

  test('does nothing when the patch directory has no patch files', () {
    File(p.join(patches.path, '0001-sample.patch')).deleteSync();

    expect(applyCorePatches(rootDir: root.path), isEmpty);
    expect(source.readAsStringSync(), 'before\n');
  });
}
