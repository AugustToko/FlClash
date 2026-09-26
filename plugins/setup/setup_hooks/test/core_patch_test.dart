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

  test('upgrades a tree with a legacy patch already applied', () {
    final currentPatch = File(p.join(patches.path, '0001-sample.patch'));
    final migrationDirectory = Directory(p.join(patches.path, 'migrations'))
      ..createSync();
    final migrationPatch = File(
      p.join(migrationDirectory.path, '0001-sample-v1.patch'),
    );

    source.writeAsStringSync('legacy\n');
    final legacyDiff = git(['diff', '--binary', '--full-index']);
    expect(legacyDiff.exitCode, 0);
    migrationPatch.writeAsStringSync(legacyDiff.stdout as String);
    expect(git(['checkout', '--', 'sample.txt']).exitCode, 0);

    source.writeAsStringSync('after-v2\n');
    final currentDiff = git(['diff', '--binary', '--full-index']);
    expect(currentDiff.exitCode, 0);
    currentPatch.writeAsStringSync(currentDiff.stdout as String);
    expect(git(['checkout', '--', 'sample.txt']).exitCode, 0);
    expect(git(['apply', migrationPatch.path]).exitCode, 0);

    final inputs = applyCorePatches(rootDir: root.path);
    final repeated = applyCorePatches(rootDir: root.path);

    expect(source.readAsStringSync(), 'after-v2\n');
    expect(inputs, [currentPatch.absolute.path, migrationPatch.absolute.path]);
    expect(repeated, inputs);
  });

  test('rejects a source tree that matches neither side of the patch', () {
    source.writeAsStringSync('conflict\n');

    expect(
      () => applyCorePatches(rootDir: root.path),
      throwsA(
        isA<BuildException>().having(
          (error) => error.message,
          'message',
          contains('nor matches a supported migration'),
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
