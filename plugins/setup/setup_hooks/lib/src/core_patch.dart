import 'dart:io';

import 'package:path/path.dart' as p;

import 'error.dart';
import 'util.dart';

/// Applies repository-owned patches to the pinned Mihomo submodule.
///
/// Current patches live directly under `core/patches`. Older patch versions
/// under `core/patches/migrations` are build inputs and can be removed from a
/// dirty source tree before the corresponding current patch is applied.
List<String> applyCorePatches({required String rootDir}) {
  final patchDirectory = Directory(p.join(rootDir, 'core', 'patches'));
  if (!patchDirectory.existsSync()) return const [];

  final patches = _patchFiles(patchDirectory);
  if (patches.isEmpty) return const [];
  final migrationDirectory = Directory(
    p.join(patchDirectory.path, 'migrations'),
  );
  final migrations = migrationDirectory.existsSync()
      ? _patchFiles(migrationDirectory)
      : const <String>[];

  final coreDirectory = Directory(p.join(rootDir, 'core', 'Clash.Meta'));
  if (!coreDirectory.existsSync()) {
    throw BuildException(
      'Mihomo submodule is missing: ${coreDirectory.path}. '
      'Run git submodule update --init --recursive.',
    );
  }

  final lockFile = File(
    p.join(rootDir, '.dart_tool', 'setup_build_cache', 'core-patches.lock'),
  );
  ensureDir(lockFile.parent.path);
  final lock = lockFile.openSync(mode: FileMode.append);
  lock.lockSync(FileLock.exclusive);
  try {
    for (final patch in patches) {
      final stem = p.basenameWithoutExtension(patch);
      final candidates = migrations
          .where(
            (migration) =>
                p.basenameWithoutExtension(migration).startsWith('$stem-'),
          )
          .toList(growable: false);
      _applyPatch(coreDirectory.path, patch, candidates);
    }
  } finally {
    lock.unlockSync();
    lock.closeSync();
  }

  final inputs = <String>[...patches, ...migrations]..sort();
  return List.unmodifiable(inputs);
}

List<String> _patchFiles(Directory directory) {
  final files = directory
      .listSync(followLinks: false)
      .whereType<File>()
      .where((file) => file.path.endsWith('.patch'))
      .map((file) => p.normalize(file.absolute.path))
      .toList();
  files.sort();
  return files;
}

void _applyPatch(String coreDirectory, String patch, List<String> migrations) {
  final check = _gitApply(
    coreDirectory: coreDirectory,
    patch: patch,
    check: true,
  );
  if (check.exitCode == 0) {
    final applied = _gitApply(
      coreDirectory: coreDirectory,
      patch: patch,
      check: false,
    );
    if (applied.exitCode != 0) {
      throw _patchFailure(patch: patch, action: 'apply', result: applied);
    }
    return;
  }

  final reverse = _gitApply(
    coreDirectory: coreDirectory,
    patch: patch,
    check: true,
    reverse: true,
  );
  if (reverse.exitCode == 0) return;

  for (final migration in migrations) {
    final legacyPresent = _gitApply(
      coreDirectory: coreDirectory,
      patch: migration,
      check: true,
      reverse: true,
    );
    if (legacyPresent.exitCode != 0) continue;

    final removed = _gitApply(
      coreDirectory: coreDirectory,
      patch: migration,
      check: false,
      reverse: true,
    );
    if (removed.exitCode != 0) {
      throw _patchFailure(
        patch: migration,
        action: 'remove legacy',
        result: removed,
      );
    }

    final migratedCheck = _gitApply(
      coreDirectory: coreDirectory,
      patch: patch,
      check: true,
    );
    if (migratedCheck.exitCode == 0) {
      final migrated = _gitApply(
        coreDirectory: coreDirectory,
        patch: patch,
        check: false,
      );
      if (migrated.exitCode == 0) return;
      _restoreLegacy(coreDirectory, migration);
      throw _patchFailure(
        patch: patch,
        action: 'apply after migration',
        result: migrated,
      );
    }

    _restoreLegacy(coreDirectory, migration);
  }

  throw BuildException(
    'Core patch ${p.basename(patch)} neither applies cleanly, appears to be '
    'present, nor matches a supported migration. Reset core/Clash.Meta to the '
    'pinned submodule revision and retry.\n'
    'apply check: ${_processDiagnostic(check)}\n'
    'reverse check: ${_processDiagnostic(reverse)}',
  );
}

void _restoreLegacy(String coreDirectory, String migration) {
  final restored = _gitApply(
    coreDirectory: coreDirectory,
    patch: migration,
    check: false,
  );
  if (restored.exitCode != 0) {
    throw _patchFailure(
      patch: migration,
      action: 'restore legacy',
      result: restored,
    );
  }
}

ProcessResult _gitApply({
  required String coreDirectory,
  required String patch,
  required bool check,
  bool reverse = false,
}) {
  return Process.runSync(
    'git',
    [
      'apply',
      if (reverse) '--reverse',
      if (check) '--check',
      '--whitespace=nowarn',
      patch,
    ],
    workingDirectory: coreDirectory,
    stdoutEncoding: systemEncoding,
    stderrEncoding: systemEncoding,
  );
}

BuildException _patchFailure({
  required String patch,
  required String action,
  required ProcessResult result,
}) {
  return BuildException(
    'Could not $action Core patch ${p.basename(patch)}: '
    '${_processDiagnostic(result)}',
  );
}

String _processDiagnostic(ProcessResult result) {
  final stderr = (result.stderr as String).trim();
  final stdout = (result.stdout as String).trim();
  final detail = stderr.isNotEmpty ? stderr : stdout;
  return detail.isEmpty ? 'exit ${result.exitCode}' : detail;
}
