import 'dart:io';

import 'package:path/path.dart' as p;

import 'error.dart';
import 'util.dart';

/// Applies repository-owned patches to the pinned Mihomo submodule.
///
/// The patch set lives in the parent repository so a feature branch never
/// points at a submodule commit that collaborators cannot fetch. Application
/// is idempotent: a patch is applied when possible and accepted as already
/// present only when its reverse check succeeds.
List<String> applyCorePatches({required String rootDir}) {
  final patchDirectory = Directory(p.join(rootDir, 'core', 'patches'));
  if (!patchDirectory.existsSync()) return const [];

  final patches =
      patchDirectory
          .listSync(followLinks: false)
          .whereType<File>()
          .where((file) => file.path.endsWith('.patch'))
          .map((file) => p.normalize(file.absolute.path))
          .toList()
        ..sort();
  if (patches.isEmpty) return const [];

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
      _applyPatch(coreDirectory.path, patch);
    }
  } finally {
    lock.unlockSync();
    lock.closeSync();
  }
  return List.unmodifiable(patches);
}

void _applyPatch(String coreDirectory, String patch) {
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

  throw BuildException(
    'Core patch ${p.basename(patch)} neither applies cleanly nor appears to '
    'be present. Reset core/Clash.Meta to the pinned submodule revision and '
    'retry.\napply check: ${_processDiagnostic(check)}\n'
    'reverse check: ${_processDiagnostic(reverse)}',
  );
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
