import 'dart:io';

const _defaultReport = 'coverage/lcov.info';

const _excludedPatterns = [
  '/generated/',
  'lib/l10n/',
  '.g.dart',
  '.freezed.dart',
];

// Long-term targets never move down. Explicit debts must preserve both
// their percentage and missed-line count, then disappear at the target.
const _groupTargets = <String, double>{
  'core': 76.0,
  'database': 81.0,
  'widgets': 82.0,
  'features': 81.0,
  'models': 67.0,
  'providers': 73.0,
  'common': 74.0,
  'manager': 68.0,
  'views': 66.0,
  'enum': 86.0,
  'pages': 71.0,
  'plugins': 67.0,
  'lib': 20.0,
};
// Captured before this stage: aggregate quick-routing and bootstrap debt.
const _groupDebtRatchets = <String, _CoverageDebtRatchet>{
  'features': _CoverageDebtRatchet(hit: 1476, found: 3292),
  'lib': _CoverageDebtRatchet(hit: 50, found: 322),
};

class _Coverage {
  int found = 0;
  int hit = 0;

  int get missed => found - hit;

  double get percent => found == 0 ? 0 : hit / found * 100;
}

class _CoverageDebtRatchet {
  final int hit;
  final int found;

  const _CoverageDebtRatchet({required this.hit, required this.found});

  int get missed => found - hit;

  double get percent => found == 0 ? 0 : hit / found * 100;

  bool accepts(_Coverage coverage) {
    if (coverage.found == 0 || found == 0) {
      return false;
    }
    final percentageDidNotRegress =
        coverage.hit * found >= hit * coverage.found;
    return percentageDidNotRegress && coverage.missed <= missed;
  }
}

bool _isExcluded(String path) {
  final normalized = path.replaceAll(r'\', '/');
  return _excludedPatterns.any(normalized.contains);
}

String _group(String path) {
  final normalized = path.replaceAll(r'\', '/');
  // Anchor on the project's own `lib/`, which is the last one on the path. The
  // first match is not it whenever the report carries absolute paths and
  // something above the checkout is called `lib` — a clone under `~/dev/lib/`,
  // a pub cache entry — and every file then lands in whatever directory
  // happened to follow that one.
  final int start;
  if (normalized.startsWith('lib/')) {
    start = 4;
  } else {
    final index = normalized.lastIndexOf('/lib/');
    if (index == -1) {
      return 'other';
    }
    start = index + 5;
  }
  final relative = normalized.substring(start);
  final separator = relative.indexOf('/');
  return separator == -1 ? 'lib' : relative.substring(0, separator);
}

void main(List<String> arguments) {
  exitCode = runCoverageCheck(arguments);
}

int runCoverageCheck(
  List<String> arguments, {
  void Function(Object?)? output,
  void Function(Object?)? error,
}) {
  final writeOutput = output ?? stdout.writeln;
  final writeError = error ?? stderr.writeln;
  final reportPath = arguments.isNotEmpty ? arguments.first : _defaultReport;
  var minimum = 0.0;
  if (arguments.length > 1) {
    final parsed = double.tryParse(arguments[1]);
    if (parsed == null) {
      writeError(
        'The total target must be a number, got "${arguments[1]}".\n'
        'Usage: dart run tool/check_coverage.dart [report] [total-target]',
      );
      return 64;
    }
    minimum = parsed;
  }

  final report = File(reportPath);
  if (!report.existsSync()) {
    writeError('Coverage report not found: $reportPath');
    return 1;
  }

  final total = _Coverage();
  final byGroup = <String, _Coverage>{};
  var source = '';
  var excluded = false;

  for (final line in report.readAsLinesSync()) {
    if (line.startsWith('SF:')) {
      source = line.substring(3);
      excluded = _isExcluded(source);
      continue;
    }
    if (excluded || source.isEmpty) {
      continue;
    }
    final group = byGroup.putIfAbsent(_group(source), _Coverage.new);
    if (line.startsWith('LF:')) {
      final found = int.parse(line.substring(3));
      total.found += found;
      group.found += found;
    } else if (line.startsWith('LH:')) {
      final hit = int.parse(line.substring(3));
      total.hit += hit;
      group.hit += hit;
    }
  }

  if (total.found == 0) {
    writeError('No measurable lines in $reportPath after exclusions.');
    return 1;
  }

  final groups = byGroup.entries.toList()
    ..sort((a, b) => b.value.found.compareTo(a.value.found));
  final failures = <String>[];

  for (final debt in _groupDebtRatchets.entries) {
    final target = _groupTargets[debt.key];
    if (target == null) {
      failures.add('${debt.key} has a debt ratchet but no long-term target.');
    } else if (debt.value.found <= 0 ||
        debt.value.hit < 0 ||
        debt.value.hit > debt.value.found ||
        debt.value.percent >= target) {
      failures.add(
        '${debt.key} carries an invalid or already-paid debt ratchet.',
      );
    }
  }

  for (final entry in groups) {
    final coverage = entry.value;
    final target = _groupTargets[entry.key];
    final debt = _groupDebtRatchets[entry.key];
    final belowTarget = target != null && coverage.percent < target;
    final debtAccepted = belowTarget && debt != null && debt.accepts(coverage);
    final failed = belowTarget && !debtAccepted;

    if (failed) {
      if (debt == null) {
        failures.add(
          '${entry.key} ${coverage.percent.toStringAsFixed(2)}% is below its '
          '${target.toStringAsFixed(2)}% target.',
        );
      } else {
        failures.add(
          '${entry.key} regressed past its debt ratchet: '
          '${coverage.percent.toStringAsFixed(2)}% with ${coverage.missed} '
          'missed lines; require at least '
          '${debt.percent.toStringAsFixed(2)}% and at most '
          '${debt.missed} missed lines until the '
          '${target.toStringAsFixed(2)}% target is reached.',
        );
      }
    } else if (!belowTarget && debt != null) {
      failures.add(
        '${entry.key} reached its ${target!.toStringAsFixed(2)}% target; '
        'remove its paid debt ratchet.',
      );
    }

    final guard = switch ((target, debtAccepted ? debt : null)) {
      (null, _) => ' (NO TARGET)',
      (final double value, final _CoverageDebtRatchet ratchet) =>
        ' (target ${value.toStringAsFixed(0)}%; debt >= '
            '${ratchet.percent.toStringAsFixed(1)}%, missed <= '
            '${ratchet.missed}) DEBT',
      (final double value, _) => ' (target ${value.toStringAsFixed(0)}%)',
    };
    writeOutput(
      '${entry.key.padRight(12)} '
      '${coverage.hit.toString().padLeft(6)}/${coverage.found.toString().padLeft(6)} '
      '${coverage.percent.toStringAsFixed(1).padLeft(6)}%$guard'
      '${failed ? ' FAIL' : ''}',
    );
  }
  writeOutput(
    'TOTAL (generated code excluded): '
    '${total.hit}/${total.found} ${total.percent.toStringAsFixed(2)}%',
  );

  final missing = _groupTargets.keys
      .where((group) => !byGroup.containsKey(group))
      .toList();
  for (final group in missing) {
    failures.add('$group has a target but no measured lines in the report.');
  }

  final unguarded = groups
      .map((entry) => entry.key)
      .where((group) => !_groupTargets.containsKey(group))
      .toList();
  for (final group in unguarded) {
    failures.add(
      '$group is measured but has no target in _groupTargets; add one at or '
      'below its current coverage.',
    );
  }

  if (total.percent < minimum) {
    failures.add(
      'TOTAL ${total.percent.toStringAsFixed(2)}% is below the '
      '${minimum.toStringAsFixed(2)}% target.',
    );
  }

  if (failures.isEmpty) {
    return 0;
  }
  for (final failure in failures) {
    writeError(failure);
  }
  return 1;
}
