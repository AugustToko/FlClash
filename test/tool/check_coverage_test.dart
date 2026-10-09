import 'dart:io';

import 'package:test/test.dart';

import '../../tool/check_coverage.dart' as coverage;

const _groups = <String>[
  'core',
  'database',
  'widgets',
  'features',
  'models',
  'providers',
  'common',
  'manager',
  'views',
  'enum',
  'pages',
  'plugins',
  'lib',
];

typedef _LineCoverage = ({int hit, int found});

Map<String, _LineCoverage> _passingCoverage() => {
  for (final group in _groups)
    group: group == 'features'
        ? (hit: 1476, found: 3292)
        : group == 'lib'
        ? (hit: 50, found: 322)
        : (hit: 500, found: 500),
};

String _sourceFor(String group) =>
    group == 'lib' ? 'lib/application.dart' : 'lib/$group/sample.dart';

String _lcov(Map<String, _LineCoverage> values) {
  final output = StringBuffer();
  for (final entry in values.entries) {
    output
      ..writeln('SF:${_sourceFor(entry.key)}')
      ..writeln('LF:${entry.value.found}')
      ..writeln('LH:${entry.value.hit}')
      ..writeln('end_of_record');
  }
  return output.toString();
}

({int code, String stdout, String stderr}) _check(
  File report, {
  String totalTarget = '75',
}) {
  final stdout = StringBuffer();
  final stderr = StringBuffer();
  final code = coverage.runCoverageCheck(
    [report.path, totalTarget],
    output: stdout.writeln,
    error: stderr.writeln,
  );
  return (code: code, stdout: stdout.toString(), stderr: stderr.toString());
}

void main() {
  late Directory temporary;
  late File report;

  setUp(() {
    temporary = Directory.systemTemp.createTempSync('flclash-coverage-');
    report = File('${temporary.path}/lcov.info');
  });

  tearDown(() {
    temporary.deleteSync(recursive: true);
  });

  test('explicit debt ratchets pass without lowering long-term targets', () {
    report.writeAsStringSync(_lcov(_passingCoverage()));

    final result = _check(report);

    expect(result.code, 0, reason: result.stderr);
    expect(result.stdout, contains('target 81%; debt >= 44.8%'));
    expect(result.stdout, contains('target 20%; debt >= 15.5%'));
    expect(result.stdout, contains('TOTAL'));
  });

  test('a debt percentage regression fails the group gate', () {
    final values = _passingCoverage()..['features'] = (hit: 1475, found: 3292);
    report.writeAsStringSync(_lcov(values));

    final result = _check(report, totalTarget: '0');

    expect(result.code, 1);
    expect(result.stderr, contains('features regressed past its debt ratchet'));
  });

  test('extra missed lines fail even when the debt percentage improves', () {
    final values = _passingCoverage()..['features'] = (hit: 1800, found: 4000);
    report.writeAsStringSync(_lcov(values));

    final result = _check(report, totalTarget: '0');

    expect(result.code, 1);
    expect(result.stderr, contains('at most 1816 missed lines'));
  });

  test('a paid debt must be removed instead of becoming permanent', () {
    final values = _passingCoverage()..['features'] = (hit: 82, found: 100);
    report.writeAsStringSync(_lcov(values));

    final result = _check(report, totalTarget: '0');

    expect(result.code, 1);
    expect(result.stderr, contains('reached its 81.00% target'));
    expect(result.stderr, contains('remove its paid debt ratchet'));
  });

  test('the repository-wide target remains independently enforced', () {
    report.writeAsStringSync(_lcov(_passingCoverage()));

    final result = _check(report, totalTarget: '99');

    expect(result.code, 1);
    expect(result.stderr, contains('TOTAL'));
    expect(result.stderr, contains('below the 99.00% target'));
  });
}
