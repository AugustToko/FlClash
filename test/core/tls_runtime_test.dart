import 'package:fl_clash/core/controller.dart';
import 'package:fl_clash/core/desktop/model.dart';
import 'package:fl_clash/core/interface.dart';
import 'package:fl_clash/core/method.dart';
import 'package:fl_clash/models/models.dart';
import 'package:flutter_test/flutter_test.dart';

const _id = '0123456789abcdef0123456789abcdef';
const _generation = 'abcdef0123456789abcdef0123456789';
final _fingerprint = List.filled(32, 'AA').join(':');
final _digest = List.filled(64, 'a').join();
const _runtimeProofId = 'fedcba9876543210fedcba9876543210';
final _password = List.filled(64, 'b').join();

Map<String, Object?> _status() => {
  'runtime': <String, Object?>{
    'id': _id,
    'state': 'running',
    'address': '127.0.0.1:32000',
    'expiresAt': DateTime.now()
        .toUtc()
        .add(const Duration(minutes: 9))
        .toIso8601String(),
    'active': 0,
    'accepted': 2,
    'completed': 1,
    'failed': 1,
    'uploaded': 100,
    'downloaded': 200,
  },
  'generation': _generation,
  'authorityFingerprintSha256': _fingerprint,
  'policyDigest': _digest,
  'runtimeProofId': _runtimeProofId,
  'mode': 'loopback-connect-http1',
  'capacity': 16,
  'connectionLifetimeSeconds': 120,
  'capturesPayload': false,
  'changesSystemProxy': false,
};

TlsInspectionAuthorityStatus _authority() => TlsInspectionAuthorityStatus(
  state: 'ready',
  ready: true,
  generation: _generation,
  fingerprintSha256: _fingerprint,
  subject: 'CN=FlClash Local Inspection CA',
  serialNumber: '01',
  notBefore: DateTime.now().toUtc().subtract(const Duration(days: 1)),
  notAfter: DateTime.now().toUtc().add(const Duration(days: 365)),
  algorithm: 'ECDSA P-256 / SHA-256',
  keyStorage: 'app-data-file',
  keyPermissionsRestricted: true,
  trustState: 'unknown',
  trustCapability: 'manual-only',
  certificateFileName: 'flclash-local-inspection-ca.crt',
);

TlsInspectionLeafCacheStatus _cache() => TlsInspectionLeafCacheStatus(
  state: 'ready',
  ready: true,
  generation: _generation,
  authorityFingerprintSha256: _fingerprint,
  policyDigest: _digest,
  entryCount: 0,
  capacity: 64,
  leafValiditySeconds: 86400,
  algorithm: 'ECDSA P-256 / SHA-256',
  keyStorage: 'app-data-file',
  keyPermissionsRestricted: true,
  privateKeysExported: false,
  runtimeAuthorizationPresent: true,
  runtimeProofId: _runtimeProofId,
  updatedAt: DateTime.now().toUtc(),
  contractValid: true,
);

class _RuntimeHandler extends CoreHandlerInterface {
  final calls = <CoreMethodCall>[];
  Map<String, Object?>? startResult;
  bool stopResult = true;
  CoreMethodException? startError;

  _RuntimeHandler()
    : startResult = {
        'status': _status(),
        'username': 'flclash',
        'password': _password,
      };

  @override
  Future<CoreLifecycleResult> start() async => const CoreLifecycleResult(
    revision: 1,
    outcome: CoreLifecycleOutcome.applied,
  );
  @override
  Future<CoreLifecycleResult> restart() => start();
  @override
  Future<CoreLifecycleResult> stop() => start();
  @override
  Future<CoreLifecycleResult> close() => start();

  @override
  Future<T?> invokeMethod<T>({
    required CoreMethod method,
    Object? arguments,
    Duration? timeout,
  }) async {
    calls.add(CoreMethodCall(method: method, arguments: arguments));
    if (method == CoreMethod.startTlsInspectionRuntime && startError != null) {
      throw startError!;
    }
    final Object? result = switch (method) {
      CoreMethod.getTlsInspectionRuntimeStatus => _status(),
      CoreMethod.startTlsInspectionRuntime => startResult,
      CoreMethod.stopTlsInspectionRuntime => stopResult,
      _ => throw StateError('unexpected runtime method'),
    };
    return result as T?;
  }
}

void main() {
  test(
    'runtime status is explicit about loopback mode and binds authorization',
    () {
      final value = TlsInspectionRuntimeStatus.fromJson(_status());
      expect(value.matches(_authority(), _cache(), _id), isTrue);
      expect(value.matches(_authority(), _cache(), _generation), isFalse);
      expect(value.active, 0);
      expect(value.downloaded, 200);
    },
  );

  for (final entry in <String, Object?>{
    'mode': 'transparent-tun',
    'capacity': 16.0,
    'connectionLifetimeSeconds': 120.0,
    'capturesPayload': true,
    'changesSystemProxy': true,
    'generation': '${_generation}00',
    'policyDigest': 'wrong',
    'runtimeProofId': 'wrong',
    'authorityFingerprintSha256': 'bad',
  }.entries) {
    test('runtime status rejects malformed ${entry.key}', () {
      expect(
        () => TlsInspectionRuntimeStatus.fromJson({
          ..._status(),
          entry.key: entry.value,
        }),
        throwsFormatException,
      );
    });
  }

  for (final entry in <String, Object?>{
    'address': '0.0.0.0:32000',
    'id': 'unknown',
    'state': 'unverified',
    'expiresAt': '9999-01-01T00:00:00Z',
    'active': 17,
    'accepted': 3,
    'uploaded': -1,
    'downloaded': '200',
  }.entries) {
    test('runtime state rejects malformed ${entry.key}', () {
      final json = _status();
      json['runtime'] = {
        ...json['runtime'] as Map<String, Object?>,
        entry.key: entry.value,
      };
      expect(
        () => TlsInspectionRuntimeStatus.fromJson(json),
        throwsFormatException,
      );
    });
  }

  test('runtime credentials are bounded and redacted from toString', () {
    final value = TlsInspectionRuntimeStart.fromJson({
      'status': _status(),
      'username': 'flclash',
      'password': _password,
    });
    expect(value.password, _password);
    expect(value.toString(), isNot(contains(_password)));
    for (final password in ['', 'secret', 'b' * 65, 17, null]) {
      expect(
        () => TlsInspectionRuntimeStart.fromJson({
          'status': _status(),
          'username': 'flclash',
          'password': password,
        }),
        throwsFormatException,
      );
    }
  });

  test(
    'runtime starts only with explicit authorization and uses identity-bound stop',
    () async {
      final handler = _RuntimeHandler();
      final core = CoreController.scoped(handler);
      final result = await core.startTlsInspectionRuntime(
        id: _id,
        confirmed: true,
        authority: _authority(),
        cache: _cache(),
      );
      expect(result.status.id, _id);
      expect(handler.calls.single.arguments, {
        'id': _id,
        'confirm': true,
        'authorityGeneration': _generation,
        'authorityFingerprintSha256': _fingerprint,
        'policyDigest': _digest,
        'runtimeProofId': _runtimeProofId,
      });
      expect(await core.stopTlsInspectionRuntime(_id), isTrue);
      expect(handler.calls.last.arguments, {'id': _id});
      expect((await core.getTlsInspectionRuntimeStatus()).running, isTrue);
    },
  );

  test('unconfirmed start does not call Core', () async {
    final handler = _RuntimeHandler();
    await expectLater(
      CoreController.scoped(handler).startTlsInspectionRuntime(
        id: _id,
        confirmed: false,
        authority: _authority(),
        cache: _cache(),
      ),
      throwsA(isA<CoreMethodException>()),
    );
    expect(handler.calls, isEmpty);
  });

  test(
    'invalid or missing start response requests cleanup of its own identity',
    () async {
      for (final result in <Map<String, Object?>?>[
        null,
        {},
        {'status': _status(), 'username': 'flclash', 'password': 'bad'},
      ]) {
        final handler = _RuntimeHandler()..startResult = result;
        await expectLater(
          CoreController.scoped(handler).startTlsInspectionRuntime(
            id: _id,
            confirmed: true,
            authority: _authority(),
            cache: _cache(),
          ),
          throwsA(isA<CoreMethodException>()),
        );
        expect(handler.calls.last.method, CoreMethod.stopTlsInspectionRuntime);
        expect(handler.calls.last.arguments, {'id': _id});
      }
    },
  );

  test(
    'stop does not claim confirmation from an unsuccessful Core response',
    () async {
      final handler = _RuntimeHandler()..stopResult = false;
      expect(
        await CoreController.scoped(handler).stopTlsInspectionRuntime(_id),
        isFalse,
      );
    },
  );
  test(
    'repeated start cannot tear down the already-running identity',
    () async {
      final handler = _RuntimeHandler()
        ..startError = const CoreMethodException(
          code: 'runtime_already_running',
          message: 'already running',
        );
      await expectLater(
        CoreController.scoped(handler).startTlsInspectionRuntime(
          id: _id,
          confirmed: true,
          authority: _authority(),
          cache: _cache(),
        ),
        throwsA(isA<CoreMethodException>()),
      );
      expect(handler.calls.map((call) => call.method), [
        CoreMethod.startTlsInspectionRuntime,
      ]);
    },
  );

  test('runtime observations enforce the privacy-safe capture contract', () {
    final started = DateTime.utc(2026, 10, 7, 2);
    final value = TlsInspectionRuntimeObservation.fromJson({
      'sessionId': 'http-capture:123',
      'connectionId': _id,
      'runtimeId': _generation,
      'host': 'api.example.com',
      'state': 'completed',
      'startedAt': started.toIso8601String(),
      'completedAt': started.add(const Duration(seconds: 1)).toIso8601String(),
      'downstreamTlsVersion': 'TLS 1.3',
      'upstreamTlsVersion': 'TLS 1.2',
      'alpn': 'http/1.1',
      'uploaded': 100,
      'downloaded': 200,
    });
    expect(value.completed, isTrue);
    expect(value.host, 'api.example.com');
    expect(value.toJson(), isNot(containsPair('failureKind', anything)));
    expect(
      TlsInspectionRuntimeObservation.fromJson(value.toJson()).toJson(),
      value.toJson(),
    );
  });

  test('capture interruption is terminal and retains only coarse metadata', () {
    final started = DateTime.utc(2026, 10, 7, 2);
    final running = TlsInspectionRuntimeObservation.fromJson({
      'sessionId': 'http-capture:123',
      'connectionId': _id,
      'runtimeId': _generation,
      'host': 'api.example.com',
      'state': 'running',
      'startedAt': started.toIso8601String(),
      'downstreamTlsVersion': '',
      'upstreamTlsVersion': '',
      'alpn': '',
      'uploaded': 0,
      'downloaded': 0,
    });
    final interrupted = running.interrupt(
      completedAt: started.add(const Duration(seconds: 2)),
      failureKind: 'capture-stopped',
    );
    expect(interrupted.completed, isTrue);
    expect(interrupted.state, 'interrupted');
    expect(interrupted.failureKind, 'capture-stopped');
    expect(
      TlsInspectionRuntimeObservation.fromJson(interrupted.toJson()).toJson(),
      interrupted.toJson(),
    );
    expect(
      running.interrupt(completedAt: started, failureKind: 'upstream-tls'),
      same(running),
    );
  });

  for (final mutation in <String, Object?>{
    'sessionId': 'wrong-session',
    'connectionId': 'bad',
    'runtimeId': 'bad',
    'host': 'https://api.example.com',
    'state': 'unknown',
    'startedAt': 'bad',
    'completedAt': '2020-01-01T00:00:00Z',
    'downstreamTlsVersion': 'TLS 1.1',
    'upstreamTlsVersion': 'TLS 1.4',
    'alpn': 'h2',
    'uploaded': -1,
    'downloaded': '200',
    'failureKind': 'raw error text',
  }.entries) {
    test('runtime observation rejects malformed ${mutation.key}', () {
      final started = DateTime.utc(2026, 10, 7, 2);
      expect(
        () => TlsInspectionRuntimeObservation.fromJson({
          'sessionId': 'http-capture:123',
          'connectionId': _id,
          'runtimeId': _generation,
          'host': 'api.example.com',
          'state': 'completed',
          'startedAt': started.toIso8601String(),
          'completedAt': started
              .add(const Duration(seconds: 1))
              .toIso8601String(),
          'downstreamTlsVersion': 'TLS 1.3',
          'upstreamTlsVersion': 'TLS 1.2',
          'alpn': 'http/1.1',
          'uploaded': 100,
          'downloaded': 200,
          mutation.key: mutation.value,
        }),
        throwsFormatException,
      );
    });
  }
}
