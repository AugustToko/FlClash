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
      'httpRequest': {
        'method': 'GET',
        'target': '/items',
        'version': 'HTTP/1.1',
        'host': 'api.example.com',
        'headerNames': ['host', 'authorization', 'cookie'],
        'headersComplete': true,
      },
      'httpResponse': {
        'version': 'HTTP/1.1',
        'statusCode': 201,
        'informationalStatusCodes': [100],
        'headerNames': ['content-type', 'set-cookie'],
        'headersComplete': true,
        'observedBytes': 128,
        'observedAfterMilliseconds': 25,
      },
    });
    expect(value.completed, isTrue);
    expect(value.host, 'api.example.com');
    expect(value.httpRequest?.target, '/items');
    expect(value.httpResponse?.statusCode, 201);
    expect(value.metadataRank, 3);
    expect(value.toJson(), isNot(containsPair('failureKind', anything)));
    expect(
      TlsInspectionRuntimeObservation.fromJson(value.toJson()).toJson(),
      value.toJson(),
    );
  });

  test('runtime v6 HTTP timeline validates, truncates, and round-trips', () {
    final started = DateTime.utc(2026, 10, 7, 2);
    final value = TlsInspectionRuntimeObservation.fromJson({
      'sessionId': 'http-capture:timeline',
      'connectionId': _id,
      'runtimeId': _generation,
      'host': 'api.example.com',
      'state': 'completed',
      'startedAt': started.toIso8601String(),
      'completedAt': started.add(const Duration(seconds: 1)).toIso8601String(),
      'downstreamTlsVersion': 'TLS 1.3',
      'upstreamTlsVersion': 'TLS 1.3',
      'alpn': 'http/1.1',
      'uploaded': 256,
      'downloaded': 512,
      'httpTransactionsTruncated': true,
      'httpTransactions': [
        {
          'sequence': 1,
          'requestObservedAfterMilliseconds': 4,
          'request': {
            'method': 'GET',
            'target': '/one',
            'version': 'HTTP/1.1',
            'host': 'api.example.com',
            'headerNames': ['host', 'authorization'],
            'headersComplete': true,
          },
          'response': {
            'version': 'HTTP/1.1',
            'statusCode': 200,
            'headerNames': ['content-type'],
            'headersComplete': true,
            'observedBytes': 64,
            'observedAfterMilliseconds': 12,
          },
        },
        {
          'sequence': 2,
          'requestObservedAfterMilliseconds': 18,
          'request': {
            'method': 'POST',
            'target': '/two',
            'version': 'HTTP/1.1',
            'host': 'api.example.com',
            'headerNames': ['host', 'content-length'],
            'headersComplete': true,
          },
        },
      ],
    });
    expect(value.httpTransactions, hasLength(2));
    expect(value.httpTransactions.first.sequence, 1);
    expect(value.httpTransactions.last.request.target, '/two');
    expect(value.httpTransactionsTruncated, isTrue);
    expect(value.httpRequest?.target, '/one');
    expect(value.httpResponse?.statusCode, 200);
    expect(value.metadataRank, 5);
    final encoded = value.toJson();
    expect(encoded, contains('httpTransactions'));
    expect(encoded, containsPair('httpTransactionsTruncated', true));
    expect(encoded, isNot(contains('httpRequest')));
    expect(encoded, isNot(contains('httpResponse')));
    expect(TlsInspectionRuntimeObservation.fromJson(encoded).toJson(), encoded);
  });

  test('runtime v6 timeline rejects malformed correlation', () {
    final started = DateTime.utc(2026, 10, 7, 2);
    Map<String, Object?> base() => {
      'sessionId': 'http-capture:invalid-timeline',
      'connectionId': _id,
      'runtimeId': _generation,
      'host': 'api.example.com',
      'state': 'running',
      'startedAt': started.toIso8601String(),
      'downstreamTlsVersion': 'TLS 1.3',
      'upstreamTlsVersion': 'TLS 1.3',
      'alpn': 'http/1.1',
      'uploaded': 0,
      'downloaded': 0,
    };
    Map<String, Object?> request({
      int sequence = 1,
      int delay = 10,
      String host = 'api.example.com',
      int responseDelay = 20,
      bool includeResponse = true,
      bool hostTruncated = false,
    }) => {
      'sequence': sequence,
      'requestObservedAfterMilliseconds': delay,
      'request': {
        'method': 'GET',
        'target': '/items',
        'version': 'HTTP/1.1',
        'host': host,
        'headersComplete': true,
        if (hostTruncated) 'hostTruncated': true,
      },
      if (includeResponse)
        'response': {
          'version': 'HTTP/1.1',
          'statusCode': 200,
          'headersComplete': true,
          'observedBytes': 64,
          'observedAfterMilliseconds': responseDelay,
        },
    };
    for (final transactions in <List<Map<String, Object?>>>[
      [request(sequence: 2)],
      [request(host: 'other.example.com')],
      [request(host: '', hostTruncated: true)],
      [request(delay: 20, responseDelay: 10)],
      [
        request(sequence: 1, delay: 20, responseDelay: 30),
        request(sequence: 2, delay: 10, responseDelay: 40),
      ],
      [
        request(sequence: 1, includeResponse: false),
        request(sequence: 2, delay: 20, responseDelay: 30),
      ],
      [
        request(sequence: 1, delay: 10, responseDelay: 30),
        request(sequence: 2, delay: 20, responseDelay: 25),
      ],
      [
        for (
          var sequence = 1;
          sequence <= TlsInspectionRuntimeHttpTransaction.maximumCount + 1;
          sequence++
        )
          request(sequence: sequence),
      ],
    ]) {
      expect(
        () => TlsInspectionRuntimeObservation.fromJson({
          ...base(),
          'httpTransactions': transactions,
        }),
        throwsFormatException,
      );
    }
    final cappedTransactions = [
      for (
        var sequence = 1;
        sequence <= TlsInspectionRuntimeHttpTransaction.maximumCount;
        sequence++
      )
        request(sequence: sequence),
    ];
    expect(
      () => TlsInspectionRuntimeObservation.fromJson({
        ...base(),
        'httpTransactions': cappedTransactions,
      }),
      throwsFormatException,
    );
    final capped = TlsInspectionRuntimeObservation.fromJson({
      ...base(),
      'httpTransactions': cappedTransactions,
      'httpTransactionsTruncated': true,
    });
    expect(capped.httpTransactions, hasLength(32));
    expect(capped.httpTransactionsTruncated, isTrue);
    expect(
      () => TlsInspectionRuntimeObservation.fromJson({
        ...base(),
        'httpTransactions': [request()],
        'httpRequest': request()['request'],
      }),
      throwsFormatException,
    );
  });

  test('runtime v6 timeline rejects events after connection completion', () {
    final started = DateTime.utc(2026, 10, 7, 2);
    expect(
      () => TlsInspectionRuntimeObservation.fromJson({
        'sessionId': 'http-capture:late-timeline',
        'connectionId': _id,
        'runtimeId': _generation,
        'host': 'api.example.com',
        'state': 'completed',
        'startedAt': started.toIso8601String(),
        'completedAt': started
            .add(const Duration(milliseconds: 50))
            .toIso8601String(),
        'downstreamTlsVersion': 'TLS 1.3',
        'upstreamTlsVersion': 'TLS 1.3',
        'alpn': 'http/1.1',
        'uploaded': 0,
        'downloaded': 0,
        'httpTransactions': [
          {
            'sequence': 1,
            'requestObservedAfterMilliseconds': 60,
            'request': {
              'method': 'GET',
              'target': '/late',
              'version': 'HTTP/1.1',
              'host': 'api.example.com',
              'headersComplete': true,
            },
          },
        ],
      }),
      throwsFormatException,
    );
  });

  test('HTTP/1 metadata remains valid when TLS negotiates no ALPN', () {
    final started = DateTime.utc(2026, 10, 7, 2);
    final value = TlsInspectionRuntimeObservation.fromJson({
      'sessionId': 'http-capture:no-alpn',
      'connectionId': _id,
      'runtimeId': _generation,
      'host': 'api.example.com',
      'state': 'running',
      'startedAt': started.toIso8601String(),
      'downstreamTlsVersion': 'TLS 1.3',
      'upstreamTlsVersion': 'TLS 1.3',
      'uploaded': 64,
      'downloaded': 0,
      'httpRequest': {
        'method': 'GET',
        'target': '/fallback',
        'version': 'HTTP/1.1',
        'host': 'api.example.com',
        'headerNames': ['host'],
        'headersComplete': true,
      },
    });
    expect(value.alpn, isEmpty);
    expect(value.httpRequest?.target, '/fallback');
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
      'downstreamTlsVersion': 'TLS 1.3',
      'upstreamTlsVersion': 'TLS 1.3',
      'alpn': 'http/1.1',
      'uploaded': 0,
      'downloaded': 0,
      'httpRequest': {
        'method': 'GET',
        'target': '/items',
        'version': 'HTTP/1.1',
        'host': 'api.example.com',
        'headerNames': ['host'],
        'headersComplete': true,
      },
    });
    final interrupted = running.interrupt(
      completedAt: started.add(const Duration(seconds: 2)),
      failureKind: 'capture-stopped',
    );
    expect(interrupted.completed, isTrue);
    expect(interrupted.state, 'interrupted');
    expect(interrupted.failureKind, 'capture-stopped');
    expect(interrupted.httpRequest?.target, '/items');
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

  test('runtime merge never splices an incompatible transaction suffix', () {
    final started = DateTime.utc(2026, 10, 7, 2);
    Map<String, Object?> observation({
      required String firstTarget,
      required List<Map<String, Object?>> transactions,
    }) => {
      'sessionId': 'http-capture:merge-conflict',
      'connectionId': _id,
      'runtimeId': _generation,
      'host': 'api.example.com',
      'state': 'running',
      'startedAt': started.toIso8601String(),
      'downstreamTlsVersion': 'TLS 1.3',
      'upstreamTlsVersion': 'TLS 1.3',
      'alpn': 'http/1.1',
      'uploaded': 0,
      'downloaded': 0,
      'httpTransactions': transactions,
    };
    Map<String, Object?> transaction(int sequence, String target) => {
      'sequence': sequence,
      'requestObservedAfterMilliseconds': sequence * 5,
      'request': {
        'method': 'GET',
        'target': target,
        'version': 'HTTP/1.1',
        'host': 'api.example.com',
        'headersComplete': true,
      },
    };
    final current = TlsInspectionRuntimeObservation.fromJson(
      observation(
        firstTarget: '/current',
        transactions: [transaction(1, '/current')],
      ),
    );
    final incompatibleLonger = TlsInspectionRuntimeObservation.fromJson(
      observation(
        firstTarget: '/incoming',
        transactions: [
          transaction(1, '/incoming'),
          transaction(2, '/must-not-splice'),
        ],
      ),
    );
    final merged = current.merge(incompatibleLonger);
    expect(merged.httpTransactions, hasLength(1));
    expect(merged.httpTransactions.single.request.target, '/current');
    expect(merged.httpTransactionsTruncated, isTrue);
  });

  test('runtime merge keeps a timeline anchored to one start time', () {
    final currentStart = DateTime.utc(2026, 10, 7, 2);
    final incomingStart = currentStart.add(const Duration(seconds: 1));
    Map<String, Object?> transaction(int sequence, String target) => {
      'sequence': sequence,
      'requestObservedAfterMilliseconds': sequence * 5,
      'request': {
        'method': 'GET',
        'target': target,
        'version': 'HTTP/1.1',
        'host': 'api.example.com',
        'headersComplete': true,
      },
    };
    TlsInspectionRuntimeObservation value(
      DateTime startedAt,
      List<Map<String, Object?>> transactions,
    ) => TlsInspectionRuntimeObservation.fromJson({
      'sessionId': 'http-capture:start-conflict',
      'connectionId': _id,
      'runtimeId': _generation,
      'host': 'api.example.com',
      'state': 'running',
      'startedAt': startedAt.toIso8601String(),
      'downstreamTlsVersion': 'TLS 1.3',
      'upstreamTlsVersion': 'TLS 1.3',
      'alpn': 'http/1.1',
      'uploaded': 0,
      'downloaded': 0,
      'httpTransactions': transactions,
    });
    final current = value(currentStart, [transaction(1, '/current')]);
    final incoming = value(incomingStart, [
      transaction(1, '/current'),
      transaction(2, '/must-not-splice'),
    ]);
    final merged = current.merge(incoming);
    expect(merged.startedAt, currentStart);
    expect(merged.httpTransactions, hasLength(1));
    expect(merged.httpTransactions.single.request.target, '/current');
    expect(merged.httpTransactionsTruncated, isTrue);
    expect(
      TlsInspectionRuntimeObservation.fromJson(merged.toJson()).toJson(),
      merged.toJson(),
    );
  });

  test('runtime terminal merge rejects metadata beyond completion', () {
    final started = DateTime.utc(2026, 10, 7, 2);
    Map<String, Object?> transaction(
      int sequence,
      String target,
      int requestAfter,
      int responseAfter,
    ) => {
      'sequence': sequence,
      'requestObservedAfterMilliseconds': requestAfter,
      'request': {
        'method': 'GET',
        'target': target,
        'version': 'HTTP/1.1',
        'host': 'api.example.com',
        'headersComplete': true,
      },
      'response': {
        'version': 'HTTP/1.1',
        'statusCode': 200,
        'headersComplete': true,
        'observedBytes': 64,
        'observedAfterMilliseconds': responseAfter,
      },
    };
    TlsInspectionRuntimeObservation value({
      required String state,
      DateTime? completedAt,
      required int uploaded,
      required int downloaded,
      required List<Map<String, Object?>> transactions,
    }) => TlsInspectionRuntimeObservation.fromJson({
      'sessionId': 'http-capture:terminal-boundary',
      'connectionId': _id,
      'runtimeId': _generation,
      'host': 'api.example.com',
      'state': state,
      'startedAt': started.toIso8601String(),
      if (completedAt != null) 'completedAt': completedAt.toIso8601String(),
      'downstreamTlsVersion': 'TLS 1.3',
      'upstreamTlsVersion': 'TLS 1.3',
      'alpn': 'http/1.1',
      'uploaded': uploaded,
      'downloaded': downloaded,
      'httpTransactions': transactions,
    });
    final terminal = value(
      state: 'completed',
      completedAt: started.add(const Duration(milliseconds: 100)),
      uploaded: 128,
      downloaded: 256,
      transactions: [transaction(1, '/first', 10, 20)],
    );
    final lateRunning = value(
      state: 'running',
      uploaded: 999,
      downloaded: 999,
      transactions: [
        transaction(1, '/first', 10, 20),
        transaction(2, '/after-completion', 150, 160),
      ],
    );
    final merged = terminal.merge(lateRunning);
    expect(merged.state, 'completed');
    expect(merged.completedAt, terminal.completedAt);
    expect(merged.uploaded, 128);
    expect(merged.downloaded, 256);
    expect(merged.httpTransactions, hasLength(1));
    expect(merged.httpTransactions.single.request.target, '/first');
    expect(merged.httpTransactionsTruncated, isTrue);
    expect(
      TlsInspectionRuntimeObservation.fromJson(merged.toJson()).toJson(),
      merged.toJson(),
    );
  });

  test('runtime merge preserves response truncation evidence', () {
    final started = DateTime.utc(2026, 10, 7, 2);
    TlsInspectionRuntimeObservation value({
      required bool complete,
      required bool truncated,
      required bool headerNamesTruncated,
      required bool informationalTruncated,
      required int observedBytes,
      required int observedAfter,
      required List<String> headerNames,
    }) => TlsInspectionRuntimeObservation.fromJson({
      'sessionId': 'http-capture:response-flags',
      'connectionId': _id,
      'runtimeId': _generation,
      'host': 'api.example.com',
      'state': 'running',
      'startedAt': started.toIso8601String(),
      'downstreamTlsVersion': 'TLS 1.3',
      'upstreamTlsVersion': 'TLS 1.3',
      'alpn': 'http/1.1',
      'uploaded': 0,
      'downloaded': 0,
      'httpTransactions': [
        {
          'sequence': 1,
          'requestObservedAfterMilliseconds': 5,
          'request': {
            'method': 'GET',
            'target': '/items',
            'version': 'HTTP/1.1',
            'host': 'api.example.com',
            'headersComplete': true,
          },
          'response': {
            'version': 'HTTP/1.1',
            'statusCode': 200,
            'informationalStatusCodes': [103],
            'headerNames': headerNames,
            'headersComplete': complete,
            'observedBytes': observedBytes,
            'observedAfterMilliseconds': observedAfter,
            'truncated': truncated,
            'headerNamesTruncated': headerNamesTruncated,
            'informationalStatusCodesTruncated': informationalTruncated,
          },
        },
      ],
    });
    final complete = value(
      complete: true,
      truncated: false,
      headerNamesTruncated: false,
      informationalTruncated: false,
      observedBytes: 64,
      observedAfter: 20,
      headerNames: const ['content-type'],
    );
    final bounded = value(
      complete: false,
      truncated: true,
      headerNamesTruncated: true,
      informationalTruncated: true,
      observedBytes: 128,
      observedAfter: 18,
      headerNames: const ['content-type', 'x-request-id'],
    );
    final response = complete.merge(bounded).httpTransactions.single.response!;
    expect(response.headersComplete, isTrue);
    expect(response.truncated, isTrue);
    expect(response.headerNamesTruncated, isTrue);
    expect(response.informationalStatusCodesTruncated, isTrue);
    expect(response.observedBytes, 128);
    expect(response.observedAfterMilliseconds, 18);
    expect(response.headerNames, ['content-type']);
  });

  test('runtime merge keeps an existing response when identity conflicts', () {
    final started = DateTime.utc(2026, 10, 7, 2);
    TlsInspectionRuntimeObservation value(int statusCode) =>
        TlsInspectionRuntimeObservation.fromJson({
          'sessionId': 'http-capture:response-conflict',
          'connectionId': _id,
          'runtimeId': _generation,
          'host': 'api.example.com',
          'state': 'running',
          'startedAt': started.toIso8601String(),
          'downstreamTlsVersion': 'TLS 1.3',
          'upstreamTlsVersion': 'TLS 1.3',
          'alpn': 'http/1.1',
          'uploaded': 0,
          'downloaded': 0,
          'httpTransactions': [
            {
              'sequence': 1,
              'requestObservedAfterMilliseconds': 5,
              'request': {
                'method': 'GET',
                'target': '/items',
                'version': 'HTTP/1.1',
                'host': 'api.example.com',
                'headersComplete': true,
              },
              'response': {
                'version': 'HTTP/1.1',
                'statusCode': statusCode,
                'headersComplete': true,
                'observedBytes': 64,
                'observedAfterMilliseconds': 10,
              },
            },
          ],
        });
    final merged = value(200).merge(value(500));
    expect(merged.httpTransactions.single.response?.statusCode, 200);
    expect(merged.httpTransactionsTruncated, isTrue);
    expect(
      TlsInspectionRuntimeObservation.fromJson(merged.toJson()).toJson(),
      merged.toJson(),
    );
  });

  test(
    'runtime observation merges terminal state with richer HTTP metadata',
    () {
      final started = DateTime.utc(2026, 10, 7, 2);
      final running = TlsInspectionRuntimeObservation.fromJson({
        'sessionId': 'http-capture:merge',
        'connectionId': _id,
        'runtimeId': _generation,
        'host': 'api.example.com',
        'state': 'running',
        'startedAt': started.toIso8601String(),
        'downstreamTlsVersion': 'TLS 1.3',
        'upstreamTlsVersion': 'TLS 1.3',
        'alpn': 'http/1.1',
        'uploaded': 0,
        'downloaded': 0,
        'httpRequest': {
          'method': 'GET',
          'target': '/items',
          'version': 'HTTP/1.1',
          'host': 'api.example.com',
          'headerNames': ['host', 'authorization'],
          'headersComplete': true,
        },
        'httpResponse': {
          'version': 'HTTP/1.1',
          'statusCode': 200,
          'headerNames': ['content-type'],
          'headersComplete': true,
          'observedBytes': 64,
        },
      });
      final completed = TlsInspectionRuntimeObservation.fromJson({
        'sessionId': 'http-capture:merge',
        'connectionId': _id,
        'runtimeId': _generation,
        'host': 'api.example.com',
        'state': 'completed',
        'startedAt': started.toIso8601String(),
        'completedAt': started
            .add(const Duration(seconds: 1))
            .toIso8601String(),
        'downstreamTlsVersion': 'TLS 1.3',
        'upstreamTlsVersion': 'TLS 1.3',
        'alpn': 'http/1.1',
        'uploaded': 128,
        'downloaded': 256,
      });
      final merged = completed.merge(running);
      expect(merged.state, 'completed');
      expect(merged.httpRequest?.target, '/items');
      expect(merged.httpResponse?.statusCode, 200);
      expect(merged.uploaded, 128);
      expect(merged.downloaded, 256);
      expect(merged.failureKind, isEmpty);
    },
  );

  for (final invalid in <String, Object?>{
    'response without request': {
      'httpResponse': {
        'version': 'HTTP/1.1',
        'statusCode': 200,
        'headersComplete': true,
        'observedBytes': 64,
      },
    },
    'HTTP metadata without TLS relay evidence': {
      'downstreamTlsVersion': '',
      'upstreamTlsVersion': '',
      'alpn': '',
      'httpRequest': {
        'method': 'GET',
        'target': '/items',
        'version': 'HTTP/1.1',
        'headersComplete': true,
      },
    },
    'unknown response without informational status': {
      'httpRequest': {
        'method': 'GET',
        'target': '/items',
        'version': 'HTTP/1.1',
        'headersComplete': true,
      },
      'httpResponse': {
        'version': '',
        'statusCode': 0,
        'headersComplete': false,
        'observedBytes': 64,
        'truncated': true,
      },
    },
    'unknown response without truncation': {
      'httpRequest': {
        'method': 'GET',
        'target': '/items',
        'version': 'HTTP/1.1',
        'headersComplete': true,
      },
      'httpResponse': {
        'version': '',
        'statusCode': 0,
        'informationalStatusCodes': [100],
        'headersComplete': false,
        'observedBytes': 64,
        'truncated': false,
      },
    },
    'request query': {
      'httpRequest': {
        'method': 'GET',
        'target': '/items?secret=value',
        'version': 'HTTP/1.1',
        'headersComplete': true,
      },
    },
    'request header case': {
      'httpRequest': {
        'method': 'GET',
        'target': '/items',
        'version': 'HTTP/1.1',
        'headerNames': ['Authorization'],
        'headersComplete': true,
      },
    },
    'response informational final status': {
      'httpResponse': {
        'version': 'HTTP/1.1',
        'statusCode': 100,
        'headersComplete': true,
        'observedBytes': 64,
      },
    },
    'response byte overflow': {
      'httpResponse': {
        'version': 'HTTP/1.1',
        'statusCode': 200,
        'headersComplete': true,
        'observedBytes': 32769,
      },
    },
  }.entries) {
    test('runtime observation rejects malformed ${invalid.key}', () {
      final started = DateTime.utc(2026, 10, 7, 2);
      expect(
        () => TlsInspectionRuntimeObservation.fromJson({
          'sessionId': 'http-capture:invalid-http',
          'connectionId': _id,
          'runtimeId': _generation,
          'host': 'api.example.com',
          'state': 'running',
          'startedAt': started.toIso8601String(),
          'downstreamTlsVersion': 'TLS 1.3',
          'upstreamTlsVersion': 'TLS 1.3',
          'alpn': 'http/1.1',
          'uploaded': 0,
          'downloaded': 0,
          ...invalid.value! as Map<String, Object?>,
        }),
        throwsFormatException,
      );
    });
  }
}
