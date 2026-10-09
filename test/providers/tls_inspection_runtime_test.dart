import 'dart:async';

import 'package:fl_clash/core/controller.dart';
import 'package:fl_clash/core/desktop/model.dart';
import 'package:fl_clash/core/interface.dart';
import 'package:fl_clash/core/method.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/app.dart';
import 'package:fl_clash/providers/core.dart';
import 'package:fl_clash/providers/logbook.dart';
import 'package:fl_clash/providers/tls_inspection.dart';
import 'package:fl_clash/providers/tls_inspection_runtime.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:riverpod/riverpod.dart';

const _id = '0123456789abcdef0123456789abcdef';
const _otherId = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const _generation = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const _runtimeProof = 'cccccccccccccccccccccccccccccccc';
const _digest =
    'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd';
const _fingerprint =
    'EE:EE:EE:EE:EE:EE:EE:EE:EE:EE:EE:EE:EE:EE:EE:EE:'
    'EE:EE:EE:EE:EE:EE:EE:EE:EE:EE:EE:EE:EE:EE:EE:EE';
const _password =
    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

late TlsInspectionState _foundationState;

class _FoundationNotifier extends TlsInspectionNotifier {
  @override
  TlsInspectionState build() => _foundationState;

  void replace(TlsInspectionState value) => state = value;

  @override
  Future<void> reload() async {}
}

TlsInspectionState _preparedFoundation() {
  final now = DateTime.now().toUtc();
  final authority = TlsInspectionAuthorityStatus(
    state: 'ready',
    ready: true,
    generation: _generation,
    fingerprintSha256: _fingerprint,
    subject: 'CN=FlClash Local Inspection CA',
    serialNumber: '01',
    notBefore: now.subtract(const Duration(days: 1)),
    notAfter: now.add(const Duration(days: 365)),
    algorithm: 'ECDSA P-256 / SHA-256',
    keyStorage: 'app-data-file',
    keyPermissionsRestricted: true,
    trustState: 'unknown',
    trustCapability: 'manual-only',
    certificateFileName: 'flclash-local-inspection-ca.crt',
  );
  return TlsInspectionState(
    rulesValidated: true,
    authority: authority,
    policy: TlsInspectionPolicy(
      prepared: true,
      acknowledgedRiskVersion: tlsInspectionRiskVersion,
      manuallyTrustedFingerprint: _fingerprint,
      manuallyTrustedAt: now,
      allowlist: const [
        TlsInspectionDomainRule(
          host: 'example.com',
          scope: TlsInspectionRuleScope.subdomains,
        ),
      ],
    ),
    leafCache: TlsInspectionLeafCacheStatus(
      state: 'ready',
      ready: true,
      generation: _generation,
      authorityFingerprintSha256: _fingerprint,
      policyDigest: _digest,
      entryCount: 0,
      capacity: tlsInspectionLeafCacheCapacity,
      leafValiditySeconds: tlsInspectionLeafMaxValidity.inSeconds,
      algorithm: 'ECDSA P-256 / SHA-256',
      keyStorage: 'app-data-file',
      keyPermissionsRestricted: true,
      privateKeysExported: false,
      runtimeAuthorizationPresent: true,
      runtimeProofId: _runtimeProof,
      updatedAt: now,
      contractValid: true,
    ),
  );
}

class _RuntimeCore extends CoreHandlerInterface {
  bool running = false;
  String runningId = '';
  bool stopResult = true;
  int startCalls = 0;
  int stopCalls = 0;
  int statusCalls = 0;
  int accepted = 0;
  Completer<void>? startGate;
  final cancelled = <String>{};
  Map<String, Object?>? lastStartArguments;
  Map<String, Object?>? startResultOverride;

  Map<String, Object?> status() => {
    'runtime': <String, Object?>{
      'id': running ? runningId : '',
      'state': running ? 'running' : 'stopped',
      'address': running ? '127.0.0.1:32000' : '',
      'expiresAt': running
          ? DateTime.now()
                .toUtc()
                .add(const Duration(minutes: 9))
                .toIso8601String()
          : DateTime.fromMillisecondsSinceEpoch(0).toUtc().toIso8601String(),
      'active': 0,
      'accepted': accepted,
      'completed': accepted,
      'failed': 0,
      'uploaded': accepted * 100,
      'downloaded': accepted * 200,
    },
    'generation': running ? _generation : '',
    'authorityFingerprintSha256': running ? _fingerprint : '',
    'policyDigest': running ? _digest : '',
    if (running) 'runtimeProofId': _runtimeProof,
    'mode': 'loopback-connect-http1-h2',
    'capacity': 16,
    'connectionLifetimeSeconds': 120,
    'capturesPayload': false,
    'capturePolicy': TlsInspectionCapturePolicy.metadataOnly.toJson(),
    'changesSystemProxy': false,
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
    final result = switch (method) {
      CoreMethod.getTlsInspectionRuntimeStatus => _readStatus(),
      CoreMethod.startTlsInspectionRuntime => await _startRuntime(arguments),
      CoreMethod.stopTlsInspectionRuntime => _stopRuntime(arguments),
      _ => throw StateError('unexpected method: $method'),
    };
    return result as T?;
  }

  Map<String, Object?> _readStatus() {
    statusCalls++;
    return status();
  }

  Future<Map<String, Object?>> _startRuntime(Object? arguments) async {
    startCalls++;
    final values = Map<String, Object?>.from(arguments! as Map);
    lastStartArguments = values;
    final gate = startGate;
    if (gate != null) {
      await gate.future;
    }
    final id = values['id']! as String;
    if (cancelled.contains(id)) {
      throw const CoreMethodException(
        code: 'runtime_start_cancelled',
        message: 'cancelled',
      );
    }
    running = true;
    runningId = id;
    return startResultOverride ??
        {'status': status(), 'username': 'flclash', 'password': _password};
  }

  bool _stopRuntime(Object? arguments) {
    stopCalls++;
    final id = (arguments! as Map)['id']! as String;
    cancelled.add(id);
    if (!stopResult) {
      return false;
    }
    if (runningId == id) {
      running = false;
      runningId = '';
    }
    return true;
  }
}

ProviderContainer _container(
  _RuntimeCore core, {
  TlsInspectionRuntimeIdentityFactory? identityFactory,
}) {
  _foundationState = _preparedFoundation();
  final container = ProviderContainer(
    overrides: [
      coreHandlerProvider.overrideWithValue(CoreController.scoped(core)),
      tlsInspectionProvider.overrideWith(_FoundationNotifier.new),
      tlsInspectionRuntimeIdentityFactoryProvider.overrideWithValue(
        identityFactory ?? () => _id,
      ),
      tlsInspectionRuntimePollIntervalProvider.overrideWithValue(
        const Duration(hours: 1),
      ),
      logbookPersistenceEnabledProvider.overrideWithValue(false),
    ],
  );
  container.read(coreStatusProvider.notifier).value = CoreStatus.connected;
  addTearDown(container.dispose);
  return container;
}

Future<void> _drain([int turns = 8]) async {
  for (var index = 0; index < turns; index++) {
    await Future<void>.delayed(Duration.zero);
  }
}

void main() {
  test(
    'runtime requires explicit confirmation and prepared foundation',
    () async {
      final core = _RuntimeCore();
      final container = _container(core);
      final notifier = container.read(tlsInspectionRuntimeProvider.notifier);

      await expectLater(
        notifier.start(confirmed: false),
        throwsA(
          isA<TlsInspectionPolicyException>().having(
            (error) => error.code,
            'code',
            'runtime_confirmation_required',
          ),
        ),
      );
      expect(core.startCalls, 0);

      (container.read(tlsInspectionProvider.notifier) as _FoundationNotifier)
          .replace(_foundationState.copyWith(rulesValidated: false));
      await expectLater(
        notifier.start(confirmed: true),
        throwsA(isA<TlsInspectionPolicyException>()),
      );
      expect(core.startCalls, 0);
    },
  );

  test('secure identity failure is reported without calling Core', () async {
    final core = _RuntimeCore();
    final container = _container(
      core,
      identityFactory: () => throw StateError('entropy unavailable'),
    );

    await expectLater(
      container
          .read(tlsInspectionRuntimeProvider.notifier)
          .start(confirmed: true),
      throwsA(
        isA<TlsInspectionPolicyException>().having(
          (error) => error.code,
          'code',
          'runtime_identity_unavailable',
        ),
      ),
    );
    expect(core.startCalls, 0);
    expect(
      container.read(tlsInspectionRuntimeProvider).phase,
      TlsInspectionRuntimePhase.stopped,
    );
  });

  test(
    'start binds runtime proof and keeps credentials out of Logbook',
    () async {
      final core = _RuntimeCore();
      final container = _container(core);
      final notifier = container.read(tlsInspectionRuntimeProvider.notifier);

      final access = await notifier.start(confirmed: true);
      await _drain();

      expect(access.password, _password);
      expect(container.read(tlsInspectionRuntimeProvider).running, isTrue);
      expect(
        core.lastStartArguments,
        containsPair('runtimeProofId', _runtimeProof),
      );
      final encoded = container
          .read(logbookProvider)
          .map((event) => event.toJson().toString())
          .join('\n');
      expect(encoded, isNot(contains(_password)));
      expect(encoded, isNot(contains('password')));
    },
  );

  test(
    'policy change revokes the running relay and clears credentials',
    () async {
      final core = _RuntimeCore();
      final container = _container(core);
      final runtime = container.read(tlsInspectionRuntimeProvider.notifier);
      await runtime.start(confirmed: true);

      (container.read(tlsInspectionProvider.notifier) as _FoundationNotifier)
          .replace(_foundationState.copyWith(rulesValidated: false));
      await _drain(20);

      expect(core.stopCalls, greaterThanOrEqualTo(1));
      expect(container.read(tlsInspectionRuntimeProvider).access, isNull);
      expect(
        container.read(tlsInspectionRuntimeProvider).phase,
        TlsInspectionRuntimePhase.stopped,
      );
    },
  );

  test('Core disconnect immediately clears runtime credentials', () async {
    final core = _RuntimeCore();
    final container = _container(core);
    await container
        .read(tlsInspectionRuntimeProvider.notifier)
        .start(confirmed: true);

    container.read(coreStatusProvider.notifier).value = CoreStatus.disconnected;
    await _drain();

    final state = container.read(tlsInspectionRuntimeProvider);
    expect(state.phase, TlsInspectionRuntimePhase.stopped);
    expect(state.access, isNull);
    expect(state.errorCode, 'core-disconnected');
  });

  test('unconfirmed stop keeps credentials visible for recovery', () async {
    final core = _RuntimeCore();
    final container = _container(core);
    final notifier = container.read(tlsInspectionRuntimeProvider.notifier);
    await notifier.start(confirmed: true);
    core.stopResult = false;

    await expectLater(notifier.stop(), throwsA(isA<Exception>()));

    final state = container.read(tlsInspectionRuntimeProvider);
    expect(state.phase, TlsInspectionRuntimePhase.stopUnconfirmed);
    expect(state.access?.password, _password);
    expect(state.errorCode, 'runtime_stop_unconfirmed');
  });

  test('stop racing a pending start prevents credential publication', () async {
    final core = _RuntimeCore()..startGate = Completer<void>();
    final container = _container(core);
    final notifier = container.read(tlsInspectionRuntimeProvider.notifier);

    final starting = notifier.start(confirmed: true);
    await _drain();
    final stopping = notifier.stop();
    await _drain();
    core.startGate!.complete();

    await expectLater(starting, throwsA(isA<Exception>()));
    await stopping;
    final state = container.read(tlsInspectionRuntimeProvider);
    expect(state.phase, TlsInspectionRuntimePhase.stopped);
    expect(state.access, isNull);
    expect(core.running, isFalse);
  });

  test('repeated start never creates a second Core runtime', () async {
    final core = _RuntimeCore();
    final container = _container(core);
    final notifier = container.read(tlsInspectionRuntimeProvider.notifier);

    await notifier.start(confirmed: true);
    await expectLater(
      notifier.start(confirmed: true),
      throwsA(
        isA<TlsInspectionPolicyException>().having(
          (error) => error.code,
          'code',
          'runtime_already_running',
        ),
      ),
    );

    expect(core.startCalls, 1);
    expect(core.running, isTrue);
  });

  test('Core reconnect stops an orphan without auto restarting it', () async {
    final core = _RuntimeCore();
    final container = _container(core);
    final notifier = container.read(tlsInspectionRuntimeProvider.notifier);
    await notifier.start(confirmed: true);

    container.read(coreStatusProvider.notifier).value = CoreStatus.disconnected;
    await _drain();
    expect(core.startCalls, 1);
    expect(core.running, isTrue);

    container.read(coreStatusProvider.notifier).value = CoreStatus.connected;
    await _drain(16);

    expect(core.startCalls, 1);
    expect(core.stopCalls, greaterThanOrEqualTo(1));
    expect(core.running, isFalse);
    final state = container.read(tlsInspectionRuntimeProvider);
    expect(state.phase, TlsInspectionRuntimePhase.stopped);
    expect(state.access, isNull);
  });

  test(
    'reconcile revokes a running relay without an in-memory owner',
    () async {
      final core = _RuntimeCore()
        ..running = true
        ..runningId = _otherId;
      final container = _container(core);

      await container.read(tlsInspectionRuntimeProvider.notifier).reconcile();
      await _drain();

      expect(core.running, isFalse);
      expect(core.stopCalls, 1);
      expect(
        container.read(tlsInspectionRuntimeProvider).errorCode,
        'runtime_orphaned',
      );
    },
  );

  test(
    'reconcile updates public counters without changing credentials',
    () async {
      final core = _RuntimeCore();
      final container = _container(core);
      final notifier = container.read(tlsInspectionRuntimeProvider.notifier);
      await notifier.start(confirmed: true);
      core.accepted = 3;

      await notifier.reconcile();

      final state = container.read(tlsInspectionRuntimeProvider);
      expect(state.status?.accepted, 3);
      expect(state.status?.downloaded, 600);
      expect(state.access?.password, _password);
    },
  );

  test(
    'authorization loss clears credentials while retaining stop ownership',
    () async {
      final core = _RuntimeCore();
      final container = _container(core);
      final notifier = container.read(tlsInspectionRuntimeProvider.notifier);
      await notifier.start(confirmed: true);
      core.stopResult = false;

      (container.read(tlsInspectionProvider.notifier) as _FoundationNotifier)
          .replace(_foundationState.copyWith(rulesValidated: false));
      await _drain(16);

      final blocked = container.read(tlsInspectionRuntimeProvider);
      expect(blocked.phase, TlsInspectionRuntimePhase.stopUnconfirmed);
      expect(blocked.requestedId, _id);
      expect(blocked.access, isNull);
      expect(core.running, isTrue);

      core.stopResult = true;
      await notifier.reconcile();
      expect(
        container.read(tlsInspectionRuntimeProvider).phase,
        TlsInspectionRuntimePhase.stopped,
      );
      expect(core.running, isFalse);
    },
  );

  test(
    'malformed start with failed cleanup preserves the runtime identity',
    () async {
      final core = _RuntimeCore()
        ..stopResult = false
        ..startResultOverride = {
          'status': _RuntimeCore().status(),
          'username': 'flclash',
          'password': 'bad',
        };
      final container = _container(core);
      final notifier = container.read(tlsInspectionRuntimeProvider.notifier);

      await expectLater(
        notifier.start(confirmed: true),
        throwsA(isA<CoreMethodException>()),
      );
      final blocked = container.read(tlsInspectionRuntimeProvider);
      expect(blocked.phase, TlsInspectionRuntimePhase.stopUnconfirmed);
      expect(blocked.requestedId, _id);
      expect(blocked.access, isNull);
      expect(core.running, isTrue);

      core.stopResult = true;
      await notifier.reconcile();
      expect(core.running, isFalse);
      expect(
        container.read(tlsInspectionRuntimeProvider).phase,
        TlsInspectionRuntimePhase.stopped,
      );
    },
  );
}
