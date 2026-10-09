import 'dart:async';
import 'dart:math';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/core/core.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/app.dart';
import 'package:fl_clash/providers/core.dart';
import 'package:fl_clash/providers/logbook.dart';
import 'package:fl_clash/providers/tls_inspection.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

enum TlsInspectionRuntimePhase {
  stopped,
  starting,
  running,
  stopping,
  stopUnconfirmed,
  unavailable,
}

class TlsInspectionRuntimeState {
  final TlsInspectionRuntimePhase phase;
  final String requestedId;
  final TlsInspectionRuntimeStatus? status;
  final TlsInspectionRuntimeStart? access;
  final String errorCode;
  final int revision;

  const TlsInspectionRuntimeState({
    this.phase = TlsInspectionRuntimePhase.stopped,
    this.requestedId = '',
    this.status,
    this.access,
    this.errorCode = '',
    this.revision = 0,
  });

  TlsInspectionRuntimeState copyWith({
    TlsInspectionRuntimePhase? phase,
    String? requestedId,
    TlsInspectionRuntimeStatus? status,
    bool clearStatus = false,
    TlsInspectionRuntimeStart? access,
    bool clearAccess = false,
    String? errorCode,
    int? revision,
  }) {
    return TlsInspectionRuntimeState(
      phase: phase ?? this.phase,
      requestedId: requestedId ?? this.requestedId,
      status: clearStatus ? null : status ?? this.status,
      access: clearAccess ? null : access ?? this.access,
      errorCode: errorCode ?? this.errorCode,
      revision: revision ?? this.revision,
    );
  }

  bool get running =>
      phase == TlsInspectionRuntimePhase.running &&
      status?.running == true &&
      access != null &&
      access!.status.id == status!.id;

  bool get busy =>
      phase == TlsInspectionRuntimePhase.starting ||
      phase == TlsInspectionRuntimePhase.stopping;
}

typedef TlsInspectionRuntimeIdentityFactory = String Function();

String _newTlsInspectionRuntimeIdentity() {
  final random = Random.secure();
  final buffer = StringBuffer();
  for (var index = 0; index < 16; index++) {
    buffer.write(random.nextInt(256).toRadixString(16).padLeft(2, '0'));
  }
  return buffer.toString();
}

final tlsInspectionRuntimeIdentityFactoryProvider =
    Provider<TlsInspectionRuntimeIdentityFactory>(
      (_) => _newTlsInspectionRuntimeIdentity,
    );

final tlsInspectionRuntimePollIntervalProvider = Provider<Duration>(
  (_) => const Duration(seconds: 2),
);

class TlsInspectionRuntimeNotifier extends Notifier<TlsInspectionRuntimeState> {
  Future<void> _operationTail = Future<void>.value();
  Timer? _pollTimer;
  int _intentRevision = 0;
  bool _desiredRunning = false;

  @override
  TlsInspectionRuntimeState build() {
    ref.onDispose(_cancelPolling);
    ref.listen<CoreStatus>(coreStatusProvider, (previous, next) {
      if (next == CoreStatus.connected) {
        if (previous != CoreStatus.connected) {
          unawaited(reconcile());
        }
        return;
      }
      _intentRevision++;
      _desiredRunning = false;
      _cancelPolling();
      if (!ref.mounted) {
        return;
      }
      state = state.copyWith(
        phase: TlsInspectionRuntimePhase.stopped,
        requestedId: '',
        clearStatus: true,
        clearAccess: true,
        errorCode: 'core-disconnected',
        revision: state.revision + 1,
      );
    });
    ref.listen<TlsInspectionState>(tlsInspectionProvider, (previous, next) {
      final previousKey = previous == null ? '' : _authorizationKey(previous);
      final nextKey = _authorizationKey(next);
      if (previousKey == nextKey ||
          (state.phase == TlsInspectionRuntimePhase.stopped &&
              state.requestedId.isEmpty)) {
        return;
      }
      unawaited(_stopForLifecycle('authorization-changed'));
    });
    return const TlsInspectionRuntimeState();
  }

  Future<void> _stopForLifecycle(String reason) async {
    try {
      await stop(reason: reason);
    } catch (error, stackTrace) {
      commonPrint.log(
        'TLS inspection runtime lifecycle stop was not confirmed: '
        '${compactError(error)}, $stackTrace',
        logLevel: coreFailureLogLevel(error),
      );
    }
  }

  void _scheduleReconcileRetry() {
    _cancelPolling();
    _pollTimer = Timer(ref.read(tlsInspectionRuntimePollIntervalProvider), () {
      _pollTimer = null;
      unawaited(reconcile());
    });
  }

  String _authorizationKey(TlsInspectionState value) {
    if (!value.prepared) {
      return '';
    }
    return [
      value.authority.generation,
      value.authority.fingerprintSha256,
      value.leafCache.policyDigest,
      value.leafCache.runtimeProofId,
    ].join('\u0000');
  }

  Future<T> _serialize<T>(Future<T> Function() action) {
    final completer = Completer<T>();
    _operationTail = _operationTail.catchError((_) {}).then((_) async {
      try {
        completer.complete(await action());
      } catch (error, stackTrace) {
        completer.completeError(error, stackTrace);
      }
    });
    return completer.future;
  }

  void _cancelPolling() {
    _pollTimer?.cancel();
    _pollTimer = null;
  }

  void _schedulePolling() {
    _cancelPolling();
    if (!_desiredRunning || !state.running) {
      return;
    }
    _pollTimer = Timer(ref.read(tlsInspectionRuntimePollIntervalProvider), () {
      _pollTimer = null;
      unawaited(reconcile());
    });
  }

  String _errorCode(Object error) => switch (error) {
    final CoreMethodException value => value.code,
    final TlsInspectionPolicyException value => value.code,
    final FormatException _ => 'runtime_contract_invalid',
    _ => 'runtime_unavailable',
  };

  Future<void> _record({
    required String id,
    required LogbookSeverity severity,
    required String status,
    TlsInspectionRuntimeStatus? runtime,
    String failureKind = '',
  }) async {
    await ref
        .read(logbookProvider.notifier)
        .record(
          category: LogbookCategory.network,
          severity: severity,
          eventType: 'tls.inspection.runtime',
          title: 'tls.inspection.runtime',
          message: status,
          correlationId: id.isEmpty ? 'tls-inspection-runtime' : id,
          details: {
            'status': status,
            'localOnly': true,
            'mode': runtime?.mode ?? 'loopback-connect-http1-h2',
            'capturesPayload': runtime?.capturePolicy.capturesBodies ?? false,
            'capturePolicy':
                (runtime?.capturePolicy ??
                        TlsInspectionCapturePolicy.metadataOnly)
                    .toJson(),
            'changesSystemProxy': false,
            if (runtime != null) ...{
              'active': runtime.active,
              'accepted': runtime.accepted,
              'completed': runtime.completed,
              'failed': runtime.failed,
              'uploaded': runtime.uploaded,
              'downloaded': runtime.downloaded,
            },
            if (failureKind.isNotEmpty) 'failureKind': failureKind,
          },
        );
  }

  Future<TlsInspectionRuntimeStart> start({required bool confirmed}) {
    if (!confirmed) {
      return Future.error(
        const TlsInspectionPolicyException(
          'runtime_confirmation_required',
          'Starting the local HTTPS relay requires explicit confirmation.',
        ),
      );
    }
    final foundation = ref.read(tlsInspectionProvider);
    if (ref.read(coreStatusProvider) != CoreStatus.connected ||
        !foundation.prepared) {
      return Future.error(
        const TlsInspectionPolicyException(
          'runtime_not_authorized',
          'Complete the HTTPS inspection safety requirements first.',
        ),
      );
    }
    if (_desiredRunning || state.busy || state.running) {
      return Future.error(
        const TlsInspectionPolicyException(
          'runtime_already_running',
          'The local HTTPS relay is already starting or running.',
        ),
      );
    }
    String id;
    try {
      id = ref.read(tlsInspectionRuntimeIdentityFactoryProvider)();
    } catch (_) {
      return Future.error(
        const TlsInspectionPolicyException(
          'runtime_identity_unavailable',
          'A secure runtime identity could not be created.',
        ),
      );
    }
    if (!RegExp(r'^[0-9a-f]{32}$').hasMatch(id)) {
      return Future.error(
        const TlsInspectionPolicyException(
          'runtime_identity_unavailable',
          'A secure runtime identity could not be created.',
        ),
      );
    }
    _desiredRunning = true;
    final intent = ++_intentRevision;
    state = state.copyWith(
      phase: TlsInspectionRuntimePhase.starting,
      requestedId: id,
      clearStatus: true,
      clearAccess: true,
      errorCode: '',
      revision: state.revision + 1,
    );
    return _serialize(() => _startNow(id, intent, foundation));
  }

  Future<TlsInspectionRuntimeStart> _startNow(
    String id,
    int intent,
    TlsInspectionState foundation,
  ) async {
    TlsInspectionRuntimeStart? started;
    unawaited(
      _record(id: id, severity: LogbookSeverity.info, status: 'starting'),
    );
    try {
      final core = ref.read(coreHandlerProvider);
      started = await core.startTlsInspectionRuntime(
        id: id,
        confirmed: true,
        authority: foundation.authority,
        cache: foundation.leafCache,
      );
      final status = await core.getTlsInspectionRuntimeStatus();
      final current = ref.read(tlsInspectionProvider);
      final stillDesired =
          _desiredRunning &&
          intent == _intentRevision &&
          current.prepared &&
          started.status.matches(current.authority, current.leafCache, id) &&
          status.matches(current.authority, current.leafCache, id);
      if (!stillDesired) {
        throw const TlsInspectionPolicyException(
          'runtime_start_superseded',
          'The runtime start was superseded by a newer safety state.',
        );
      }
      final access = TlsInspectionRuntimeStart(
        status: status,
        username: started.username,
        password: started.password,
      );
      if (!ref.mounted) {
        throw const TlsInspectionPolicyException(
          'runtime_start_superseded',
          'The runtime owner is no longer available.',
        );
      }
      state = state.copyWith(
        phase: TlsInspectionRuntimePhase.running,
        requestedId: id,
        status: status,
        access: access,
        errorCode: '',
        revision: state.revision + 1,
      );
      _schedulePolling();
      unawaited(
        _record(
          id: id,
          severity: LogbookSeverity.success,
          status: 'running',
          runtime: status,
        ),
      );
      return access;
    } catch (error, stackTrace) {
      final superseded = !_desiredRunning || intent != _intentRevision;
      _desiredRunning = false;
      final cleanup = await _stopIdentityAndConfirm(id);
      commonPrint.log(
        'TLS inspection runtime start failed: '
        '${compactError(error)}, $stackTrace',
        logLevel: superseded ? LogLevel.info : coreFailureLogLevel(error),
      );
      if (ref.mounted && state.requestedId == id) {
        final retainedAccess =
            !cleanup.confirmed && cleanup.status?.id == id && started != null
            ? TlsInspectionRuntimeStart(
                status: cleanup.status!,
                username: started.username,
                password: started.password,
              )
            : null;
        state = state.copyWith(
          phase: cleanup.confirmed
              ? TlsInspectionRuntimePhase.stopped
              : TlsInspectionRuntimePhase.stopUnconfirmed,
          requestedId: cleanup.confirmed ? '' : id,
          status: cleanup.status,
          clearStatus: cleanup.confirmed || cleanup.status == null,
          access: retainedAccess,
          clearAccess: cleanup.confirmed || retainedAccess == null,
          errorCode: cleanup.confirmed
              ? (superseded ? '' : _errorCode(error))
              : 'runtime_stop_unconfirmed',
          revision: state.revision + 1,
        );
        if (!cleanup.confirmed) {
          _scheduleReconcileRetry();
        }
      }
      if (!superseded) {
        unawaited(
          _record(
            id: id,
            severity: cleanup.confirmed
                ? LogbookSeverity.error
                : LogbookSeverity.warning,
            status: cleanup.confirmed ? 'failed' : 'stop-unconfirmed',
            runtime: cleanup.status,
            failureKind: cleanup.confirmed
                ? _errorCode(error)
                : 'runtime_stop_unconfirmed',
          ),
        );
      }
      rethrow;
    }
  }

  Future<({bool confirmed, TlsInspectionRuntimeStatus? status})>
  _stopIdentityAndConfirm(String id) async {
    if (!RegExp(r'^[0-9a-f]{32}$').hasMatch(id) ||
        ref.read(coreStatusProvider) != CoreStatus.connected) {
      return (confirmed: false, status: null);
    }
    final core = ref.read(coreHandlerProvider);
    try {
      await core.stopTlsInspectionRuntime(id);
    } catch (_) {}
    try {
      final current = await core.getTlsInspectionRuntimeStatus();
      return (
        confirmed: !current.running || current.id != id,
        status: current.running ? current : null,
      );
    } catch (_) {
      return (confirmed: false, status: null);
    }
  }

  Future<void> _requestStopIdentity(String id) async {
    if (!RegExp(r'^[0-9a-f]{32}$').hasMatch(id) ||
        ref.read(coreStatusProvider) != CoreStatus.connected) {
      return;
    }
    try {
      await ref.read(coreHandlerProvider).stopTlsInspectionRuntime(id);
    } catch (_) {}
  }

  Future<void> stop({String reason = 'user'}) {
    final id = state.requestedId.isNotEmpty
        ? state.requestedId
        : state.status?.id ?? '';
    _desiredRunning = false;
    final intent = ++_intentRevision;
    _cancelPolling();
    if (id.isNotEmpty && state.phase == TlsInspectionRuntimePhase.starting) {
      unawaited(_requestStopIdentity(id));
    }
    if (state.phase != TlsInspectionRuntimePhase.stopped || id.isNotEmpty) {
      state = state.copyWith(
        phase: TlsInspectionRuntimePhase.stopping,
        clearAccess: reason != 'user',
        errorCode: '',
        revision: state.revision + 1,
      );
    }
    return _serialize(() => _stopNow(id, intent, reason));
  }

  Future<void> _stopNow(String id, int intent, String reason) async {
    var effectiveId = id;
    final previousStatus = state.status;
    try {
      final core = ref.read(coreHandlerProvider);
      if (effectiveId.isEmpty) {
        final current = await core.getTlsInspectionRuntimeStatus();
        effectiveId = current.running ? current.id : '';
      }
      final outcome = effectiveId.isEmpty
          ? (confirmed: true, status: null)
          : await _stopIdentityAndConfirm(effectiveId);
      if (!outcome.confirmed) {
        throw const TlsInspectionPolicyException(
          'runtime_stop_unconfirmed',
          'The local HTTPS relay stop could not be verified.',
        );
      }
      if (!ref.mounted || intent != _intentRevision) {
        return;
      }
      state = state.copyWith(
        phase: TlsInspectionRuntimePhase.stopped,
        requestedId: '',
        clearStatus: true,
        clearAccess: true,
        errorCode: '',
        revision: state.revision + 1,
      );
      if (effectiveId.isNotEmpty) {
        unawaited(
          _record(
            id: effectiveId,
            severity: LogbookSeverity.success,
            status: reason == 'expired' ? 'expired' : 'stopped',
            runtime: previousStatus,
          ),
        );
      }
    } catch (error, stackTrace) {
      commonPrint.log(
        'TLS inspection runtime stop was not confirmed: '
        '${compactError(error)}, $stackTrace',
        logLevel: coreFailureLogLevel(error),
      );
      if (!ref.mounted || intent != _intentRevision) {
        return;
      }
      state = state.copyWith(
        phase: TlsInspectionRuntimePhase.stopUnconfirmed,
        requestedId: effectiveId,
        errorCode: _errorCode(error),
        revision: state.revision + 1,
      );
      unawaited(
        _record(
          id: effectiveId,
          severity: LogbookSeverity.warning,
          status: 'stop-unconfirmed',
          runtime: previousStatus,
          failureKind: _errorCode(error),
        ),
      );
      _scheduleReconcileRetry();
      rethrow;
    }
  }

  Future<void> reconcile() => _serialize(_reconcileNow);

  Future<void> _reconcileNow() async {
    if (ref.read(coreStatusProvider) != CoreStatus.connected) {
      return;
    }
    try {
      final core = ref.read(coreHandlerProvider);
      final runtime = await core.getTlsInspectionRuntimeStatus();
      if (!runtime.running) {
        final previousStatus = state.status;
        final wasActive =
            state.requestedId.isNotEmpty || previousStatus?.running == true;
        final id = state.requestedId;
        _desiredRunning = false;
        _cancelPolling();
        if (ref.mounted) {
          state = state.copyWith(
            phase: TlsInspectionRuntimePhase.stopped,
            requestedId: '',
            clearStatus: true,
            clearAccess: true,
            errorCode: '',
            revision: state.revision + 1,
          );
        }
        if (wasActive && id.isNotEmpty) {
          unawaited(
            _record(
              id: id,
              severity: LogbookSeverity.info,
              status: 'expired',
              runtime: previousStatus,
            ),
          );
        }
        return;
      }
      final foundation = ref.read(tlsInspectionProvider);
      final expectedId = state.requestedId;
      final valid =
          _desiredRunning &&
          expectedId.isNotEmpty &&
          runtime.matches(
            foundation.authority,
            foundation.leafCache,
            expectedId,
          );
      if (!valid) {
        _desiredRunning = false;
        _cancelPolling();
        final cleanup = await _stopIdentityAndConfirm(runtime.id);
        if (ref.mounted) {
          state = state.copyWith(
            phase: cleanup.confirmed
                ? TlsInspectionRuntimePhase.stopped
                : TlsInspectionRuntimePhase.stopUnconfirmed,
            requestedId: cleanup.confirmed ? '' : runtime.id,
            status: cleanup.status,
            clearStatus: cleanup.confirmed || cleanup.status == null,
            clearAccess: true,
            errorCode: cleanup.confirmed
                ? 'runtime_orphaned'
                : 'runtime_stop_unconfirmed',
            revision: state.revision + 1,
          );
          if (!cleanup.confirmed) {
            _scheduleReconcileRetry();
          }
        }
        unawaited(
          _record(
            id: runtime.id,
            severity: LogbookSeverity.warning,
            status: cleanup.confirmed ? 'revoked' : 'stop-unconfirmed',
            runtime: runtime,
            failureKind: cleanup.confirmed
                ? 'runtime_orphaned'
                : 'runtime_stop_unconfirmed',
          ),
        );
        return;
      }
      final access = state.access;
      if (access == null || access.status.id != runtime.id) {
        _desiredRunning = false;
        _cancelPolling();
        final cleanup = await _stopIdentityAndConfirm(runtime.id);
        if (ref.mounted) {
          state = state.copyWith(
            phase: cleanup.confirmed
                ? TlsInspectionRuntimePhase.stopped
                : TlsInspectionRuntimePhase.stopUnconfirmed,
            requestedId: cleanup.confirmed ? '' : runtime.id,
            status: cleanup.status,
            clearStatus: cleanup.confirmed || cleanup.status == null,
            clearAccess: true,
            errorCode: cleanup.confirmed
                ? 'runtime_credentials_unavailable'
                : 'runtime_stop_unconfirmed',
            revision: state.revision + 1,
          );
          if (!cleanup.confirmed) {
            _scheduleReconcileRetry();
          }
        }
        return;
      }
      if (!ref.mounted) {
        return;
      }
      state = state.copyWith(
        phase: TlsInspectionRuntimePhase.running,
        status: runtime,
        access: TlsInspectionRuntimeStart(
          status: runtime,
          username: access.username,
          password: access.password,
        ),
        errorCode: '',
        revision: state.revision + 1,
      );
      _schedulePolling();
    } catch (error, stackTrace) {
      commonPrint.log(
        'TLS inspection runtime status refresh failed: '
        '${compactError(error)}, $stackTrace',
        logLevel: coreFailureLogLevel(error),
      );
      if (!ref.mounted) {
        return;
      }
      state = state.copyWith(
        phase: _desiredRunning
            ? TlsInspectionRuntimePhase.stopUnconfirmed
            : TlsInspectionRuntimePhase.unavailable,
        errorCode: _errorCode(error),
        revision: state.revision + 1,
      );
      if (_desiredRunning) {
        _pollTimer = Timer(
          ref.read(tlsInspectionRuntimePollIntervalProvider),
          () {
            _pollTimer = null;
            unawaited(reconcile());
          },
        );
      }
    }
  }
}

final tlsInspectionRuntimeProvider =
    NotifierProvider<TlsInspectionRuntimeNotifier, TlsInspectionRuntimeState>(
      TlsInspectionRuntimeNotifier.new,
    );
