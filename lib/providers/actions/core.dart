part of '../action.dart';

@Riverpod(keepAlive: true)
class CoreAction extends _$CoreAction {
  CoreController get _core => ref.read(coreHandlerProvider);

  int _requestedRestartRevision = 0;
  Future<bool>? _restartOperation;

  @override
  void build() {}

  void _recordLifecycle({
    required LogbookSeverity severity,
    required String eventType,
    required String title,
    String message = '',
    Map<String, Object?> details = const {},
  }) {
    unawaited(
      ref
          .read(logbookProvider.notifier)
          .record(
            profileId: ref.read(currentProfileIdProvider),
            category: LogbookCategory.core,
            severity: severity,
            eventType: eventType,
            title: title,
            message: message,
            details: details,
          ),
    );
  }

  Future<void> initCore() async {
    final isInit = await _core.isInit;

    final version = ref.read(versionProvider);
    if (!isInit) {
      final res = await _core.init(version);
      commonPrint.log('init result: $res');
    } else {
      await ref.read(proxiesActionProvider.notifier).updateGroups();
    }
  }

  Future<void> startCore() async {
    final startedAt = DateTime.now();
    ref.read(coreStatusProvider.notifier).value = CoreStatus.connecting;
    try {
      final result = await startLifecycle();
      final applied = await _applyLifecycleResult(result);
      _recordLifecycle(
        severity: applied ? LogbookSeverity.success : LogbookSeverity.warning,
        eventType: applied ? 'core.start.completed' : 'core.start.superseded',
        title: applied ? 'core.start.completed' : 'core.start.superseded',
        message:
            '${result.outcome.name} · '
            '${DateTime.now().difference(startedAt).inMilliseconds} ms',
        details: {
          'durationMs': DateTime.now().difference(startedAt).inMilliseconds,
          'outcome': result.outcome.name,
        },
      );
    } catch (error) {
      ref.read(coreStatusProvider.notifier).value = CoreStatus.disconnected;
      _recordLifecycle(
        severity: LogbookSeverity.error,
        eventType: 'core.start.failed',
        title: 'core.start.failed',
        message: compactError(error),
        details: {
          'durationMs': DateTime.now().difference(startedAt).inMilliseconds,
        },
      );
      dialogs.showNotifier(error.toString(), level: MessageLevel.error);
    }
  }

  @protected
  Future<CoreLifecycleResult> startLifecycle() {
    return _core.start();
  }

  @protected
  Future<CoreLifecycleResult> restartLifecycle() {
    return _core.restart();
  }

  // Nothing in lib/ calls CoreController.stop(); only close() (app exit)
  // supersedes a start/restart. statusFirst lets onCrash catch a crash
  // during initCore itself (it early-returns unless status is connected).
  Future<bool> _applyLifecycleResult(
    CoreLifecycleResult result, {
    bool statusFirst = false,
  }) async {
    if (result.outcome == CoreLifecycleOutcome.superseded) {
      return false;
    }
    if (statusFirst) {
      ref.read(coreStatusProvider.notifier).value = CoreStatus.connected;
      await initCore();
    } else {
      await initCore();
      ref.read(coreStatusProvider.notifier).value = CoreStatus.connected;
    }
    return true;
  }

  Future<void> closeConnection(String id) async {
    await _core.closeConnection(id);
  }

  Future<void> closeConnections() async {
    await _core.closeConnections();
  }

  Future<void> requestGc() async {
    await _core.requestGc();
  }

  Future<void> crash() async {
    _recordLifecycle(
      severity: LogbookSeverity.warning,
      eventType: 'core.crash.requested',
      title: 'core.crash.requested',
      message: 'developer-tools',
    );
    await _core.crash();
  }

  Future<bool> restartCore() {
    _requestedRestartRevision++;
    final activeOperation = _restartOperation;
    if (activeOperation != null) {
      return activeOperation;
    }

    final operation = _runRestartWorker();
    _restartOperation = operation;
    return operation;
  }

  Future<bool> _runRestartWorker() async {
    final startedAt = DateTime.now();
    try {
      ref.read(coreStatusProvider.notifier).value = CoreStatus.connecting;
      final result = await restartLifecycle();
      if (!await _applyLifecycleResult(result, statusFirst: true)) {
        return false;
      }

      var appliedRevision = 0;
      var applied = true;
      while (appliedRevision < _requestedRestartRevision) {
        final revision = _requestedRestartRevision;
        if (ref.read(isStartProvider)) {
          applied = await ref
              .read(setupActionProvider.notifier)
              .setRunning(true, initialize: true);
        } else {
          applied = await ref
              .read(setupActionProvider.notifier)
              .applyProfile(force: true);
        }
        appliedRevision = revision;
      }
      _recordLifecycle(
        severity: applied ? LogbookSeverity.success : LogbookSeverity.warning,
        eventType: applied
            ? 'core.restart.completed'
            : 'core.restart.profile-apply-failed',
        title: applied
            ? 'core.restart.completed'
            : 'core.restart.profile-apply-failed',
        message:
            '${DateTime.now().difference(startedAt).inMilliseconds} ms · '
            'revision=$_requestedRestartRevision',
        details: {
          'durationMs': DateTime.now().difference(startedAt).inMilliseconds,
          'requestedRevision': _requestedRestartRevision,
        },
      );
      return applied;
    } catch (error) {
      ref.read(coreStatusProvider.notifier).value = CoreStatus.disconnected;
      _recordLifecycle(
        severity: LogbookSeverity.error,
        eventType: 'core.restart.failed',
        title: 'core.restart.failed',
        message: compactError(error),
        details: {
          'durationMs': DateTime.now().difference(startedAt).inMilliseconds,
        },
      );
      rethrow;
    } finally {
      _restartOperation = null;
    }
  }
}
