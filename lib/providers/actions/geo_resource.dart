part of '../action.dart';

@Riverpod(keepAlive: true)
class GeoResourceAction extends _$GeoResourceAction {
  final _manualUpdates = <GeoResource>{};
  final _manualStartedAt = <GeoResource, DateTime>{};
  final _manualCorrelationIds = <GeoResource, String>{};
  final _operations = <GeoResource, int>{};

  CoreController get _core => ref.read(coreHandlerProvider);

  @override
  void build() {
    ref.listen(coreStatusProvider, (_, next) {
      if (next != CoreStatus.connected) {
        _manualUpdates.clear();
        _manualStartedAt.clear();
        _manualCorrelationIds.clear();
        _operations.clear();
      }
    });
  }

  int _startUpdating(GeoResource geoResource) {
    return _operations.putIfAbsent(
      geoResource,
      () => ref
          .read(updatingKeysProvider.notifier)
          .start(geoResource.updatingKey, scope: UpdatingScope.core),
    );
  }

  void _stopUpdating(GeoResource geoResource, [int? operation]) {
    final current = _operations[geoResource];
    if (current == null || (operation != null && current != operation)) {
      return;
    }
    _operations.remove(geoResource);
    ref
        .read(updatingKeysProvider.notifier)
        .stop(geoResource.updatingKey, current);
  }

  void _recordGeoOperation({
    required GeoResource geoResource,
    required String status,
    required DateTime startedAt,
    required bool manual,
    String correlationId = '',
    String? failureKind,
  }) {
    final durationMs = DateTime.now().difference(startedAt).inMilliseconds;
    final severity = switch (status) {
      'completed' => LogbookSeverity.success,
      'failed' => LogbookSeverity.error,
      _ => LogbookSeverity.info,
    };
    unawaited(
      ref
          .read(logbookProvider.notifier)
          .record(
            category: LogbookCategory.provider,
            severity: severity,
            eventType: 'provider.geo.update',
            title: 'provider.geo.update',
            message: '${geoResource.name} · $durationMs ms',
            correlationId: correlationId,
            details: {
              'status': status,
              'resource': geoResource.name,
              'manual': manual,
              'durationMs': durationMs,
              'failureKind': ?failureKind,
            },
          ),
    );
  }

  /// Completes once the Core has accepted the update, not once it finishes.
  /// Completion arrives as a geo-update event through [handleCoreUpdate];
  /// callers that need it watch [isUpdatingProvider] for the key to clear.
  Future<void> updateGeoResource(GeoResource geoResource) async {
    _manualUpdates.add(geoResource);
    final startedAt = _manualStartedAt.putIfAbsent(geoResource, DateTime.now);
    final correlationId = _manualCorrelationIds.putIfAbsent(
      geoResource,
      () => '${geoResource.name}:${startedAt.microsecondsSinceEpoch}',
    );
    _recordGeoOperation(
      geoResource: geoResource,
      status: 'running',
      startedAt: startedAt,
      manual: true,
      correlationId: correlationId,
    );
    final operation = _startUpdating(geoResource);
    try {
      final message = await _core.updateGeoData(geoResource.name);
      if (message.isNotEmpty) {
        throw MessageException(message);
      }
    } catch (error) {
      _manualUpdates.remove(geoResource);
      _manualStartedAt.remove(geoResource);
      _manualCorrelationIds.remove(geoResource);
      _stopUpdating(geoResource, operation);
      _recordGeoOperation(
        geoResource: geoResource,
        status: 'failed',
        startedAt: startedAt,
        manual: true,
        correlationId: correlationId,
        failureKind: error.runtimeType.toString(),
      );
      rethrow;
    }
  }

  void handleCoreUpdate(
    String geoType,
    bool updating,
    bool skipped,
    String? error,
  ) {
    final geoResource = GeoResource.fromJson(geoType.toLowerCase());
    final shouldNotify = !updating && _manualUpdates.remove(geoResource);
    if (!updating) {
      final startedAt = _manualStartedAt.remove(geoResource) ?? DateTime.now();
      final correlationId = _manualCorrelationIds.remove(geoResource) ?? '';
      _recordGeoOperation(
        geoResource: geoResource,
        status: error != null && error.isNotEmpty
            ? 'failed'
            : skipped
            ? 'skipped'
            : 'completed',
        startedAt: startedAt,
        manual: shouldNotify,
        correlationId: correlationId,
        failureKind: error != null && error.isNotEmpty ? 'core-event' : null,
      );
    }
    if (shouldNotify) {
      if (error == null || error.isEmpty) {
        final l10n = currentAppLocalizations;
        final message = skipped
            ? l10n.geoSkipped(geoResource.name)
            : l10n.geoUpdated(geoResource.name);
        dialogs.showNotifier(message);
      } else {
        dialogs.showNotifier(error, level: MessageLevel.error);
      }
    }
    if (updating) {
      _startUpdating(geoResource);
    } else {
      _stopUpdating(geoResource);
    }
  }

  void updateGeoResourceUrl(GeoResource geoResource, String newUrl) {
    if (!newUrl.isUrl) {
      throw ArgumentError.value(newUrl, 'newUrl', 'Not a valid URL');
    }
    ref.read(patchClashConfigProvider.notifier).update((state) {
      return state.copyWith(geoXUrl: {...state.geoXUrl, geoResource: newUrl});
    });
  }
}
