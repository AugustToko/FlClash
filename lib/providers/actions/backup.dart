part of '../action.dart';

@Riverpod(keepAlive: true)
class BackupAction extends _$BackupAction {
  @override
  void build() {}

  void _recordTransfer({
    required String eventType,
    required String correlationId,
    required String status,
    required DateTime startedAt,
    Map<String, Object?> details = const {},
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
            category: LogbookCategory.system,
            severity: severity,
            eventType: eventType,
            title: eventType,
            message: '$durationMs ms',
            correlationId: correlationId,
            details: {
              'status': status,
              'durationMs': durationMs,
              ...details,
              'failureKind': ?failureKind,
            },
          ),
    );
  }

  Future<bool> consumeBackup(Future<bool> Function(String path) send) async {
    final startedAt = DateTime.now();
    final correlationId = 'backup:${startedAt.microsecondsSinceEpoch}';
    _recordTransfer(
      eventType: 'system.backup',
      correlationId: correlationId,
      status: 'running',
      startedAt: startedAt,
    );
    String path = '';
    try {
      path = await backup();
      if (path.isEmpty) {
        _recordTransfer(
          eventType: 'system.backup',
          correlationId: correlationId,
          status: 'cancelled',
          startedAt: startedAt,
        );
        return false;
      }
      final sent = await send(path);
      _recordTransfer(
        eventType: 'system.backup',
        correlationId: correlationId,
        status: sent ? 'completed' : 'cancelled',
        startedAt: startedAt,
      );
      return sent;
    } catch (error) {
      _recordTransfer(
        eventType: 'system.backup',
        correlationId: correlationId,
        status: 'failed',
        startedAt: startedAt,
        failureKind: error.runtimeType.toString(),
      );
      rethrow;
    } finally {
      if (path.isNotEmpty) {
        await File(path).safeDelete();
      }
    }
  }

  @visibleForTesting
  Future<String> backup() async {
    final res = await Future.wait([
      database.profilesDao.fileNames().get(),
      database.scriptsDao.fileNames().get(),
    ]);
    final profileFileNames = res[0];
    final scriptFileNames = res[1];
    final configMap = ref.read(configProvider).toJson();
    configMap['version'] = await preferences.getVersion();
    return backupTask(configMap, [...profileFileNames, ...scriptFileNames]);
  }

  Future<void> restore(RestoreOption option) async {
    final startedAt = DateTime.now();
    final correlationId = 'restore:${startedAt.microsecondsSinceEpoch}';
    _recordTransfer(
      eventType: 'system.restore',
      correlationId: correlationId,
      status: 'running',
      startedAt: startedAt,
      details: {'option': option.name},
    );
    final restoreDirPath = await appPath.restoreDirPath;
    final restoreDir = Directory(restoreDirPath);
    try {
      final migrationData = await restoreTask();
      if (!await restoreDir.exists()) {
        throw MessageException(currentAppLocalizations.restoreException);
      }
      await applyRestore(migrationData, option);
      _recordTransfer(
        eventType: 'system.restore',
        correlationId: correlationId,
        status: 'completed',
        startedAt: startedAt,
        details: {
          'option': option.name,
          'profiles': migrationData.profiles.length,
          'scripts': migrationData.scripts.length,
          'rules': migrationData.rules.length,
        },
      );
    } catch (error) {
      _recordTransfer(
        eventType: 'system.restore',
        correlationId: correlationId,
        status: 'failed',
        startedAt: startedAt,
        details: {'option': option.name},
        failureKind: error.runtimeType.toString(),
      );
      rethrow;
    } finally {
      await restoreDir.safeDelete(recursive: true);
    }
  }

  @visibleForTesting
  Future<void> applyRestore(MigrationData data, RestoreOption option) async {
    final restoreStrategy = ref.read(
      appSettingProvider.select((state) => state.restoreStrategy),
    );
    final isOverride = restoreStrategy == RestoreStrategy.override;
    final configMap = data.configMap;
    final config = option == RestoreOption.onlyProfiles || configMap == null
        ? null
        : Config.fromJson(configMap);
    await database.restore(
      data.profiles,
      data.scripts,
      data.rules,
      data.links,
      data.proxyGroups,
      isOverride: isOverride,
    );
    if (config == null) {
      return;
    }
    ref.read(davSettingProvider.notifier).update((_) => config.davProps);
    ref.read(patchClashConfigProvider.notifier).value = config.patchClashConfig;
    ref.read(appSettingProvider.notifier).value = config.appSettingProps;
    ref.read(currentProfileIdProvider.notifier).value = config.currentProfileId;
    ref.read(themeSettingProvider.notifier).value = config.themeProps;
    ref.read(windowSettingProvider.notifier).value = config.windowProps;
    ref.read(vpnSettingProvider.notifier).value = config.vpnProps;
    ref.read(proxiesStyleSettingProvider.notifier).value =
        config.proxiesStyleProps;
    ref.read(overrideDnsProvider.notifier).value = config.overrideDns;
    ref.read(networkSettingProvider.notifier).value = config.networkProps;
    ref.read(hotKeyActionsProvider.notifier).value = config.hotKeyActions;
  }
}
