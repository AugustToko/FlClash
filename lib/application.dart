import 'dart:async';
import 'dart:io';

import 'package:connectivity_plus/connectivity_plus.dart';
import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/common/window.dart';
import 'package:fl_clash/bootstrap.dart';
import 'package:fl_clash/common/system_dns.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/l10n/l10n.dart';
import 'package:fl_clash/manager/hotkey_manager.dart';
import 'package:fl_clash/manager/manager.dart';
import 'package:fl_clash/plugins/app.dart';
import 'package:fl_clash/providers/providers.dart';
import 'package:fl_clash/state.dart';
import 'package:material_ui/material_ui.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'pages/pages.dart';

Widget buildManagerStack({
  required bool isDesktop,
  required Future<void> Function(List<ConnectivityResult> results)
  onConnectivityChanged,
  required Widget child,
}) {
  final platformApp = isDesktop
      ? WindowHeaderContainer(child: child)
      : VpnManager(child: child);
  final state = QuickRoutingManager(
    child: AppStateManager(
      child: CoreManager(
        child: ConnectivityManager(
          onConnectivityChanged: onConnectivityChanged,
          child: platformApp,
        ),
      ),
    ),
  );
  final platformState = isDesktop
      ? WindowManager(
          child: TrayManager(
            child: HotKeyManager(child: ProxyManager(child: state)),
          ),
        )
      : AndroidManager(child: TileManager(child: state));
  return AppEnvManager(
    child: LocaleManager(
      child: StatusManager(child: ThemeManager(child: platformState)),
    ),
  );
}

class Application extends ConsumerStatefulWidget {
  const Application({super.key});

  @override
  ConsumerState<Application> createState() => ApplicationState();
}

class ApplicationState extends ConsumerState<Application> {
  static const _networkRuleRetryDelay = Duration(seconds: 30);

  Timer? _autoUpdateProfilesTaskTimer;
  Timer? _networkRuleRetryTimer;
  bool _preHasVpn = false;
  bool _networkCleanupRunning = false;
  String? _networkSignature;
  List<ConnectivityResult>? _pendingNetworkResults;

  final _pageTransitionsTheme = const PageTransitionsTheme(
    builders: <TargetPlatform, PageTransitionsBuilder>{
      TargetPlatform.android: commonSharedXPageTransitions,
      TargetPlatform.windows: commonSharedXPageTransitions,
      TargetPlatform.linux: commonSharedXPageTransitions,
      TargetPlatform.macOS: commonSharedXPageTransitions,
    },
  );

  ColorScheme _getAppColorScheme({required Brightness brightness}) {
    return ref.read(genColorSchemeProvider(brightness));
  }

  @override
  void initState() {
    super.initState();
    SystemNavigator.setFrameworkHandlesBack(true);
    WidgetsBinding.instance.addPostFrameCallback((timeStamp) async {
      if (globalState.navigatorKey.currentContext != null) {
        await bootstrap.attach();
      } else {
        exit(0);
      }
      _autoUpdateProfilesTask();
      _initLink();
      unawaited(app?.initShortcuts());
    });
  }

  void _initLink() {
    linkManager.initAppLinksListen((url) async {
      unawaited(window?.show());
      final message = currentAppLocalizations.createProfileFromUrlTip(url);
      final parts = message.split(url);
      final res = await dialogs.showMessage(
        title: currentAppLocalizations.addProfile,
        message: TextSpan(
          children: [
            TextSpan(text: parts.first),
            TextSpan(
              text: url,
              style: TextStyle(
                color: context.colorScheme.primary,
                decoration: TextDecoration.underline,
                decorationColor: context.colorScheme.primary,
              ),
            ),
            if (parts.length > 1) TextSpan(text: parts.last),
          ],
        ),
      );
      if (res != true) return;
      unawaited(
        ref.read(profilesActionProvider.notifier).addProfileFormURL(url),
      );
    });
  }

  void _autoUpdateProfilesTask() {
    _autoUpdateProfilesTaskTimer = Timer(const Duration(minutes: 20), () async {
      await ref.read(profilesActionProvider.notifier).autoUpdateProfiles();
      if (!mounted) {
        return;
      }
      _autoUpdateProfilesTask();
    });
  }

  String _getNetworkSignature(List<ConnectivityResult> results) {
    final values = results
        .where(
          (result) =>
              result != ConnectivityResult.vpn &&
              result != ConnectivityResult.none,
        )
        .map((result) => result.name)
        .toList()
      ..sort();
    return values.join(',');
  }

  Future<void> _clearNetworkRoutingRulesIfNeeded(
    List<ConnectivityResult> results,
  ) async {
    _pendingNetworkResults = List<ConnectivityResult>.unmodifiable(results);
    if (_networkCleanupRunning) {
      return;
    }
    _networkCleanupRunning = true;
    try {
      while (mounted) {
        final pending = _pendingNetworkResults;
        if (pending == null) {
          break;
        }
        _pendingNetworkResults = null;
        await _processNetworkRoutingChange(pending);
      }
    } finally {
      _networkCleanupRunning = false;
    }
  }

  Future<void> _processNetworkRoutingChange(
    List<ConnectivityResult> results,
  ) async {
    final nextSignature = _getNetworkSignature(results);
    final previousSignature = _networkSignature;
    _networkSignature = nextSignature;
    if (previousSignature == null || previousSignature == nextSignature) {
      return;
    }
    _networkRuleRetryTimer?.cancel();
    _networkRuleRetryTimer = null;
    final snapshot = ref.read(quickRoutingRulesProvider);
    final notifier = ref.read(quickRoutingRulesProvider.notifier);
    if (!notifier.clearNetworkBound()) {
      return;
    }
    if (ref.read(runTimeProvider) == null) {
      return;
    }
    try {
      final applied = await ref
          .read(setupActionProvider.notifier)
          .applyProfile(force: true, silence: true);
      if (!mounted) {
        return;
      }
      if (!applied) {
        throw StateError('Failed to clear network quick routing rules');
      }
    } catch (error, stackTrace) {
      if (!mounted) {
        commonPrint.log(
          'network quick routing cleanup stopped after disposal: '
          '${compactError(error)}, $stackTrace',
          logLevel: LogLevel.warning,
        );
        return;
      }
      notifier.replaceAll(snapshot);
      _networkSignature = previousSignature;
      if (ref.read(runTimeProvider) != null) {
        try {
          await ref
              .read(setupActionProvider.notifier)
              .applyProfile(force: true, silence: true);
        } catch (rollbackError, rollbackStackTrace) {
          commonPrint.log(
            'network quick routing rollback failed: '
            '${compactError(rollbackError)}, $rollbackStackTrace',
            logLevel: LogLevel.error,
          );
        }
      }
      if (!mounted) {
        return;
      }
      commonPrint.log(
        'network quick routing cleanup failed: '
        '${compactError(error)}, $stackTrace',
        logLevel: LogLevel.warning,
      );
      dialogs.showNotifier(
        currentAppLocalizations.databaseWriteFailedTip,
        level: MessageLevel.error,
      );
      _scheduleNetworkRuleRetry(results);
    }
  }

  void _scheduleNetworkRuleRetry(List<ConnectivityResult> results) {
    _networkRuleRetryTimer?.cancel();
    final retryResults = List<ConnectivityResult>.unmodifiable(results);
    _networkRuleRetryTimer = Timer(_networkRuleRetryDelay, () {
      _networkRuleRetryTimer = null;
      if (!mounted) {
        return;
      }
      unawaited(_clearNetworkRoutingRulesIfNeeded(retryResults));
    });
  }

  Future<void> _handleConnectivityChanged(
    List<ConnectivityResult> results,
  ) {
    commonPrint.log('connectivityChanged ${results.toString()}');
    unawaited(systemDnsCoordinator?.resync() ?? Future.value());
    unawaited(ref.read(systemActionProvider.notifier).updateLocalIp());
    unawaited(_clearNetworkRoutingRulesIfNeeded(results));
    final hasVpn = results.contains(ConnectivityResult.vpn);
    if (_preHasVpn == hasVpn) {
      ref.read(checkIpNumProvider.notifier).add();
    }
    _preHasVpn = hasVpn;
    return Future<void>.value();
  }

  @override
  Widget build(context) {
    return Consumer(
      builder: (_, ref, child) {
        final locale = ref.watch(
          appSettingProvider.select((state) => state.locale),
        );
        final themeProps = ref.watch(themeSettingProvider);
        return MaterialApp(
          debugShowCheckedModeBanner: false,
          navigatorKey: globalState.navigatorKey,
          onNavigationNotification: (_) => true,
          localizationsDelegates: const [
            AppLocalizations.delegate,
            ...GlobalMaterialLocalizations.delegates,
          ],
          builder: (context, child) {
            // The bridge's legacy Theme swaps in its own default IconTheme color,
            // which material_ui IconButton.filled reads as custom and loses onPrimary.
            // ignore: deprecated_member_use
            return MaterialUiCompatibilityBridge(
              child: IconTheme(
                data: Theme.of(context).iconTheme,
                child: buildManagerStack(
                  isDesktop: system.isDesktop,
                  onConnectivityChanged: _handleConnectivityChanged,
                  child: child!,
                ),
              ),
            );
          },
          scrollBehavior: const BaseScrollBehavior(),
          title: appName,
          locale: getLocaleForString(locale),
          supportedLocales: AppLocalizations.delegate.supportedLocales,
          themeMode: themeProps.themeMode,
          theme: ThemeData(
            useMaterial3: true,
            pageTransitionsTheme: _pageTransitionsTheme,
            colorScheme: _getAppColorScheme(brightness: Brightness.light),
          ).withAppShapes,
          darkTheme: ThemeData(
            useMaterial3: true,
            pageTransitionsTheme: _pageTransitionsTheme,
            colorScheme: _getAppColorScheme(
              brightness: Brightness.dark,
            ).toPureBlack(themeProps.pureBlack),
          ).withAppShapes,
          home: child!,
        );
      },
      child: const HomePage(),
    );
  }

  @override
  void dispose() {
    linkManager.destroy();
    _autoUpdateProfilesTaskTimer?.cancel();
    _networkRuleRetryTimer?.cancel();
    _pendingNetworkResults = null;
    super.dispose();
  }
}
