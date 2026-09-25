import 'dart:async';

import 'package:connectivity_plus/connectivity_plus.dart';
import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/providers/app.dart';
import 'package:fl_clash/providers/config.dart';
import 'package:fl_clash/providers/quick_routing.dart';
import 'package:material_ui/material_ui.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:wifi_ssid/wifi_ssid.dart';

typedef SsidReader = Future<String?> Function();

class ConnectivityManager extends ConsumerStatefulWidget {
  final Function(List<ConnectivityResult> results)? onConnectivityChanged;
  final Stream<List<ConnectivityResult>>? connectivityStream;
  final SsidReader? readSsid;
  final Duration ssidPollInterval;
  final Widget child;

  const ConnectivityManager({
    super.key,
    this.onConnectivityChanged,
    this.connectivityStream,
    this.readSsid,
    this.ssidPollInterval = const Duration(seconds: 15),
    required this.child,
  });

  @override
  ConsumerState<ConnectivityManager> createState() =>
      _ConnectivityManagerState();
}

class _ConnectivityManagerState extends ConsumerState<ConnectivityManager> {
  late final StreamSubscription subscription;
  late final SsidReader _readSsid =
      widget.readSsid ?? WifiSsidManager.instance.getSsid;

  Timer? _ssidPollTimer;
  int _ssidRequestId = 0;
  bool _onWifi = false;
  bool _hasNetworkQuickRules = false;

  @override
  void initState() {
    super.initState();
    _hasNetworkQuickRules = _containsActiveNetworkQuickRules(
      ref.read(quickRoutingRulesProvider),
    );
    final stream =
        widget.connectivityStream ?? Connectivity().onConnectivityChanged;
    subscription = stream.listen(_handleResults);
    ref.listenManual(excludeSSIDsProvider.select((state) => state.isNotEmpty), (
      previous,
      next,
    ) {
      if (previous != next) {
        _configureSsidPolling();
        unawaited(_updateSsid());
      }
    });
    ref.listenManual<bool>(
      quickRoutingRulesProvider.select(_containsActiveNetworkQuickRules),
      (_, next) {
        if (_hasNetworkQuickRules == next) {
          return;
        }
        _hasNetworkQuickRules = next;
        _configureSsidPolling();
        unawaited(_updateSsid());
      },
    );
  }

  bool _containsActiveNetworkQuickRules(List<QuickRoutingRuleEntry> entries) {
    final now = DateTime.now();
    return entries.any(
      (entry) =>
          entry.lifetime == QuickRoutingLifetime.network &&
          !entry.isExpired(now),
    );
  }

  bool get _needsSsid =>
      ref.read(excludeSSIDsProvider).isNotEmpty || _hasNetworkQuickRules;

  void _handleResults(List<ConnectivityResult> results) {
    _onWifi = results.contains(ConnectivityResult.wifi);
    _configureSsidPolling();
    unawaited(_updateSsid());
    widget.onConnectivityChanged?.call(results);
  }

  void _configureSsidPolling() {
    _ssidPollTimer?.cancel();
    _ssidPollTimer = null;
    if (!_onWifi || !_hasNetworkQuickRules) {
      return;
    }
    _ssidPollTimer = Timer.periodic(
      widget.ssidPollInterval,
      (_) => unawaited(_updateSsid()),
    );
  }

  Future<void> _updateSsid() async {
    final requestId = ++_ssidRequestId;
    // SSID lookup is a blocking platform call and may require location
    // permission. Keep it event-driven unless a network-lifetime rule needs
    // to detect Wi-Fi-to-Wi-Fi transitions.
    if (!_onWifi || !_needsSsid) {
      _publishSsid(requestId, null);
      return;
    }
    try {
      final ssid = await _readSsid();
      if (_publishSsid(requestId, ssid)) {
        commonPrint.log('Wi-fi SSID: $ssid', logLevel: LogLevel.info);
      }
    } catch (error) {
      commonPrint.log(
        'Unable to read the Wi-Fi SSID: $error',
        logLevel: LogLevel.warning,
      );
      _publishSsid(requestId, null);
    }
  }

  bool _publishSsid(int requestId, String? ssid) {
    if (requestId != _ssidRequestId || !mounted) {
      return false;
    }
    final previous = ref.read(currentSSIDProvider);
    if (previous == ssid) {
      return false;
    }
    ref.read(currentSSIDProvider.notifier).value = ssid;
    return true;
  }

  @override
  void dispose() {
    _ssidPollTimer?.cancel();
    subscription.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return widget.child;
  }
}
