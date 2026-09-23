import 'dart:async';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/providers/providers.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

class QuickRoutingManager extends ConsumerStatefulWidget {
  final Widget child;

  const QuickRoutingManager({super.key, required this.child});

  @override
  ConsumerState<QuickRoutingManager> createState() =>
      _QuickRoutingManagerState();
}

class _QuickRoutingManagerState extends ConsumerState<QuickRoutingManager>
    with WidgetsBindingObserver {
  static const _reconcileRetryDelay = Duration(seconds: 30);

  Timer? _expiryTimer;
  Timer? _reconcileRetryTimer;
  String? _lastWifiSsid;
  bool _isRunning = false;
  bool _needsReconcileOnResume = false;
  bool _reconciling = false;
  bool _reconcilePending = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _isRunning = ref.read(runTimeProvider) != null;
    _lastWifiSsid = _normalizeSsid(ref.read(currentSSIDProvider));
    ref.listenManual<List<QuickRoutingRuleEntry>>(
      quickRoutingRulesProvider,
      (previous, next) {
        if (!_isRunning &&
            previous != null &&
            !identical(previous, next) &&
            ref.read(coreStatusProvider) != CoreStatus.disconnected) {
          _needsReconcileOnResume = true;
        }
        _scheduleExpiry();
      },
      fireImmediately: true,
    );
    ref.listenManual<bool>(
      runTimeProvider.select((value) => value != null),
      (_, running) => _handleRunningChanged(running),
    );
    ref.listenManual<String?>(
      currentSSIDProvider,
      (_, ssid) => _handleSsidChanged(ssid),
    );
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      _purgeExpired();
    }
  }

  void _handleRunningChanged(bool running) {
    if (_isRunning == running) {
      return;
    }
    _isRunning = running;
    if (!running) {
      _expiryTimer?.cancel();
      _expiryTimer = null;
      _reconcileRetryTimer?.cancel();
      _reconcileRetryTimer = null;
      return;
    }
    if (_needsReconcileOnResume || _reconcilePending) {
      _needsReconcileOnResume = false;
      _requestReconcile();
      return;
    }
    _scheduleExpiry();
  }

  String? _normalizeSsid(String? value) {
    final normalized = value?.trim();
    return normalized == null || normalized.isEmpty ? null : normalized;
  }

  void _handleSsidChanged(String? value) {
    final ssid = _normalizeSsid(value);
    if (ssid == null) {
      return;
    }
    final previous = _lastWifiSsid;
    _lastWifiSsid = ssid;
    if (previous == null || previous == ssid) {
      return;
    }
    final changed = ref
        .read(quickRoutingRulesProvider.notifier)
        .clearNetworkBound();
    if (!changed) {
      return;
    }
    if (!_isRunning) {
      if (ref.read(coreStatusProvider) != CoreStatus.disconnected) {
        _needsReconcileOnResume = true;
      }
      return;
    }
    _requestReconcile();
  }

  void _scheduleExpiry() {
    _expiryTimer?.cancel();
    _expiryTimer = null;
    if (!_isRunning) {
      return;
    }
    final nextExpiry = ref.read(quickRoutingRulesProvider.notifier).nextExpiry;
    if (nextExpiry == null) {
      return;
    }
    final remaining = nextExpiry.difference(DateTime.now());
    _expiryTimer = Timer(
      remaining.isNegative ? Duration.zero : remaining,
      _purgeExpired,
    );
  }

  void _purgeExpired() {
    if (!_isRunning) {
      _scheduleExpiry();
      return;
    }
    final changed = ref
        .read(quickRoutingRulesProvider.notifier)
        .purgeExpired();
    if (!changed) {
      _scheduleExpiry();
      return;
    }
    _requestReconcile();
  }

  void _requestReconcile() {
    if (!_isRunning) {
      return;
    }
    _reconcilePending = true;
    if (_reconciling) {
      return;
    }
    _reconcileRetryTimer?.cancel();
    _reconcileRetryTimer = null;
    unawaited(_drainReconcileRequests());
  }

  Future<void> _drainReconcileRequests() async {
    if (_reconciling) {
      return;
    }
    _reconciling = true;
    try {
      while (_reconcilePending && _isRunning) {
        _reconcilePending = false;
        var applied = false;
        try {
          applied = await ref
              .read(setupActionProvider.notifier)
              .applyProfile(force: true, silence: true);
        } catch (error, stackTrace) {
          commonPrint.log(
            'quick routing reconciliation failed: '
            '${compactError(error)}, $stackTrace',
            logLevel: LogLevel.warning,
          );
        }
        if (!applied) {
          _reconcilePending = true;
          _scheduleReconcileRetry();
          return;
        }
      }
      _reconcileRetryTimer?.cancel();
      _reconcileRetryTimer = null;
      _scheduleExpiry();
    } finally {
      _reconciling = false;
      if (_reconcilePending &&
          _isRunning &&
          _reconcileRetryTimer == null) {
        _requestReconcile();
      }
    }
  }

  void _scheduleReconcileRetry() {
    if (!_isRunning) {
      return;
    }
    commonPrint.log(
      'failed to reconcile quick routing rules; retrying',
      logLevel: LogLevel.warning,
    );
    _reconcileRetryTimer?.cancel();
    _reconcileRetryTimer = Timer(_reconcileRetryDelay, () {
      _reconcileRetryTimer = null;
      _requestReconcile();
    });
  }

  @override
  Widget build(BuildContext context) => widget.child;

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _expiryTimer?.cancel();
    _reconcileRetryTimer?.cancel();
    super.dispose();
  }
}
