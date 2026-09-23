import 'dart:async';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/providers.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

class _PendingQuickRoutingGroupTransition {
  final String groupName;
  final Set<String> acceptedFixed;
  final String targetFixed;

  const _PendingQuickRoutingGroupTransition({
    required this.groupName,
    required this.acceptedFixed,
    required this.targetFixed,
  });

  factory _PendingQuickRoutingGroupTransition.fromTransition(
    QuickRoutingGroupOverrideTransition transition,
  ) {
    return _PendingQuickRoutingGroupTransition(
      groupName: transition.groupName,
      acceptedFixed: {
        transition.expectedFixed,
        transition.targetFixed,
      },
      targetFixed: transition.targetFixed,
    );
  }

  _PendingQuickRoutingGroupTransition merge(
    QuickRoutingGroupOverrideTransition transition,
  ) {
    return _PendingQuickRoutingGroupTransition(
      groupName: groupName,
      acceptedFixed: {
        ...acceptedFixed,
        transition.expectedFixed,
        transition.targetFixed,
      },
      targetFixed: transition.targetFixed,
    );
  }
}

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
  Timer? _groupOverrideRetryTimer;
  final _pendingGroupTransitions =
      <String, _PendingQuickRoutingGroupTransition>{};
  String? _lastWifiSsid;
  bool _isRunning = false;
  bool _needsReconcileOnResume = false;
  bool _reconciling = false;
  bool _reconcilePending = false;
  bool _groupOverrideReconciling = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _isRunning = ref.read(runTimeProvider) != null;
    _lastWifiSsid = _normalizeSsid(ref.read(currentSSIDProvider));
    ref.listenManual<List<QuickRoutingRuleEntry>>(
      quickRoutingRulesProvider,
      (previous, next) {
        _queueGroupTransitions(
          buildQuickRoutingGroupOverrideTransitions(
            previous: previous ?? const <QuickRoutingRuleEntry>[],
            next: next,
          ),
        );
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
    ref.listenManual<CoreStatus>(coreStatusProvider, (_, status) {
      if (status == CoreStatus.connected) {
        _requestGroupOverrideReconcile();
      }
    });
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      _purgeExpired();
      _requestGroupOverrideReconcile();
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
      _requestGroupOverrideReconcile();
      return;
    }
    _requestGroupOverrideReconcile();
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
    if (!mounted || !_isRunning) {
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
    if (!mounted || !_isRunning) {
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
    if (!mounted || !_isRunning) {
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
    if (_reconciling || !mounted) {
      return;
    }
    _reconciling = true;
    try {
      while (_reconcilePending && _isRunning && mounted) {
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
        if (!mounted) {
          return;
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
      if (mounted &&
          _reconcilePending &&
          _isRunning &&
          _reconcileRetryTimer == null) {
        _requestReconcile();
      }
    }
  }

  void _scheduleReconcileRetry() {
    if (!mounted || !_isRunning) {
      return;
    }
    commonPrint.log(
      'failed to reconcile quick routing rules; retrying',
      logLevel: LogLevel.warning,
    );
    _reconcileRetryTimer?.cancel();
    _reconcileRetryTimer = Timer(_reconcileRetryDelay, () {
      _reconcileRetryTimer = null;
      if (mounted) {
        _requestReconcile();
      }
    });
  }

  void _queueGroupTransitions(
    Iterable<QuickRoutingGroupOverrideTransition> transitions,
  ) {
    for (final transition in transitions) {
      final existing = _pendingGroupTransitions[transition.groupName];
      final pending = existing == null
          ? _PendingQuickRoutingGroupTransition.fromTransition(transition)
          : existing.merge(transition);
      if (pending.acceptedFixed.length == 1 &&
          pending.acceptedFixed.single == pending.targetFixed) {
        _pendingGroupTransitions.remove(transition.groupName);
      } else {
        _pendingGroupTransitions[transition.groupName] = pending;
      }
    }
    _requestGroupOverrideReconcile();
  }

  void _requestGroupOverrideReconcile() {
    if (!mounted ||
        _pendingGroupTransitions.isEmpty ||
        _groupOverrideReconciling ||
        ref.read(coreStatusProvider) != CoreStatus.connected) {
      return;
    }
    _groupOverrideRetryTimer?.cancel();
    _groupOverrideRetryTimer = null;
    unawaited(_drainGroupOverrideTransitions());
  }

  Future<void> _drainGroupOverrideTransitions() async {
    if (_groupOverrideReconciling || !mounted) {
      return;
    }
    _groupOverrideReconciling = true;
    try {
      while (_pendingGroupTransitions.isNotEmpty && mounted) {
        final batch = Map<String, _PendingQuickRoutingGroupTransition>.from(
          _pendingGroupTransitions,
        );
        _pendingGroupTransitions.clear();
        try {
          final fixedStates = Map<String, String>.from(
            await ref.read(coreHandlerProvider).getProxyGroupFixedStates(),
          );
          var changed = false;
          for (final transition in batch.values) {
            final current = fixedStates[transition.groupName];
            if (current == null) {
              commonPrint.log(
                'quick routing automatic group disappeared: '
                '${transition.groupName}',
                logLevel: LogLevel.warning,
              );
              continue;
            }
            if (current == transition.targetFixed) {
              continue;
            }
            if (!transition.acceptedFixed.contains(current)) {
              commonPrint.log(
                'quick routing automatic group changed externally: '
                '${transition.groupName} ($current)',
                logLevel: LogLevel.info,
              );
              continue;
            }
            final message = await ref.read(coreHandlerProvider).changeProxy(
                  ChangeProxyParams(
                    groupName: transition.groupName,
                    proxyName: transition.targetFixed,
                  ),
                );
            if (message.isNotEmpty) {
              throw MessageException(message);
            }
            fixedStates[transition.groupName] = transition.targetFixed;
            changed = true;
          }
          if (changed) {
            await ref.read(proxiesActionProvider.notifier).updateGroups();
          }
        } catch (error, stackTrace) {
          for (final transition in batch.values) {
            final existing = _pendingGroupTransitions[transition.groupName];
            _pendingGroupTransitions[transition.groupName] = existing == null
                ? transition
                : transition.merge(
                    QuickRoutingGroupOverrideTransition(
                      groupName: existing.groupName,
                      expectedFixed: existing.acceptedFixed.first,
                      targetFixed: existing.targetFixed,
                    ),
                  );
          }
          commonPrint.log(
            'quick routing automatic group reconciliation failed: '
            '${compactError(error)}, $stackTrace',
            logLevel: LogLevel.warning,
          );
          _scheduleGroupOverrideRetry();
          return;
        }
      }
    } finally {
      _groupOverrideReconciling = false;
      if (mounted &&
          _pendingGroupTransitions.isNotEmpty &&
          _groupOverrideRetryTimer == null) {
        _requestGroupOverrideReconcile();
      }
    }
  }

  void _scheduleGroupOverrideRetry() {
    if (!mounted) {
      return;
    }
    _groupOverrideRetryTimer?.cancel();
    _groupOverrideRetryTimer = Timer(_reconcileRetryDelay, () {
      _groupOverrideRetryTimer = null;
      if (mounted) {
        _requestGroupOverrideReconcile();
      }
    });
  }

  @override
  Widget build(BuildContext context) => widget.child;

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _expiryTimer?.cancel();
    _reconcileRetryTimer?.cancel();
    _groupOverrideRetryTimer?.cancel();
    _pendingGroupTransitions.clear();
    super.dispose();
  }
}
