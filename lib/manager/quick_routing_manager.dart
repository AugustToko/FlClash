import 'dart:async';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/providers.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

class _PendingQuickRoutingGroupTransition {
  final int profileId;
  final String groupName;
  final Set<String> acceptedFixed;
  final String targetFixed;

  const _PendingQuickRoutingGroupTransition({
    required this.profileId,
    required this.groupName,
    required this.acceptedFixed,
    required this.targetFixed,
  });

  factory _PendingQuickRoutingGroupTransition.fromTransition(
    QuickRoutingGroupOverrideTransition transition,
  ) {
    return _PendingQuickRoutingGroupTransition(
      profileId: transition.profileId,
      groupName: transition.groupName,
      acceptedFixed: {transition.expectedFixed, transition.targetFixed},
      targetFixed: transition.targetFixed,
    );
  }

  factory _PendingQuickRoutingGroupTransition.activation(
    int profileId,
    QuickRoutingGroupOverride override,
  ) {
    return _PendingQuickRoutingGroupTransition(
      profileId: profileId,
      groupName: override.groupName,
      acceptedFixed: {
        override.previousFixed,
        override.expectedFixed,
        override.desiredFixed,
      },
      targetFixed: override.desiredFixed,
    );
  }

  _PendingQuickRoutingGroupTransition mergeTransition(
    QuickRoutingGroupOverrideTransition transition,
  ) {
    return _PendingQuickRoutingGroupTransition(
      profileId: profileId,
      groupName: groupName,
      acceptedFixed: {
        ...acceptedFixed,
        transition.expectedFixed,
        transition.targetFixed,
      },
      targetFixed: transition.targetFixed,
    );
  }

  _PendingQuickRoutingGroupTransition mergePending(
    _PendingQuickRoutingGroupTransition next,
  ) {
    return _PendingQuickRoutingGroupTransition(
      profileId: profileId,
      groupName: groupName,
      acceptedFixed: {...acceptedFixed, ...next.acceptedFixed},
      targetFixed: next.targetFixed,
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
      <(int, String), _PendingQuickRoutingGroupTransition>{};
  int? _groupsProfileId;
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
    if (ref.read(groupsProvider).isNotEmpty) {
      _groupsProfileId = ref.read(currentProfileIdProvider);
    }
    ref.listenManual<List<QuickRoutingRuleEntry>>(quickRoutingRulesProvider, (
      previous,
      next,
    ) {
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
    }, fireImmediately: true);
    ref.listenManual<bool>(
      runTimeProvider.select((value) => value != null),
      (_, running) => _handleRunningChanged(running),
    );
    ref.listenManual<String?>(
      currentSSIDProvider,
      (_, ssid) => _handleSsidChanged(ssid),
    );
    ref.listenManual<int?>(currentProfileIdProvider, (previous, next) {
      if (previous == next) {
        return;
      }
      _groupsProfileId = null;
      _groupOverrideRetryTimer?.cancel();
      _groupOverrideRetryTimer = null;
    });
    ref.listenManual<List<Group>>(groupsProvider, (_, groups) {
      final profileId = ref.read(currentProfileIdProvider);
      _groupsProfileId = groups.isEmpty ? null : profileId;
      _queueCurrentProfileGroupActivations();
    });
    ref.listenManual<CoreStatus>(coreStatusProvider, (_, status) {
      if (status != CoreStatus.connected) {
        _groupsProfileId = null;
        return;
      }
      if (ref.read(groupsProvider).isNotEmpty) {
        _groupsProfileId = ref.read(currentProfileIdProvider);
        _queueCurrentProfileGroupActivations();
      }
      _requestGroupOverrideReconcile();
    });
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      _purgeExpired();
      _queueCurrentProfileGroupActivations();
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
    _queueCurrentProfileGroupActivations();
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
    final changed = ref.read(quickRoutingRulesProvider.notifier).purgeExpired();
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

  void _queueCurrentProfileGroupActivations() {
    if (!mounted) {
      return;
    }
    final profileId = ref.read(currentProfileIdProvider);
    if (profileId == null || _groupsProfileId != profileId) {
      return;
    }
    final entries = ref
        .read(quickRoutingRulesProvider.notifier)
        .activeEntriesFor(profileId);
    for (final entry in entries) {
      final override = entry.groupOverride;
      if (override == null) {
        continue;
      }
      _queuePendingGroupTransition(
        _PendingQuickRoutingGroupTransition.activation(profileId, override),
      );
    }
    _requestGroupOverrideReconcile();
  }

  void _queueGroupTransitions(
    Iterable<QuickRoutingGroupOverrideTransition> transitions,
  ) {
    for (final transition in transitions) {
      _queuePendingGroupTransition(
        _PendingQuickRoutingGroupTransition.fromTransition(transition),
      );
    }
    _requestGroupOverrideReconcile();
  }

  void _queuePendingGroupTransition(
    _PendingQuickRoutingGroupTransition transition,
  ) {
    final key = (transition.profileId, transition.groupName);
    final existing = _pendingGroupTransitions[key];
    final pending = existing == null
        ? transition
        : existing.mergePending(transition);
    if (pending.acceptedFixed.length == 1 &&
        pending.acceptedFixed.single == pending.targetFixed) {
      _pendingGroupTransitions.remove(key);
    } else {
      _pendingGroupTransitions[key] = pending;
    }
  }

  bool get _hasCurrentGroupTransitions {
    final profileId = ref.read(currentProfileIdProvider);
    return profileId != null &&
        _groupsProfileId == profileId &&
        _pendingGroupTransitions.keys.any((key) => key.$1 == profileId);
  }

  void _requestGroupOverrideReconcile() {
    if (!mounted ||
        !_hasCurrentGroupTransitions ||
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
    final profileId = ref.read(currentProfileIdProvider);
    if (profileId == null || _groupsProfileId != profileId) {
      return;
    }
    _groupOverrideReconciling = true;
    try {
      while (mounted) {
        if (ref.read(currentProfileIdProvider) != profileId ||
            _groupsProfileId != profileId) {
          return;
        }
        final batch = <(int, String), _PendingQuickRoutingGroupTransition>{};
        for (final entry in _pendingGroupTransitions.entries) {
          if (entry.key.$1 == profileId) {
            batch[entry.key] = entry.value;
          }
        }
        if (batch.isEmpty) {
          return;
        }
        for (final key in batch.keys) {
          _pendingGroupTransitions.remove(key);
        }
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
            final message = await ref
                .read(coreHandlerProvider)
                .changeProxy(
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
          for (final entry in batch.entries) {
            final existing = _pendingGroupTransitions[entry.key];
            _pendingGroupTransitions[entry.key] = existing == null
                ? entry.value
                : entry.value.mergePending(existing);
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
          _hasCurrentGroupTransitions &&
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
