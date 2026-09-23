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

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    ref.listenManual<List<QuickRoutingRuleEntry>>(
      quickRoutingRulesProvider,
      (_, _) => _scheduleExpiry(),
      fireImmediately: true,
    );
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      _purgeExpired();
    }
  }

  void _scheduleExpiry() {
    _expiryTimer?.cancel();
    final nextExpiry = ref.read(quickRoutingRulesProvider.notifier).nextExpiry;
    if (nextExpiry == null) {
      _expiryTimer = null;
      return;
    }
    final remaining = nextExpiry.difference(DateTime.now());
    _expiryTimer = Timer(
      remaining.isNegative ? Duration.zero : remaining,
      _purgeExpired,
    );
  }

  void _purgeExpired() {
    final changed = ref
        .read(quickRoutingRulesProvider.notifier)
        .purgeExpired();
    if (!changed) {
      _scheduleExpiry();
      return;
    }
    if (ref.read(runTimeProvider) == null) {
      return;
    }
    unawaited(_reconcileProfile());
  }

  Future<void> _reconcileProfile() async {
    if (ref.read(runTimeProvider) == null) {
      _scheduleExpiry();
      return;
    }
    var applied = false;
    try {
      applied = await ref
          .read(setupActionProvider.notifier)
          .applyProfile(force: true, silence: true);
    } catch (error, stackTrace) {
      commonPrint.log(
        'expired quick routing reconciliation failed: '
        '${compactError(error)}, $stackTrace',
        logLevel: LogLevel.warning,
      );
    }
    if (applied) {
      _scheduleExpiry();
      return;
    }
    commonPrint.log(
      'failed to reconcile expired quick routing rules; retrying',
      logLevel: LogLevel.warning,
    );
    _expiryTimer?.cancel();
    _expiryTimer = Timer(
      _reconcileRetryDelay,
      () => unawaited(_reconcileProfile()),
    );
  }

  @override
  Widget build(BuildContext context) => widget.child;

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _expiryTimer?.cancel();
    super.dispose();
  }
}
