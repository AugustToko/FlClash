import 'dart:async';

import 'package:fl_clash/common/common.dart';
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
    ref.listenManual(runTimeProvider, (previous, next) {
      if (previous != null && next == null) {
        ref.read(quickRoutingRulesProvider.notifier).clearAll();
      }
    });
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
    if (!changed || ref.read(runTimeProvider) == null) {
      return;
    }
    unawaited(_applyProfile());
  }

  Future<void> _applyProfile() async {
    final applied = await ref
        .read(setupActionProvider.notifier)
        .applyProfile(force: true, silence: true);
    if (!applied) {
      commonPrint.log(
        'failed to remove expired quick routing rules from the active profile',
        logLevel: LogLevel.warning,
      );
    }
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
