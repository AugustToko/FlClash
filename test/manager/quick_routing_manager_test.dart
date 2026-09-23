import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/manager/quick_routing_manager.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/action.dart';
import 'package:fl_clash/providers/app.dart';
import 'package:fl_clash/providers/quick_routing.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

class _TestSetupAction extends SetupAction {
  final List<bool> results = [];
  int applyCalls = 0;

  @override
  Future<bool> applyProfile({
    bool silence = false,
    bool force = false,
    Future<void> Function()? preloadInvoke,
  }) async {
    applyCalls++;
    return results.isEmpty ? true : results.removeAt(0);
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late _TestSetupAction action;
  late ProviderContainer container;

  setUp(() {
    action = _TestSetupAction();
    container = ProviderContainer(
      overrides: [setupActionProvider.overrideWith(() => action)],
    );
    container.read(setupActionProvider.notifier);
  });

  tearDown(() {
    container.dispose();
  });

  QuickRoutingRuleEntry addRule({
    QuickRoutingLifetime lifetime = QuickRoutingLifetime.network,
    DateTime? now,
  }) {
    return container.read(quickRoutingRulesProvider.notifier).put(
      profileId: 1,
      rule: const Rule(
        id: 1,
        ruleAction: RuleAction.DOMAIN,
        content: 'example.com',
        ruleTarget: 'DIRECT',
      ),
      lifetime: lifetime,
      sourceId: 'request',
      sourceDesc: 'tcp://example.com:443',
      previousRule: 'MATCH',
      previousChains: const ['Proxy'],
      now: now,
    );
  }

  Future<void> pumpManager(WidgetTester tester) async {
    await tester.pumpWidget(
      UncontrolledProviderScope(
        container: container,
        child: const QuickRoutingManager(child: SizedBox.shrink()),
      ),
    );
    await tester.pump();
  }

  testWidgets('expired rules wait until the core is running to reconcile', (
    tester,
  ) async {
    addRule(
      lifetime: QuickRoutingLifetime.tenMinutes,
      now: DateTime.now().subtract(const Duration(minutes: 11)),
    );
    await pumpManager(tester);

    expect(container.read(quickRoutingRulesProvider), hasLength(1));
    expect(action.applyCalls, 0);

    container.read(runTimeProvider.notifier).value = 1;
    await tester.pumpAndSettle();

    expect(container.read(quickRoutingRulesProvider), isEmpty);
    expect(action.applyCalls, 1);
  });

  testWidgets('a Wi-Fi-to-Wi-Fi change clears network-bound rules', (
    tester,
  ) async {
    addRule();
    container.read(runTimeProvider.notifier).value = 1;
    container.read(coreStatusProvider.notifier).value = CoreStatus.connected;
    container.read(currentSSIDProvider.notifier).value = 'Home';
    await pumpManager(tester);

    container.read(currentSSIDProvider.notifier).value = 'Office';
    await tester.pumpAndSettle();

    expect(container.read(quickRoutingRulesProvider), isEmpty);
    expect(action.applyCalls, 1);
  });

  testWidgets('the first observed SSID establishes a baseline only', (
    tester,
  ) async {
    addRule();
    container.read(runTimeProvider.notifier).value = 1;
    container.read(coreStatusProvider.notifier).value = CoreStatus.connected;
    await pumpManager(tester);

    container.read(currentSSIDProvider.notifier).value = 'Home';
    await tester.pumpAndSettle();

    expect(container.read(quickRoutingRulesProvider), hasLength(1));
    expect(action.applyCalls, 0);
  });

  testWidgets('state changed during a failed stop reconciles after resume', (
    tester,
  ) async {
    addRule();
    container.read(runTimeProvider.notifier).value = 1;
    container.read(coreStatusProvider.notifier).value = CoreStatus.connected;
    await pumpManager(tester);

    container.read(runTimeProvider.notifier).value = null;
    await tester.pump();
    container.read(quickRoutingRulesProvider.notifier).clearNetworkBound();
    await tester.pump();
    container.read(runTimeProvider.notifier).value = 1;
    await tester.pumpAndSettle();

    expect(container.read(quickRoutingRulesProvider), isEmpty);
    expect(action.applyCalls, 1);
  });

  testWidgets('failed reconciliation retries without restoring stale rules', (
    tester,
  ) async {
    addRule();
    action.results.addAll([false, true]);
    container.read(runTimeProvider.notifier).value = 1;
    container.read(coreStatusProvider.notifier).value = CoreStatus.connected;
    container.read(currentSSIDProvider.notifier).value = 'Home';
    await pumpManager(tester);

    container.read(currentSSIDProvider.notifier).value = 'Office';
    await tester.pump();
    expect(container.read(quickRoutingRulesProvider), isEmpty);
    expect(action.applyCalls, 1);

    await tester.pump(const Duration(seconds: 30));
    await tester.pumpAndSettle();

    expect(action.applyCalls, 2);
    expect(container.read(quickRoutingRulesProvider), isEmpty);
  });
}
