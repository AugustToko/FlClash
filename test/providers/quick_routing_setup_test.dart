import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/action.dart';
import 'package:fl_clash/providers/app.dart';
import 'package:fl_clash/providers/quick_routing.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:riverpod/riverpod.dart';

class _TestSetupAction extends SetupAction {
  Object? stopError;

  @override
  Future<bool> setCoreRunning(bool running) async {
    if (!running && stopError case final error?) {
      throw error;
    }
    return true;
  }

  @override
  void resetCoreTraffic() {}
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

  void addRuntimeRule() {
    container.read(quickRoutingRulesProvider.notifier).put(
      profileId: 1,
      rule: const Rule(
        id: 1,
        ruleAction: RuleAction.DOMAIN,
        content: 'example.com',
        ruleTarget: 'DIRECT',
      ),
      lifetime: QuickRoutingLifetime.session,
      sourceId: 'request',
      sourceDesc: 'tcp://example.com:443',
      previousRule: 'MATCH',
      previousChains: const ['Proxy'],
    );
  }

  test('a confirmed listener stop clears runtime quick rules', () async {
    addRuntimeRule();

    await container.read(setupActionProvider.notifier).setRunning(false);

    expect(container.read(quickRoutingRulesProvider), isEmpty);
  });

  test('a rejected listener stop preserves runtime quick rules', () async {
    addRuntimeRule();
    action.stopError = StateError('stop failed');

    await expectLater(
      container.read(setupActionProvider.notifier).setRunning(false),
      throwsStateError,
    );

    expect(container.read(quickRoutingRulesProvider), hasLength(1));
  });
}
