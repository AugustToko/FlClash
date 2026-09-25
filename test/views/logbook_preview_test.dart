import 'dart:ui';

import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/config.dart';
import 'package:fl_clash/providers/logbook.dart';
import 'package:fl_clash/state.dart';
import 'package:fl_clash/views/logbook.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

import '../helpers/test_app.dart';

class _PreviewLogbook extends LogbookNotifier {
  @override
  List<LogbookEvent> build() {
    final base = DateTime(2026, 9, 25, 10, 30);
    LogbookEvent event({
      required int id,
      required int minutesAgo,
      required LogbookCategory category,
      required LogbookSeverity severity,
      required String type,
      required String title,
      required String message,
      Map<String, Object?> details = const {},
    }) {
      final time = base.subtract(Duration(minutes: minutesAgo));
      return LogbookEvent(
        id: id,
        profileId: 7,
        createdAt: time,
        updatedAt: time,
        category: category,
        severity: severity,
        eventType: type,
        title: title,
        message: message,
        details: details,
      );
    }

    return [
      event(
        id: 1,
        minutesAgo: 1,
        category: LogbookCategory.routing,
        severity: LogbookSeverity.success,
        type: 'routing.quick-route.verification',
        title: 'routing.quick-route.verification',
        message: 'DOMAIN-SUFFIX,openai.com,Proxy → 香港自动选择 → HK-01',
        details: const {
          'status': 'verified',
          'rule': 'DOMAIN-SUFFIX,openai.com,Proxy',
        },
      ),
      event(
        id: 2,
        minutesAgo: 3,
        category: LogbookCategory.provider,
        severity: LogbookSeverity.success,
        type: 'provider.external.update',
        title: 'provider.external.update',
        message: 'OpenAI-Domains · 842 ms',
        details: const {
          'status': 'completed',
          'provider': 'OpenAI-Domains',
          'count': 1284,
        },
      ),
      event(
        id: 3,
        minutesAgo: 5,
        category: LogbookCategory.profile,
        severity: LogbookSeverity.success,
        type: 'profile.apply.completed',
        title: 'profile.apply.completed',
        message: 'Profile 7 · completed · 186 ms',
      ),
      event(
        id: 4,
        minutesAgo: 7,
        category: LogbookCategory.network,
        severity: LogbookSeverity.info,
        type: 'network.connectivity.changed',
        title: 'network.connectivity.changed',
        message: 'Wi-Fi · Home-5G · VPN 已连接',
      ),
      event(
        id: 5,
        minutesAgo: 9,
        category: LogbookCategory.script,
        severity: LogbookSeverity.success,
        type: 'script.evaluate',
        title: 'script.evaluate',
        message: 'Routing automation · 34 ms',
        details: const {
          'status': 'completed',
          'scriptLabel': 'Routing automation',
        },
      ),
      event(
        id: 6,
        minutesAgo: 12,
        category: LogbookCategory.core,
        severity: LogbookSeverity.success,
        type: 'core.restart.completed',
        title: 'core.restart.completed',
        message: 'Mihomo · 412 ms · revision=18',
      ),
      event(
        id: 7,
        minutesAgo: 15,
        category: LogbookCategory.provider,
        severity: LogbookSeverity.info,
        type: 'provider.geo.update',
        title: 'provider.geo.update',
        message: 'MMDB · 67 ms',
        details: const {'status': 'skipped', 'resource': 'MMDB'},
      ),
      event(
        id: 8,
        minutesAgo: 18,
        category: LogbookCategory.routing,
        severity: LogbookSeverity.warning,
        type: 'routing.quick-route.verification',
        title: 'routing.quick-route.verification',
        message: '规则已命中，但 SUB-RULE 上下文不完整。',
        details: const {'status': 'approximate'},
      ),
      event(
        id: 9,
        minutesAgo: 21,
        category: LogbookCategory.system,
        severity: LogbookSeverity.success,
        type: 'system.backup',
        title: 'system.backup',
        message: '1186 ms',
        details: const {'status': 'completed'},
      ),
      event(
        id: 10,
        minutesAgo: 25,
        category: LogbookCategory.provider,
        severity: LogbookSeverity.error,
        type: 'provider.external.update',
        title: 'provider.external.update',
        message: 'Streaming-Rules · 30012 ms',
        details: const {
          'status': 'failed',
          'provider': 'Streaming-Rules',
          'failureKind': 'DioException',
        },
      ),
    ];
  }

  @override
  Future<void> reload() async {}
}

Future<void> _pumpPreview(WidgetTester tester, Size size) async {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);

  final container = ProviderContainer(
    overrides: [
      logbookProvider.overrideWith(_PreviewLogbook.new),
      currentProfileIdProvider.overrideWithBuild((_, _) => 7),
    ],
  );
  addTearDown(container.dispose);
  globalState.container = container;

  await tester.pumpWidget(
    UncontrolledProviderScope(
      container: container,
      child: const TestApp(locale: Locale('zh', 'CN'), child: LogbookView()),
    ),
  );
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('Logbook mobile preview', (tester) async {
    await _pumpPreview(tester, const Size(430, 932));

    await expectLater(
      find.byType(LogbookView),
      matchesGoldenFile('../goldens/logbook_mobile_preview.png'),
    );
  });

  testWidgets('Logbook desktop preview', (tester) async {
    await _pumpPreview(tester, const Size(1280, 800));

    await expectLater(
      find.byType(LogbookView),
      matchesGoldenFile('../goldens/logbook_desktop_preview.png'),
    );
  });
}
