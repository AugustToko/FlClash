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
        title: '快速分流已验证',
        message: 'DOMAIN-SUFFIX,openai.com,Proxy → 香港自动选择 → HK-01',
        details: const {'rule': 'DOMAIN-SUFFIX,openai.com,Proxy'},
      ),
      event(
        id: 2,
        minutesAgo: 4,
        category: LogbookCategory.profile,
        severity: LogbookSeverity.success,
        type: 'profile.apply.completed',
        title: '配置已应用',
        message: 'Profile 7 已在 186 ms 内完成重载。',
      ),
      event(
        id: 3,
        minutesAgo: 7,
        category: LogbookCategory.network,
        severity: LogbookSeverity.info,
        type: 'network.connectivity.changed',
        title: '网络连接发生变化',
        message: 'Wi-Fi · Home-5G · VPN 已连接',
      ),
      event(
        id: 4,
        minutesAgo: 12,
        category: LogbookCategory.core,
        severity: LogbookSeverity.success,
        type: 'core.restart.completed',
        title: '核心重启完成',
        message: 'Mihomo 核心已重新连接，并恢复当前配置。',
      ),
      event(
        id: 5,
        minutesAgo: 18,
        category: LogbookCategory.routing,
        severity: LogbookSeverity.warning,
        type: 'routing.quick-route.verification',
        title: '分流结果为近似验证',
        message: '规则已命中，但 SUB-RULE 上下文不完整。',
      ),
      event(
        id: 6,
        minutesAgo: 25,
        category: LogbookCategory.provider,
        severity: LogbookSeverity.error,
        type: 'provider.update.failed',
        title: '规则集更新失败',
        message: 'OpenAI-Domains · TLS handshake timeout',
      ),
    ];
  }

  @override
  Future<void> reload() async {}
}

void main() {
  testWidgets('Logbook mobile preview', (tester) async {
    tester.view.physicalSize = const Size(430, 932);
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

    await expectLater(
      find.byType(LogbookView),
      matchesGoldenFile('../goldens/logbook_mobile_preview.png'),
    );
  });
}
