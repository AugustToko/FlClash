import 'package:fl_clash/core/controller.dart';
import 'package:fl_clash/models/models.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('extracts fixed state only from groups that expose it', () {
    const data = ProxiesData(
      all: ['Auto', 'Fallback', 'Proxy', 'HK-01'],
      proxies: {
        'Auto': {'type': 'URLTest', 'fixed': 'HK-01'},
        'Fallback': {'type': 'Fallback', 'fixed': ''},
        'Proxy': {'type': 'Selector', 'now': 'HK-01'},
        'HK-01': {'type': 'Shadowsocks'},
      },
    );

    expect(extractProxyGroupFixedStates(data), const {
      'Auto': 'HK-01',
      'Fallback': '',
    });
  });

  test('ignores malformed proxy snapshots', () {
    const data = ProxiesData(
      all: ['Broken', 'Wrong'],
      proxies: {
        'Broken': 'not-a-map',
        'Wrong': {'fixed': 1},
      },
    );

    expect(extractProxyGroupFixedStates(data), isEmpty);
  });
}
