import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/features/features.dart';
import 'package:fl_clash/models/models.dart';
import 'package:test/test.dart';

void main() {
  TrackerInfo trackerInfo({
    String host = '',
    String destinationIP = '',
    String destinationPort = '',
    String process = '',
    String processPath = '',
    int uid = 0,
    List<String> chains = const [],
  }) {
    return TrackerInfo(
      id: 'connection-id',
      start: DateTime.utc(2026),
      metadata: Metadata(
        network: 'tcp',
        host: host,
        destinationIP: destinationIP,
        destinationPort: destinationPort,
        process: process,
        processPath: processPath,
        uid: uid,
      ),
      chains: chains,
      rule: 'MATCH',
      rulePayload: '',
    );
  }

  group('buildQuickRoutingCandidates', () {
    test('builds safe match choices from connection metadata', () {
      final candidates = buildQuickRoutingCandidates(
        trackerInfo(
          host: 'Api.Example.com.',
          destinationIP: '1.1.1.1',
          destinationPort: '443',
          process: 'com.example.app',
          processPath: '/data/app/com.example.app/base.apk',
          uid: 10001,
        ),
      );

      QuickRoutingCandidate candidate(RuleAction action) {
        return candidates.singleWhere(
          (candidate) => candidate.ruleAction == action,
        );
      }

      expect(candidate(RuleAction.DOMAIN).content, 'api.example.com');
      expect(
        candidate(RuleAction.DOMAIN_SUFFIX).content,
        'api.example.com',
      );
      expect(candidate(RuleAction.IP_CIDR).content, '1.1.1.1/32');
      expect(candidate(RuleAction.IP_CIDR).noResolve, isTrue);
      expect(candidate(RuleAction.PROCESS_NAME).content, 'com.example.app');
      expect(
        candidate(RuleAction.PROCESS_PATH).content,
        '/data/app/com.example.app/base.apk',
      );
      expect(candidate(RuleAction.UID).content, '10001');
      expect(candidate(RuleAction.DST_PORT).content, '443');
    });

    test('normalizes bracketed IPv6 and removes duplicate IP choices', () {
      final candidates = buildQuickRoutingCandidates(
        trackerInfo(
          host: '[2001:db8::1]:443',
          destinationIP: '2001:db8::1',
        ),
      );

      expect(
        candidates.where(
          (candidate) => candidate.ruleAction == RuleAction.IP_CIDR6,
        ),
        hasLength(1),
      );
      expect(candidates.single.content, '2001:db8::1/128');
      expect(candidates.single.noResolve, isTrue);
    });

    test('ignores empty metadata', () {
      expect(buildQuickRoutingCandidates(trackerInfo()), isEmpty);
    });
  });

  group('quick routing targets', () {
    test('keeps base targets first and removes duplicate group names', () {
      final targets = buildQuickRoutingTargets(const [
        Group(type: GroupType.Selector, all: [], name: 'Proxy'),
        Group(type: GroupType.URLTest, all: [], name: 'Auto'),
        Group(type: GroupType.Selector, all: [], name: 'DIRECT'),
        Group(type: GroupType.Selector, all: [], name: 'Proxy'),
      ]);

      expect(targets, ['DIRECT', 'REJECT', 'Proxy', 'Auto']);
    });

    test('prefers a policy group already present in the connection chain', () {
      final info = trackerInfo(chains: const ['Proxy', 'Hong Kong']);
      final target = pickQuickRoutingTarget(
        info,
        const ['DIRECT', 'REJECT', 'Proxy'],
      );

      expect(target, 'Proxy');
    });

    test('falls back to DIRECT when no chain target is available', () {
      final target = pickQuickRoutingTarget(
        trackerInfo(chains: const ['Unknown']),
        const ['DIRECT', 'REJECT', 'Proxy'],
      );

      expect(target, 'DIRECT');
    });
  });
}
