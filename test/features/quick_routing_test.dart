import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/features/features.dart';
import 'package:fl_clash/models/models.dart';
import 'package:test/test.dart';

void main() {
  TrackerInfo trackerInfo({
    String host = '',
    String sourceIP = '',
    String sourcePort = '',
    String destinationIP = '',
    String destinationPort = '',
    String process = '',
    String processPath = '',
    String network = '',
    String destinationIPASN = '',
    String sourceIPASN = '',
    List<String> destinationGeoIP = const [],
    List<String> sourceGeoIP = const [],
    int uid = 0,
    List<String> chains = const [],
  }) {
    return TrackerInfo(
      id: 'connection-id',
      start: DateTime.utc(2026),
      metadata: Metadata(
        network: network,
        host: host,
        sourceIP: sourceIP,
        sourcePort: sourcePort,
        destinationIP: destinationIP,
        destinationPort: destinationPort,
        process: process,
        processPath: processPath,
        destinationIPASN: destinationIPASN,
        sourceIPASN: sourceIPASN,
        destinationGeoIP: destinationGeoIP,
        sourceGeoIP: sourceGeoIP,
        uid: uid,
      ),
      chains: chains,
      rule: 'MATCH',
      rulePayload: '',
    );
  }

  group('buildQuickRoutingCandidates', () {
    test('builds destination, source, process and network choices', () {
      final candidates = buildQuickRoutingCandidates(
        trackerInfo(
          host: 'Api.Example.com.',
          sourceIP: '10.0.0.2',
          sourcePort: '51000',
          destinationIP: '1.1.1.1',
          destinationPort: '443',
          process: 'com.example.app',
          processPath: '/data/app/com.example.app/base.apk',
          network: 'tcp',
          destinationIPASN: 'AS13335',
          sourceIPASN: '4134',
          destinationGeoIP: const ['US'],
          sourceGeoIP: const ['CN'],
          uid: 10001,
        ),
      );

      QuickRoutingCandidate candidate(RuleAction action) {
        return candidates.singleWhere(
          (candidate) => candidate.ruleAction == action,
        );
      }

      expect(candidate(RuleAction.DOMAIN).content, 'api.example.com');
      expect(candidate(RuleAction.DOMAIN_SUFFIX).content, 'api.example.com');
      expect(candidate(RuleAction.IP_CIDR).content, '1.1.1.1/32');
      expect(candidate(RuleAction.IP_CIDR).noResolve, isTrue);
      expect(candidate(RuleAction.SRC_IP_CIDR).content, '10.0.0.2/32');
      expect(candidate(RuleAction.GEOIP).content, 'US');
      expect(candidate(RuleAction.SRC_GEOIP).content, 'CN');
      expect(candidate(RuleAction.IP_ASN).content, '13335');
      expect(candidate(RuleAction.SRC_IP_ASN).content, '4134');
      expect(candidate(RuleAction.PROCESS_NAME).content, 'com.example.app');
      expect(
        candidate(RuleAction.PROCESS_PATH).content,
        '/data/app/com.example.app/base.apk',
      );
      expect(candidate(RuleAction.UID).content, '10001');
      expect(candidate(RuleAction.NETWORK).content, 'TCP');
      expect(candidate(RuleAction.DST_PORT).content, '443');
      expect(candidate(RuleAction.SRC_PORT).content, '51000');
    });

    test('normalizes bracketed IPv6 and removes duplicate IP choices', () {
      final candidates = buildQuickRoutingCandidates(
        trackerInfo(host: '[2001:db8::1]:443', destinationIP: '2001:db8::1'),
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
    test('keeps built-ins, groups and individual proxies without duplicates', () {
      final targets = buildQuickRoutingTargets(const [
        Group(
          type: GroupType.Selector,
          all: [
            Proxy(name: 'HK-01', type: 'ss'),
            Proxy(name: 'DIRECT', type: 'direct'),
          ],
          name: 'Proxy',
        ),
        Group(
          type: GroupType.URLTest,
          all: [
            Proxy(name: 'HK-01', type: 'ss'),
            Proxy(name: 'JP-01', type: 'vmess'),
          ],
          name: 'Auto',
        ),
        Group(type: GroupType.Selector, all: [], name: 'DIRECT'),
      ]);

      expect(
        targets,
        ['DIRECT', 'REJECT', 'Proxy', 'Auto', 'HK-01', 'JP-01'],
      );
    });

    test('prefers a policy group already present in the connection chain', () {
      final info = trackerInfo(chains: const ['Proxy', 'Hong Kong']);
      final target = pickQuickRoutingTarget(info, const [
        'DIRECT',
        'REJECT',
        'Proxy',
      ]);

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

  group('buildQuickRoutingImpact', () {
    test('previews all recent requests affected by a suffix rule', () {
      const candidate = QuickRoutingCandidate(
        ruleAction: RuleAction.DOMAIN_SUFFIX,
        content: 'api.example.com',
      );
      final impact = buildQuickRoutingImpact(candidate, [
        trackerInfo(host: 'api.example.com', process: 'app.a'),
        trackerInfo(host: 'cdn.api.example.com', process: 'app.b'),
        trackerInfo(host: 'example.com', process: 'app.c'),
      ]);

      expect(impact.requestCount, 2);
      expect(impact.hosts, ['api.example.com', 'cdn.api.example.com']);
      expect(impact.processes, ['app.a', 'app.b']);
    });

    test('matches normalized ASN values', () {
      const candidate = QuickRoutingCandidate(
        ruleAction: RuleAction.IP_ASN,
        content: '13335',
      );
      final impact = buildQuickRoutingImpact(candidate, [
        trackerInfo(destinationIPASN: 'AS13335'),
        trackerInfo(destinationIPASN: '4134'),
      ]);

      expect(impact.requestCount, 1);
    });
  });
}
