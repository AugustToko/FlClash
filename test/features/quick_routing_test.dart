import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/features/features.dart';
import 'package:fl_clash/models/models.dart';
import 'package:test/test.dart';

void main() {
  TrackerInfo trackerInfo({
    String id = 'connection-id',
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
      id: id,
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
          destinationIPASN: 'AS13335 Cloudflare',
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

    test('prefers a policy group over a leaf node in the chain', () {
      final info = trackerInfo(chains: const ['HK-01', 'Proxy']);
      final target = pickQuickRoutingTarget(
        info,
        const ['DIRECT', 'REJECT', 'Proxy', 'HK-01'],
        preferredTargets: const ['Proxy'],
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

  group('buildQuickRoutingImpact', () {
    test('previews all recent requests affected by a suffix rule', () {
      const candidate = QuickRoutingCandidate(
        ruleAction: RuleAction.DOMAIN_SUFFIX,
        content: 'api.example.com',
      );
      final impact = buildQuickRoutingImpact(candidate, [
        trackerInfo(id: 'a', host: 'api.example.com', process: 'app.a'),
        trackerInfo(id: 'b', host: 'cdn.api.example.com', process: 'app.b'),
        trackerInfo(id: 'c', host: 'example.com', process: 'app.c'),
      ]);

      expect(impact.requestCount, 2);
      expect(impact.hosts, ['api.example.com', 'cdn.api.example.com']);
      expect(impact.processes, ['app.a', 'app.b']);
    });

    test('matches complete IPv4 CIDR ranges', () {
      const candidate = QuickRoutingCandidate(
        ruleAction: RuleAction.IP_CIDR,
        content: '10.0.0.0/24',
      );
      final impact = buildQuickRoutingImpact(candidate, [
        trackerInfo(id: 'a', destinationIP: '10.0.0.42'),
        trackerInfo(id: 'b', destinationIP: '10.0.1.42'),
      ]);

      expect(impact.requestCount, 1);
    });

    test('matches complete IPv6 CIDR ranges', () {
      const candidate = QuickRoutingCandidate(
        ruleAction: RuleAction.IP_CIDR6,
        content: '2001:db8::/32',
      );
      final impact = buildQuickRoutingImpact(candidate, [
        trackerInfo(id: 'a', destinationIP: '2001:db8:1::1'),
        trackerInfo(id: 'b', destinationIP: '2001:db9::1'),
      ]);

      expect(impact.requestCount, 1);
    });

    test('matches normalized ASN values', () {
      const candidate = QuickRoutingCandidate(
        ruleAction: RuleAction.IP_ASN,
        content: '13335',
      );
      final impact = buildQuickRoutingImpact(candidate, [
        trackerInfo(id: 'a', destinationIPASN: 'AS13335 Cloudflare'),
        trackerInfo(id: 'b', destinationIPASN: '4134'),
      ]);

      expect(impact.requestCount, 1);
    });

    test('adds a live connection missing from request history', () {
      final current = trackerInfo(id: 'live', host: 'live.example.com');
      final source = buildQuickRoutingImpactSource(current, [
        trackerInfo(id: 'history', host: 'history.example.com'),
      ]);

      expect(source.map((trackerInfo) => trackerInfo.id), [
        'live',
        'history',
      ]);
    });

    test('does not duplicate a connection already in request history', () {
      final current = trackerInfo(id: 'same', host: 'live.example.com');
      final source = buildQuickRoutingImpactSource(current, [current]);

      expect(source, hasLength(1));
      expect(source.single, same(current));
    });
  });

  group('buildQuickRoutingRuleAnalysis', () {
    test('finds an equivalent rule and counts known matches', () {
      final current = trackerInfo(
        host: 'api.example.com',
        process: 'com.example.app',
        chains: const ['DIRECT'],
      );
      const candidate = QuickRoutingCandidate(
        ruleAction: RuleAction.DOMAIN,
        content: 'api.example.com',
      );
      const equivalent = Rule(
        id: 1,
        ruleAction: RuleAction.DOMAIN,
        content: 'api.example.com',
        ruleTarget: 'Proxy',
      );
      final analysis = buildQuickRoutingRuleAnalysis(
        candidate: candidate,
        target: 'DIRECT',
        trackerInfo: current,
        knownRules: const [
          equivalent,
          Rule(
            id: 2,
            ruleAction: RuleAction.DOMAIN_SUFFIX,
            content: 'example.com',
            ruleTarget: 'Proxy',
          ),
          Rule(
            id: 3,
            ruleAction: RuleAction.PROCESS_NAME,
            content: 'com.example.app',
            ruleTarget: 'DIRECT',
          ),
        ],
      );

      expect(analysis.equivalentRule, equivalent);
      expect(analysis.matchingKnownRuleCount, 3);
      expect(analysis.targetAlreadyInChain, isTrue);
      expect(analysis.targetMatchesEquivalentRule('DIRECT'), isFalse);
      expect(analysis.targetMatchesEquivalentRule('Proxy'), isTrue);
    });

    test('ignores unsupported known rule types in the match count', () {
      final analysis = buildQuickRoutingRuleAnalysis(
        candidate: const QuickRoutingCandidate(
          ruleAction: RuleAction.DOMAIN,
          content: 'example.com',
        ),
        target: 'DIRECT',
        trackerInfo: trackerInfo(host: 'example.com'),
        knownRules: const [
          Rule(
            id: 1,
            ruleAction: RuleAction.MATCH,
            ruleTarget: 'Proxy',
          ),
        ],
      );

      expect(analysis.equivalentRule, isNull);
      expect(analysis.matchingKnownRuleCount, 0);
    });
  });
}
