import 'dart:convert';

import 'package:fl_clash/models/models.dart';
import 'package:flutter_test/flutter_test.dart';

TrackerInfo tracker({
  String id = 'connection-1',
  String network = 'tcp',
  String host = 'api.example.com',
  String destinationIP = '1.1.1.1',
  String destinationPort = '443',
  String sourceIP = '10.0.0.2',
  String sourcePort = '54321',
  String remoteDestination = '',
}) {
  return TrackerInfo(
    id: id,
    upload: 12,
    download: 34,
    start: DateTime.utc(2026, 9, 25, 10),
    metadata: Metadata(
      uid: 10001,
      network: network,
      sourceIP: sourceIP,
      sourcePort: sourcePort,
      destinationIP: destinationIP,
      destinationPort: destinationPort,
      host: host,
      process: 'com.example.app',
      processPath: '/data/app/com.example.app',
      remoteDestination: remoteDestination,
    ),
    chains: const ['Proxy', 'HK-01'],
    rule: 'DomainSuffix',
    rulePayload: 'example.com',
  );
}

void main() {
  test('classifies common HTTP, TLS, QUIC and host-only observations', () {
    expect(
      classifyHttpObservation(
        network: 'tcp',
        port: 80,
        host: 'example.com',
        remoteDestination: '',
      ),
      (protocol: HttpCaptureProtocol.http, evidence: 'known-http-port'),
    );
    expect(
      classifyHttpObservation(
        network: 'tcp',
        port: 443,
        host: 'example.com',
        remoteDestination: '',
      ),
      (protocol: HttpCaptureProtocol.tls, evidence: 'known-tls-port'),
    );
    expect(
      classifyHttpObservation(
        network: 'udp',
        port: 443,
        host: 'example.com',
        remoteDestination: '',
      ),
      (protocol: HttpCaptureProtocol.quic, evidence: 'known-quic-port'),
    );
    expect(
      classifyHttpObservation(
        network: 'tcp',
        port: 12345,
        host: 'example.com',
        remoteDestination: '',
      ),
      (protocol: HttpCaptureProtocol.unknown, evidence: 'host-observed'),
    );
  });

  test('remote scheme takes precedence over a non-standard port', () {
    final result = classifyHttpObservation(
      network: 'tcp',
      port: 12345,
      host: 'example.com',
      remoteDestination: 'https://edge.example.com:12345',
    );

    expect(result.protocol, HttpCaptureProtocol.tls);
    expect(result.evidence, 'remote-scheme');
  });

  test(
    'captures likely HTTP observations but ignores unrelated UDP traffic',
    () {
      expect(shouldCaptureHttpObservation(tracker()), isTrue);
      expect(
        shouldCaptureHttpObservation(
          tracker(network: 'udp', destinationPort: '53', host: 'dns.example'),
        ),
        isFalse,
      );
      expect(
        shouldCaptureHttpObservation(
          tracker(network: 'udp', destinationPort: '443'),
        ),
        isTrue,
      );
    },
  );

  test(
    'round trips a capture entry and reconstructs quick-routing metadata',
    () {
      final observedAt = DateTime.utc(2026, 9, 25, 10, 0, 1);
      final entry = HttpCaptureEntry.fromTracker(
        id: 9,
        tracker: tracker(),
        sessionId: 'session-1',
        profileId: 7,
        observedAt: observedAt,
      );

      final decoded = HttpCaptureEntry.decodePayload(entry.encodePayload());

      expect(decoded.id, 9);
      expect(decoded.sessionId, 'session-1');
      expect(decoded.profileId, 7);
      expect(decoded.protocol, HttpCaptureProtocol.tls);
      expect(decoded.origin, 'https://api.example.com');
      expect(decoded.observationDelayMs, 1000);
      expect(decoded.ruleText, 'DomainSuffix(example.com)');
      expect(decoded.chains, ['Proxy', 'HK-01']);
      expect(decoded.toTrackerInfo().metadata.destinationPort, '443');
      expect(decoded.toTrackerInfo().metadata.process, 'com.example.app');
    },
  );

  test('formats IPv6 authority without losing its port', () {
    final entry = HttpCaptureEntry.fromTracker(
      id: 10,
      tracker: tracker(
        host: '',
        destinationIP: '2001:db8::1',
        destinationPort: '8443',
      ),
      sessionId: 'session-ipv6',
      profileId: null,
    );

    expect(entry.origin, 'https://[2001:db8::1]:8443');
  });

  test('HAR export is explicit about observation-only limitations', () {
    final entry = HttpCaptureEntry.fromTracker(
      id: 11,
      tracker: tracker(),
      sessionId: 'session-har',
      profileId: 7,
      observedAt: DateTime.utc(2026, 9, 25, 10, 0, 1),
    );

    final payload = buildHttpCaptureHar(
      entries: [entry],
      exportedAt: DateTime.utc(2026, 9, 25, 11),
    );
    final log = payload['log']! as Map<String, Object?>;
    final entries = log['entries']! as List<Object?>;
    final harEntry = entries.single! as Map<String, Object?>;
    final request = harEntry['request']! as Map<String, Object?>;
    final response = harEntry['response']! as Map<String, Object?>;
    final extension = harEntry['_flclash']! as Map<String, Object?>;
    final rootExtension = log['_flclash']! as Map<String, Object?>;

    expect(request['method'], 'UNKNOWN');
    expect(request['url'], 'https://api.example.com/');
    expect(response['status'], 0);
    expect(extension['observationOnly'], isTrue);
    expect(extension['sessionId'], 'session-har');
    expect(extension['protocol'], 'tls');
    expect(rootExtension['limitations'], contains('headers-not-captured'));
    expect(rootExtension['limitations'], contains('body-not-captured'));

    final encoded = encodeHttpCaptureHar(entries: [entry]);
    expect(jsonDecode(encoded), isA<Map<String, dynamic>>());
    expect(encoded, isNot(contains('Authorization')));
  });
}
