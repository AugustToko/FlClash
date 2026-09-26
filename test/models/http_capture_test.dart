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
  ProtocolObservation? observation,
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
    observation: observation,
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
    expect(
      rootExtension['limitations'],
      contains('initial-client-prefix-only'),
    );
    expect(
      rootExtension['limitations'],
      contains('later-keep-alive-requests-not-captured'),
    );
    expect(
      rootExtension['limitations'],
      contains('request-header-values-not-captured'),
    );
    expect(
      rootExtension['limitations'],
      contains('response-body-not-captured'),
    );

    final encoded = encodeHttpCaptureHar(entries: [entry]);
    expect(jsonDecode(encoded), isA<Map<String, dynamic>>());
    expect(encoded, isNot(contains('Authorization')));
  });

  test(
    'Core HTTP/1 metadata overrides port guesses without retaining values',
    () {
      const observation = ProtocolObservation(
        sessionId: 'session-http1',
        kind: 'http1',
        observedBytes: 148,
        http: HttpProtocolObservation(
          method: 'GET',
          target: '/v1/models',
          version: 'HTTP/1.1',
          host: 'api.openai.com',
          headerNames: ['host', 'authorization', 'accept'],
          headersComplete: true,
          targetTruncated: true,
          hostTruncated: true,
        ),
        httpResponse: HttpResponseProtocolObservation(
          version: 'HTTP/1.1',
          statusCode: 200,
          informationalStatusCodes: [100],
          headerNames: ['content-type', 'set-cookie'],
          headersComplete: true,
          observedBytes: 93,
          observedAfterMilliseconds: 42,
        ),
      );
      final entry = HttpCaptureEntry.fromTracker(
        id: 12,
        tracker: tracker(
          host: '',
          destinationPort: '80',
          observation: observation,
        ),
        sessionId: 'session-http1',
        profileId: 7,
      );

      expect(entry.protocol, HttpCaptureProtocol.http);
      expect(entry.evidence, 'core-http1');
      expect(entry.host, 'api.openai.com');
      expect(entry.requestUrl, 'http://api.openai.com/v1/models');
      expect(entry.httpObservation?.headerNames, contains('authorization'));

      final decoded = HttpCaptureEntry.decodePayload(entry.encodePayload());
      expect(decoded.observation?.sessionId, 'session-http1');
      expect(decoded.observation?.kind, 'http1');
      expect(decoded.httpObservation?.method, 'GET');
      expect(decoded.httpObservation?.targetTruncated, isTrue);
      expect(decoded.httpObservation?.hostTruncated, isTrue);
      expect(decoded.httpResponseObservation?.statusCode, 200);
      expect(decoded.httpResponseObservation?.informationalStatusCodes, [100]);
      expect(decoded.httpResponseObservation?.headerNames, [
        'content-type',
        'set-cookie',
      ]);
      expect(decoded.searchText, contains('200'));
      expect(decoded.searchText, contains('set-cookie'));
      expect(decoded.toTrackerInfo().observation?.sessionId, 'session-http1');
      expect(decoded.toTrackerInfo().observation?.observedBytes, 148);

      final payload = buildHttpCaptureHar(entries: [entry]);
      final log = payload['log']! as Map<String, Object?>;
      final harEntry =
          (log['entries']! as List<Object?>).single! as Map<String, Object?>;
      final request = harEntry['request']! as Map<String, Object?>;
      final response = harEntry['response']! as Map<String, Object?>;
      final extension = harEntry['_flclash']! as Map<String, Object?>;

      expect(request['method'], 'GET');
      expect(request['url'], 'http://api.openai.com/v1/models');
      expect(request['httpVersion'], 'HTTP/1.1');
      expect(request['headers'], isEmpty);
      expect(response['status'], 200);
      expect(response['statusText'], '');
      expect(response['httpVersion'], 'HTTP/1.1');
      expect(response['headers'], isEmpty);
      expect(extension['headerNames'], contains('authorization'));
      expect(extension['responseObserved'], isTrue);
      expect(extension['responseReasonPhraseCaptured'], isFalse);
      expect(extension['responseHeaderNames'], ['content-type', 'set-cookie']);
      expect(extension['responseObservedAfterMilliseconds'], 42);
      final encoded = jsonEncode(payload);
      expect(encoded, isNot(contains('Bearer')));
      expect(encoded, isNot(contains('api_key=')));
      expect(encoded, isNot(contains('private-reason')));
      expect(encoded, isNot(contains('private-cookie')));
      expect(encoded, isNot(contains('private-body')));
    },
  );

  test('TLS ClientHello metadata supplies SNI, ALPN and version evidence', () {
    const observation = ProtocolObservation(
      kind: 'tls-client-hello',
      observedBytes: 312,
      tls: TlsClientHelloObservation(
        serverName: 'edge.example.com',
        alpn: ['h2', 'http/1.1'],
        legacyVersion: 'TLS 1.2',
        supportedVersions: ['TLS 1.3', 'TLS 1.2'],
        encryptedClientHello: true,
        clientHelloComplete: true,
      ),
    );
    final source = tracker(
      network: 'tcp',
      host: '',
      destinationPort: '9443',
      observation: observation,
    );

    expect(shouldCaptureHttpObservation(source), isTrue);
    final entry = HttpCaptureEntry.fromTracker(
      id: 13,
      tracker: source,
      sessionId: 'session-tls',
      profileId: null,
    );

    expect(entry.protocol, HttpCaptureProtocol.tls);
    expect(entry.evidence, 'core-tls-client-hello');
    expect(entry.host, 'edge.example.com');
    expect(entry.tlsObservation?.alpn, ['h2', 'http/1.1']);
    expect(entry.searchText, contains('tls 1.3'));
    expect(entry.searchText, contains('ech'));
  });

  test('Core observation JSON is bounded defensively on the Dart side', () {
    final observation = ProtocolObservation.fromJson({
      'kind': 'k' * 100,
      'observedBytes': 999999,
      'http': {
        'method': 'M' * 100,
        'target': '/${'x' * 1000}',
        'version': 'HTTP/1.1${'v' * 100}',
        'host': '${'A' * 300}.EXAMPLE',
        'headerNames': [
          for (var index = 0; index < 100; index++)
            'X-${index.toString().padLeft(3, '0')}-${'H' * 200}',
        ],
      },
      'httpResponse': {
        'version': 'HTTP/1.1${'r' * 100}',
        'statusCode': 9999,
        'informationalStatusCodes': [
          for (var index = 0; index < 20; index++) 100 + (index % 50),
          200,
        ],
        'headerNames': [
          for (var index = 0; index < 100; index++)
            'X-Response-${index.toString().padLeft(3, '0')}-${'R' * 200}',
        ],
        'observedBytes': 999999,
        'observedAfterMilliseconds': 999999999999,
      },
      'tls': {
        'serverName': '${'S' * 300}.EXAMPLE',
        'alpn': [for (var index = 0; index < 40; index++) 'p$index'],
        'legacyVersion': 'TLS ${'v' * 100}',
        'supportedVersions': [
          for (var index = 0; index < 40; index++) 'version-$index',
        ],
      },
    });

    expect(observation.kind.length, 32);
    expect(observation.observedBytes, 32 * 1024);
    expect(observation.http?.method.length, 16);
    expect(observation.http?.target.length, 512);
    expect(observation.http?.version.length, 16);
    expect(observation.http?.host.length, 255);
    expect(observation.http?.host, observation.http?.host.toLowerCase());
    expect(observation.http?.headerNames, hasLength(64));
    expect(
      observation.http!.headerNames.every((name) => name.length <= 128),
      isTrue,
    );
    expect(observation.httpResponse?.version.length, 16);
    expect(observation.httpResponse?.statusCode, 0);
    expect(observation.httpResponse?.informationalStatusCodes, hasLength(8));
    expect(observation.httpResponse?.headerNames, hasLength(64));
    expect(
      observation.httpResponse!.headerNames.every((name) => name.length <= 128),
      isTrue,
    );
    expect(observation.httpResponse?.observedBytes, 32 * 1024);
    expect(observation.httpResponse?.observedAfterMilliseconds, 0x7fffffff);
    expect(observation.tls?.serverName.length, 255);
    expect(observation.tls?.alpn, hasLength(16));
    expect(observation.tls?.legacyVersion.length, 32);
    expect(observation.tls?.supportedVersions, hasLength(16));
  });

  test('response metadata is ignored outside an HTTP/1 observation', () {
    const observation = ProtocolObservation(
      kind: 'tls-client-hello',
      tls: TlsClientHelloObservation(serverName: 'secure.example'),
      httpResponse: HttpResponseProtocolObservation(
        version: 'HTTP/1.1',
        statusCode: 200,
        headersComplete: true,
      ),
    );
    final entry = HttpCaptureEntry.fromTracker(
      id: 14,
      tracker: tracker(
        host: '',
        destinationPort: '443',
        observation: observation,
      ),
      sessionId: 'session-tls',
      profileId: null,
    );

    expect(entry.protocol, HttpCaptureProtocol.tls);
    expect(entry.httpResponseObservation, isNull);
    final payload = buildHttpCaptureHar(entries: [entry]);
    final log = payload['log']! as Map<String, Object?>;
    final harEntry =
        (log['entries']! as List<Object?>).single! as Map<String, Object?>;
    final response = harEntry['response']! as Map<String, Object?>;
    expect(response['status'], 0);
  });

  test('a Core observation remains eligible even without a candidate port', () {
    const observation = ProtocolObservation(
      kind: 'http1',
      observedBytes: 64,
      http: HttpProtocolObservation(
        method: 'OPTIONS',
        target: '*',
        version: 'HTTP/1.1',
        headersComplete: true,
      ),
    );
    expect(
      shouldCaptureHttpObservation(
        tracker(
          network: 'udp',
          host: '',
          destinationPort: '53',
          observation: observation,
        ),
      ),
      isTrue,
    );
  });
}
