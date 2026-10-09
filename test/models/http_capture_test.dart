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
      contains('passive-sources-first-http1-transaction-only'),
    );
    expect(
      rootExtension['limitations'],
      contains('inspected-runtime-at-most-32-http1-transactions'),
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

  test('inspected runtime timelines round-trip and flatten into HAR', () {
    final started = DateTime.utc(2026, 10, 7, 2);
    final observation = TlsInspectionRuntimeObservation.fromJson({
      'sessionId': 'http-capture:456',
      'connectionId': '0123456789abcdef0123456789abcdef',
      'runtimeId': 'abcdef0123456789abcdef0123456789',
      'host': 'api.example.com',
      'state': 'completed',
      'startedAt': started.toIso8601String(),
      'completedAt': started.add(const Duration(seconds: 2)).toIso8601String(),
      'downstreamTlsVersion': 'TLS 1.3',
      'upstreamTlsVersion': 'TLS 1.3',
      'alpn': 'http/1.1',
      'uploaded': 123,
      'downloaded': 456,
      'httpTransactionsTruncated': true,
      'httpTransactions': [
        {
          'sequence': 1,
          'requestObservedAfterMilliseconds': 4,
          'request': {
            'method': 'GET',
            'target': '/items',
            'version': 'HTTP/1.1',
            'host': 'api.example.com',
            'headerNames': ['host', 'authorization'],
            'headersComplete': true,
          },
          'response': {
            'version': 'HTTP/1.1',
            'statusCode': 201,
            'headerNames': ['content-type', 'set-cookie'],
            'headersComplete': true,
            'observedBytes': 96,
            'observedAfterMilliseconds': 18,
          },
        },
        {
          'sequence': 2,
          'requestObservedAfterMilliseconds': 24,
          'request': {
            'method': 'POST',
            'target': '/items/next',
            'version': 'HTTP/1.1',
            'host': 'api.example.com',
            'headerNames': ['host', 'content-length'],
            'headersComplete': true,
          },
          'response': {
            'version': 'HTTP/1.1',
            'statusCode': 204,
            'headerNames': ['x-request-id'],
            'headersComplete': true,
            'observedBytes': 48,
            'observedAfterMilliseconds': 31,
          },
        },
      ],
    });
    final entry = HttpCaptureEntry.fromInspectionRuntime(
      id: 99,
      observation: observation,
      profileId: 7,
    );
    expect(HttpCaptureEntry.formatVersion, 6);
    expect(entry.source, HttpCaptureSource.inspectedRuntime);
    expect(entry.isInspectedRuntime, isTrue);
    expect(entry.isCoreObserved, isFalse);
    expect(entry.protocol, HttpCaptureProtocol.http);
    expect(entry.host, 'api.example.com');
    expect(entry.origin, 'https://api.example.com');
    expect(entry.requestUrl, 'https://api.example.com/items');
    expect(entry.httpTransactionCount, 2);
    expect(entry.httpTransactions.last.request.target, '/items/next');
    expect(entry.httpTimelineTruncated, isTrue);
    expect(entry.searchText, contains('/items/next'));
    expect(entry.searchText, contains('204'));
    expect(entry.searchText, contains('timeline-truncated'));

    final roundTrip = HttpCaptureEntry.decodePayload(entry.encodePayload());
    expect(roundTrip.source, HttpCaptureSource.inspectedRuntime);
    expect(roundTrip.inspectionRuntime?.state, 'completed');
    expect(roundTrip.httpTransactions, hasLength(2));
    expect(roundTrip.httpTransactions.last.response?.statusCode, 204);
    expect(roundTrip.toJson()['version'], 6);

    final har = buildHttpCaptureHar(entries: [entry]);
    final log = har['log']! as Map<String, Object?>;
    final rootExtension = log['_flclash']! as Map<String, Object?>;
    final exported = log['entries']! as List<Object?>;
    expect(exported, hasLength(2));
    expect(rootExtension['version'], 6);
    expect(rootExtension['observationOnly'], isFalse);
    expect(rootExtension['includesInspectedRuntime'], isTrue);
    for (var index = 0; index < exported.length; index++) {
      final harEntry = exported[index]! as Map<String, Object?>;
      final extension = harEntry['_flclash']! as Map<String, Object?>;
      expect(extension['source'], 'inspected-runtime');
      expect(extension['observationOnly'], isFalse);
      expect(extension['metadataOnly'], isTrue);
      expect(extension['transactionSequence'], index + 1);
      expect(extension['transactionCount'], 2);
      expect(extension['timelineTruncated'], isTrue);
      expect(
        extension['parentConnectionStartedDateTime'],
        started.toIso8601String(),
      );
      final runtime = extension['inspectionRuntime']! as Map<String, Object?>;
      expect(runtime, isNot(contains('httpTransactions')));
      expect(runtime, isNot(contains('httpTransactionsTruncated')));
    }
    final first = exported.first! as Map<String, Object?>;
    final second = exported.last! as Map<String, Object?>;
    expect(
      (first['request']! as Map<String, Object?>)['url'],
      'https://api.example.com/items',
    );
    expect((first['response']! as Map<String, Object?>)['status'], 201);
    expect(
      (second['request']! as Map<String, Object?>)['url'],
      'https://api.example.com/items/next',
    );
    expect((second['response']! as Map<String, Object?>)['status'], 204);
    final encoded = jsonEncode(har);
    expect(encoded, isNot(contains('Bearer private-token')));
    expect(encoded, isNot(contains('session=private-cookie')));
  });

  test('legacy v5 inspected runtime rows decode into one v6 transaction', () {
    final started = DateTime.utc(2026, 10, 7, 2);
    final legacyRuntime = {
      'sessionId': 'http-capture:legacy-v5',
      'connectionId': '0123456789abcdef0123456789abcdef',
      'runtimeId': 'abcdef0123456789abcdef0123456789',
      'host': 'api.example.com',
      'state': 'completed',
      'startedAt': started.toIso8601String(),
      'completedAt': started.add(const Duration(seconds: 1)).toIso8601String(),
      'downstreamTlsVersion': 'TLS 1.3',
      'upstreamTlsVersion': 'TLS 1.3',
      'alpn': 'http/1.1',
      'uploaded': 64,
      'downloaded': 128,
      'httpRequest': {
        'method': 'GET',
        'target': '/legacy',
        'version': 'HTTP/1.1',
        'host': 'api.example.com',
        'headersComplete': true,
      },
      'httpResponse': {
        'version': 'HTTP/1.1',
        'statusCode': 200,
        'headersComplete': true,
        'observedBytes': 32,
        'observedAfterMilliseconds': 8,
      },
    };
    final observation = TlsInspectionRuntimeObservation.fromJson(
      Map<String, Object?>.from(legacyRuntime),
    );
    expect(observation.httpTransactions, hasLength(1));
    expect(observation.httpTransactions.single.request.target, '/legacy');
    expect(observation.toJson(), contains('httpTransactions'));
    expect(observation.toJson(), isNot(contains('httpRequest')));

    final entry = HttpCaptureEntry.fromInspectionRuntime(
      id: 100,
      observation: observation,
      profileId: null,
    );
    final legacyPayload = Map<String, Object?>.from(entry.toJson())
      ..['version'] = 5
      ..['inspectionRuntime'] = legacyRuntime;
    final decoded = HttpCaptureEntry.fromJson(legacyPayload);
    expect(decoded.httpTransactionCount, 1);
    expect(decoded.httpObservation?.target, '/legacy');
  });

  test('capture source is derived from verified payload content', () {
    final started = DateTime.utc(2026, 10, 7, 2);
    final runtime = TlsInspectionRuntimeObservation.fromJson({
      'sessionId': 'http-capture:source',
      'connectionId': '0123456789abcdef0123456789abcdef',
      'runtimeId': 'abcdef0123456789abcdef0123456789',
      'host': 'api.example.com',
      'state': 'interrupted',
      'startedAt': started.toIso8601String(),
      'completedAt': started.add(const Duration(seconds: 1)).toIso8601String(),
      'downstreamTlsVersion': '',
      'upstreamTlsVersion': '',
      'alpn': '',
      'uploaded': 0,
      'downloaded': 0,
      'failureKind': 'capture-interrupted',
    });
    final entry = HttpCaptureEntry.fromInspectionRuntime(
      id: 101,
      observation: runtime,
      profileId: null,
    );
    final tampered = Map<String, Object?>.from(entry.toJson())
      ..['source'] = 'passive-core';
    final decoded = HttpCaptureEntry.fromJson(tampered);
    expect(decoded.source, HttpCaptureSource.inspectedRuntime);
    expect(decoded.inspectionRuntime?.state, 'interrupted');

    final candidate = HttpCaptureEntry.fromTracker(
      id: 102,
      tracker: tracker(host: 'example.com', destinationPort: '443'),
      sessionId: 'source-session',
      profileId: null,
    );
    final mislabeled = Map<String, Object?>.from(candidate.toJson())
      ..['source'] = 'inspected-runtime';
    expect(
      HttpCaptureEntry.fromJson(mislabeled).source,
      HttpCaptureSource.connectionCandidate,
    );
  });

  test('legacy capture payloads derive their source without migration', () {
    final trackerEntry = HttpCaptureEntry.fromTracker(
      id: 100,
      tracker: tracker(host: 'example.com', destinationPort: '443'),
      sessionId: 'legacy-session',
      profileId: null,
    );
    final legacy = Map<String, Object?>.from(trackerEntry.toJson())
      ..remove('source')
      ..['version'] = 4;
    expect(
      HttpCaptureEntry.fromJson(legacy).source,
      HttpCaptureSource.connectionCandidate,
    );
  });
}
