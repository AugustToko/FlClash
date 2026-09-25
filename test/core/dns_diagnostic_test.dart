import 'package:fl_clash/core/controller.dart';
import 'package:fl_clash/core/desktop/model.dart';
import 'package:fl_clash/core/interface.dart';
import 'package:fl_clash/core/method.dart';
import 'package:flutter_test/flutter_test.dart';

class _DnsDiagnosticCoreHandler extends CoreHandlerInterface {
  CoreMethod? invokedMethod;
  Object? invokedArguments;
  Duration? invokedTimeout;

  @override
  Future<CoreLifecycleResult> start() async => const CoreLifecycleResult(
    revision: 1,
    outcome: CoreLifecycleOutcome.applied,
  );

  @override
  Future<CoreLifecycleResult> restart() => start();

  @override
  Future<CoreLifecycleResult> stop() => start();

  @override
  Future<CoreLifecycleResult> close() => start();

  @override
  Future<T?> invokeMethod<T>({
    required CoreMethod method,
    Object? arguments,
    Duration? timeout,
  }) async {
    invokedMethod = method;
    invokedArguments = arguments;
    invokedTimeout = timeout;
    if (method != CoreMethod.queryDns) {
      throw StateError('unexpected method: $method');
    }
    return <String, dynamic>{
          'input': 'api.example.com',
          'name': 'api.example.com',
          'questionName': 'api.example.com',
          'queryType': 'A',
          'requestedResolver': 'default',
          'resolver': 'system',
          'durationMs': 42,
          'rcode': 0,
          'status': 'NOERROR',
          'authoritative': false,
          'truncated': false,
          'recursionAvailable': true,
          'authenticatedData': false,
          'checkingDisabled': false,
          'complete': true,
          'answers': [
            {
              'section': 'answer',
              'name': 'api.example.com',
              'type': 'CNAME',
              'class': 'IN',
              'ttl': 120,
              'data': 'edge.example.net',
            },
            {
              'section': 'answer',
              'name': 'edge.example.net',
              'type': 'A',
              'class': 'IN',
              'ttl': 60,
              'data': '1.1.1.1',
            },
          ],
          'authority': <Object?>[],
          'additional': <Object?>[],
          'warnings': ['default-resolver-unavailable'],
        }
        as T;
  }
}

void main() {
  test('parses a structured DNS response', () {
    final result = CoreDnsQueryResult.fromJson({
      'input': '1.2.3.4',
      'name': '1.2.3.4',
      'questionName': '4.3.2.1.in-addr.arpa',
      'queryType': 'PTR',
      'requestedResolver': 'direct',
      'resolver': 'direct',
      'durationMs': 18,
      'rcode': 0,
      'status': 'NOERROR',
      'authoritative': true,
      'truncated': false,
      'recursionAvailable': true,
      'authenticatedData': true,
      'checkingDisabled': false,
      'complete': true,
      'answers': [
        {
          'section': 'answer',
          'name': '4.3.2.1.in-addr.arpa',
          'type': 'PTR',
          'class': 'IN',
          'ttl': 300,
          'data': 'host.example.com',
        },
      ],
      'authority': <Object?>[],
      'additional': <Object?>[],
      'warnings': <String>[],
    });

    expect(result.queryType, DnsDiagnosticQueryType.ptr);
    expect(result.requestedResolver, DnsDiagnosticResolver.direct);
    expect(result.resolver, DnsDiagnosticResolver.direct);
    expect(result.answers.single.data, 'host.example.com');
    expect(result.answers.single.ttl, 300);
    expect(result.authoritative, isTrue);
    expect(result.authenticatedData, isTrue);
    expect(result.recordCount, 1);
    expect(result.hasRecords, isTrue);
    expect(result.toJson()['queryType'], 'PTR');
  });

  test('keeps malformed optional collections safe', () {
    final result = CoreDnsQueryResult.fromJson({
      'queryType': 'unknown',
      'requestedResolver': 'unknown',
      'resolver': 'unknown',
      'answers': 'invalid',
      'authority': [null, 'invalid'],
      'additional': null,
      'warnings': [null, 3, 'no-answer-records'],
    });

    expect(result.queryType, DnsDiagnosticQueryType.a);
    expect(result.resolver, DnsDiagnosticResolver.defaultResolver);
    expect(result.answers, isEmpty);
    expect(result.authority, isEmpty);
    expect(result.additional, isEmpty);
    expect(result.warnings, ['no-answer-records']);
    expect(result.hasRecords, isFalse);
  });

  test('controller sends the DNS diagnostic contract', () async {
    final handler = _DnsDiagnosticCoreHandler();
    final controller = CoreController.scoped(handler);

    final result = await controller.queryDns(
      name: 'api.example.com',
      queryType: DnsDiagnosticQueryType.a,
      resolver: DnsDiagnosticResolver.defaultResolver,
      timeout: const Duration(seconds: 4),
    );

    expect(handler.invokedMethod, CoreMethod.queryDns);
    expect(handler.invokedArguments, {
      'name': 'api.example.com',
      'queryType': 'A',
      'resolver': 'default',
      'timeoutMs': 4000,
    });
    expect(handler.invokedTimeout, const Duration(seconds: 6));
    expect(result.status, 'NOERROR');
    expect(result.resolver, DnsDiagnosticResolver.system);
    expect(result.answers, hasLength(2));
    expect(result.warnings, ['default-resolver-unavailable']);
  });

  test('serializes and parses the queryDns protocol method name', () {
    const call = CoreMethodCall(
      id: 'request-dns',
      method: CoreMethod.queryDns,
      arguments: {
        'name': 'example.com',
        'queryType': 'AAAA',
        'resolver': 'system',
        'timeoutMs': 5000,
      },
    );

    expect(call.toJson()['method'], 'queryDns');
    expect(CoreMethodCall.fromJson(call.toJson()).method, CoreMethod.queryDns);
  });
}
