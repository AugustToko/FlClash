import 'package:fl_clash/core/controller.dart';
import 'package:fl_clash/core/desktop/model.dart';
import 'package:fl_clash/core/interface.dart';
import 'package:fl_clash/core/method.dart';
import 'package:flutter_test/flutter_test.dart';

class _DomainAnalysisCoreHandler extends CoreHandlerInterface {
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
    if (method != CoreMethod.analyzeDomain) {
      throw StateError('unexpected method: $method');
    }
    return <String, dynamic>{
      'input': 'api.example.co.uk',
      'normalizedHost': 'api.example.co.uk',
      'isIP': false,
      'publicSuffix': 'co.uk',
      'registrableDomain': 'example.co.uk',
      'icannSuffix': true,
    } as T;
  }
}

void main() {
  test('parses ICANN registrable-domain analysis', () {
    final result = CoreDomainAnalysis.fromJson({
      'input': 'api.example.co.uk',
      'normalizedHost': 'api.example.co.uk',
      'isIP': false,
      'publicSuffix': 'co.uk',
      'registrableDomain': 'example.co.uk',
      'icannSuffix': true,
    });

    expect(result.normalizedHost, 'api.example.co.uk');
    expect(result.publicSuffix, 'co.uk');
    expect(result.registrableDomain, 'example.co.uk');
    expect(result.hasRegistrableDomain, isTrue);
    expect(result.icannSuffix, isTrue);
  });

  test('keeps non-ICANN suffixes explicit', () {
    final result = CoreDomainAnalysis.fromJson({
      'normalizedHost': 'bar.foo.github.io',
      'publicSuffix': 'github.io',
      'registrableDomain': 'foo.github.io',
      'icannSuffix': false,
    });

    expect(result.hasRegistrableDomain, isTrue);
    expect(result.icannSuffix, isFalse);
  });

  test('does not expose an IP address as a domain scope', () {
    final result = CoreDomainAnalysis.fromJson({
      'normalizedHost': '2001:db8::1',
      'isIP': true,
    });

    expect(result.hasRegistrableDomain, isFalse);
    expect(result.publicSuffix, isEmpty);
    expect(result.registrableDomain, isEmpty);
  });

  test('controller sends the domain analysis contract', () async {
    final handler = _DomainAnalysisCoreHandler();
    final controller = CoreController.scoped(handler);

    final result = await controller.analyzeDomain('api.example.co.uk');

    expect(handler.invokedMethod, CoreMethod.analyzeDomain);
    expect(handler.invokedArguments, {'host': 'api.example.co.uk'});
    expect(handler.invokedTimeout, const Duration(seconds: 5));
    expect(result.registrableDomain, 'example.co.uk');
  });

  test('serializes and parses the analyzeDomain protocol method name', () {
    const call = CoreMethodCall(
      id: 'request-domain',
      method: CoreMethod.analyzeDomain,
      arguments: {'host': 'api.example.com'},
    );

    expect(call.toJson(), {
      'id': 'request-domain',
      'method': 'analyzeDomain',
      'arguments': {'host': 'api.example.com'},
    });
    expect(
      CoreMethodCall.fromJson(call.toJson()).method,
      CoreMethod.analyzeDomain,
    );
  });
}
