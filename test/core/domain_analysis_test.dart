import 'package:fl_clash/core/controller.dart';
import 'package:fl_clash/core/desktop/model.dart';
import 'package:fl_clash/core/domain_analysis.dart';
import 'package:fl_clash/core/interface.dart';
import 'package:fl_clash/core/method.dart';
import 'package:flutter_test/flutter_test.dart';

class _DomainAnalysisCoreHandler extends CoreHandlerInterface {
  CoreMethod? invokedMethod;
  Object? invokedArguments;

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
    if (method != CoreMethod.analyzeDomain) {
      throw StateError('unexpected method: $method');
    }
    return <String, Object?>{
          'input': 'https://Api.Example.CO.UK/path',
          'normalizedHost': 'api.example.co.uk',
          'isIP': false,
          'publicSuffix': 'co.uk',
          'registrableDomain': 'example.co.uk',
          'icannSuffix': true,
        }
        as T;
  }
}

void main() {
  test('parses a normalized domain analysis result', () {
    final result = CoreDomainAnalysis.fromJson(const {
      'input': '[2001:db8::1]:443',
      'normalizedHost': '2001:db8::1',
      'isIP': true,
      'publicSuffix': '',
      'registrableDomain': '',
      'icannSuffix': false,
    });

    expect(result.normalizedHost, '2001:db8::1');
    expect(result.isIP, isTrue);
    expect(result.hasRegistrableDomain, isFalse);
    expect(result.toJson()['isIP'], isTrue);
  });

  test('controller sends the domain-analysis contract', () async {
    final handler = _DomainAnalysisCoreHandler();
    final controller = CoreController.scoped(handler);

    final result = await controller.analyzeDomain(
      'https://Api.Example.CO.UK/path',
    );

    expect(handler.invokedMethod, CoreMethod.analyzeDomain);
    expect(handler.invokedArguments, {
      'host': 'https://Api.Example.CO.UK/path',
    });
    expect(result.normalizedHost, 'api.example.co.uk');
    expect(result.registrableDomain, 'example.co.uk');
    expect(result.icannSuffix, isTrue);
  });

  test('serializes and parses the analyzeDomain method name', () {
    const call = CoreMethodCall(
      id: 'request-domain',
      method: CoreMethod.analyzeDomain,
      arguments: {'host': 'example.com'},
    );

    expect(call.toJson()['method'], 'analyzeDomain');
    expect(
      CoreMethodCall.fromJson(call.toJson()).method,
      CoreMethod.analyzeDomain,
    );
  });
}
