import 'package:fl_clash/core/controller.dart';
import 'package:fl_clash/core/method.dart';
import 'package:flutter_test/flutter_test.dart';

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
