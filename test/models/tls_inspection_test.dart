import 'package:fl_clash/models/models.dart';
import 'package:flutter_test/flutter_test.dart';

const _fingerprintA =
    'AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA';
const _fingerprintB =
    'BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB';
const _generationA = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

TlsInspectionAuthorityStatus _validAuthority({
  String fingerprint = _fingerprintA,
  DateTime? notBefore,
  DateTime? notAfter,
}) => TlsInspectionAuthorityStatus(
  state: 'ready',
  ready: true,
  generation: _generationA,
  fingerprintSha256: fingerprint,
  subject: 'O=FlClash,CN=FlClash Local Inspection CA',
  serialNumber: '01',
  notBefore: notBefore ?? DateTime.utc(2020),
  notAfter: notAfter ?? DateTime.utc(2099),
  algorithm: 'ECDSA P-256 / SHA-256',
  keyStorage: 'app-data-file',
  keyPermissionsRestricted: true,
  trustCapability: 'manual-only',
);

void main() {
  test('domain rules distinguish exact and subtree scopes', () {
    const exact = TlsInspectionDomainRule(
      host: 'api.example.com',
      scope: TlsInspectionRuleScope.exact,
    );
    const subtree = TlsInspectionDomainRule(
      host: 'example.com',
      scope: TlsInspectionRuleScope.subdomains,
    );

    expect(exact.matches('API.EXAMPLE.COM.'), isTrue);
    expect(exact.matches('www.example.com'), isFalse);
    expect(subtree.matches('example.com'), isTrue);
    expect(subtree.matches('api.example.com'), isTrue);
    expect(subtree.matches('notexample.com'), isFalse);
  });

  test('exclusions always override a broader allowlist', () {
    const policy = TlsInspectionPolicy(
      prepared: true,
      acknowledgedRiskVersion: tlsInspectionRiskVersion,
      manuallyTrustedFingerprint: _fingerprintA,
      allowlist: [
        TlsInspectionDomainRule(
          host: 'example.com',
          scope: TlsInspectionRuleScope.subdomains,
        ),
      ],
      exclusions: [
        TlsInspectionDomainRule(
          host: 'accounts.example.com',
          scope: TlsInspectionRuleScope.exact,
        ),
      ],
    );
    final authority = _validAuthority();

    expect(policy.canPrepareWith(authority), isTrue);
    expect(policy.matchesAllowlist('api.example.com'), isTrue);
    expect(policy.matchesAllowlist('accounts.example.com'), isFalse);
  });

  test('policy JSON is bounded, deduplicated, and backwards compatible', () {
    final rawRules = List.generate(
      260,
      (index) => {
        'host': index.isEven
            ? 'api$index.example.com.'
            : 'API$index.EXAMPLE.COM',
        'scope': index % 3 == 0 ? 'subdomains' : 'exact',
      },
    );
    rawRules.add({'host': 'api0.example.com', 'scope': 'subdomains'});

    final policy = TlsInspectionPolicy.fromJson({
      'formatVersion': tlsInspectionPolicyFormatVersion,
      'prepared': true,
      'acknowledgedRiskVersion': 999,
      'allowlist': rawRules,
      'exclusions': 'invalid',
      'manuallyTrustedFingerprint': 'F' * 300,
      'updatedAt': '2026-09-27T00:00:00Z',
    });

    expect(policy.formatVersion, tlsInspectionPolicyFormatVersion);
    expect(policy.acknowledgedRiskVersion, tlsInspectionRiskVersion);
    expect(
      policy.allowlist.length,
      lessThanOrEqualTo(tlsInspectionMaxRulesPerList),
    );
    expect(
      policy.allowlist.every((rule) => rule.host == rule.host.toLowerCase()),
      isTrue,
    );
    expect(policy.exclusions, isEmpty);
    expect(policy.manuallyTrustedFingerprint.length, 128);
    expect(
      TlsInspectionPolicy.fromJson(policy.toJson()).allowlist,
      policy.allowlist,
    );
  });

  test('unknown future policy formats keep rules but fail closed', () {
    final policy = TlsInspectionPolicy.fromJson({
      'formatVersion': tlsInspectionPolicyFormatVersion + 1,
      'prepared': true,
      'acknowledgedRiskVersion': tlsInspectionRiskVersion,
      'manuallyTrustedFingerprint': _fingerprintA,
      'allowlist': [
        {'host': 'example.com', 'scope': 'exact'},
      ],
    });

    expect(policy.formatVersion, tlsInspectionPolicyFormatVersion);
    expect(policy.prepared, isFalse);
    expect(policy.acknowledgedRiskVersion, 0);
    expect(policy.manuallyTrustedFingerprint, isEmpty);
    expect(policy.allowlist, hasLength(1));
  });

  test('malformed persisted domain rules are dropped', () {
    final policy = TlsInspectionPolicy.fromJson({
      'allowlist': [
        {'host': 'bad domain.example', 'scope': 'exact'},
        {'host': '-bad.example', 'scope': 'subdomains'},
        {'host': 'valid.example', 'scope': 'exact'},
      ],
    });

    expect(policy.allowlist, [
      const TlsInspectionDomainRule(
        host: 'valid.example',
        scope: TlsInspectionRuleScope.exact,
      ),
    ]);
  });

  test('manual trust is bound to the current authority fingerprint', () {
    final authority = _validAuthority();
    const stale = TlsInspectionPolicy(
      acknowledgedRiskVersion: tlsInspectionRiskVersion,
      manuallyTrustedFingerprint: _fingerprintB,
      allowlist: [
        TlsInspectionDomainRule(
          host: 'example.com',
          scope: TlsInspectionRuleScope.exact,
        ),
      ],
    );

    expect(stale.manuallyTrusts(authority), isFalse);
    expect(stale.canPrepareWith(authority), isFalse);
    final current = stale.copyWith(manuallyTrustedFingerprint: _fingerprintA);
    expect(current.canPrepareWith(authority), isTrue);
  });

  test('an expired authority cannot satisfy preparation after load', () {
    final authority = _validAuthority(
      notBefore: DateTime.now().toUtc().subtract(const Duration(days: 2)),
      notAfter: DateTime.now().toUtc().subtract(const Duration(days: 1)),
    );
    const policy = TlsInspectionPolicy(
      acknowledgedRiskVersion: tlsInspectionRiskVersion,
      manuallyTrustedFingerprint: _fingerprintA,
      allowlist: [
        TlsInspectionDomainRule(
          host: 'example.com',
          scope: TlsInspectionRuleScope.exact,
        ),
      ],
    );

    expect(authority.validNow, isFalse);
    expect(policy.manuallyTrusts(authority), isFalse);
    expect(policy.canPrepareWith(authority), isFalse);
    expect(policy.canPrepareWith(authority, trustSatisfied: true), isFalse);
  });

  test('authority status parsing drops malformed dates and bounds fields', () {
    final value = TlsInspectionAuthorityStatus.fromJson({
      'state': 'ready',
      'ready': true,
      'fingerprintSha256': 'A' * 300,
      'subject': 'S' * 900,
      'notBefore': 'invalid',
      'notAfter': '2029-09-27T00:00:00Z',
      'keyPermissionsRestricted': true,
    });

    expect(value.fingerprintSha256.length, 128);
    expect(value.subject.length, 512);
    expect(value.notBefore, isNull);
    expect(value.notAfter, DateTime.utc(2029, 9, 27));
    expect(value.keyPermissionsRestricted, isTrue);
    expect(value.validNow, isFalse);
  });

  test('public certificate exports reject private keys and unsafe names', () {
    final valid = TlsInspectionAuthorityExport.fromJson({
      'fileName': '../../unsafe.pem',
      'pem': '-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n',
      'fingerprintSha256': _fingerprintA,
    });
    expect(valid.fileName, 'flclash-local-inspection-ca.crt');
    expect(valid.valid, isTrue);

    final unsafe = TlsInspectionAuthorityExport.fromJson({
      'fileName': 'authority.crt',
      'pem': '-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----',
      'fingerprintSha256': _fingerprintA,
    });
    expect(unsafe.pem, isEmpty);
    expect(unsafe.valid, isFalse);
  });

  test('authority readiness requires the complete supported contract', () {
    final valid = _validAuthority();
    expect(valid.validNow, isTrue);
    expect(
      TlsInspectionAuthorityStatus(
        state: valid.state,
        ready: valid.ready,
        generation: valid.generation,
        fingerprintSha256: valid.fingerprintSha256,
        notBefore: valid.notBefore,
        notAfter: valid.notAfter,
        algorithm: valid.algorithm,
        keyStorage: valid.keyStorage,
        keyPermissionsRestricted: false,
        trustCapability: valid.trustCapability,
      ).validNow,
      isFalse,
    );
  });
}
