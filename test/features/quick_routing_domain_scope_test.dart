import 'package:fl_clash/core/controller.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/features/features.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  const base = [
    QuickRoutingCandidate(
      ruleAction: RuleAction.DOMAIN,
      content: 'api.service.example.co.uk',
    ),
    QuickRoutingCandidate(
      ruleAction: RuleAction.DOMAIN_SUFFIX,
      content: 'api.service.example.co.uk',
    ),
    QuickRoutingCandidate(
      ruleAction: RuleAction.PROCESS_NAME,
      content: 'example-app',
    ),
  ];

  test('adds the PSL registrable domain after narrow domain choices', () {
    const analysis = CoreDomainAnalysis(
      input: 'api.service.example.co.uk',
      normalizedHost: 'api.service.example.co.uk',
      isIP: false,
      publicSuffix: 'co.uk',
      registrableDomain: 'example.co.uk',
      icannSuffix: true,
    );

    final result = augmentQuickRoutingCandidatesWithDomainAnalysis(
      base,
      analysis,
    );

    expect(
      result.map((candidate) => candidate.label),
      [
        'DOMAIN · api.service.example.co.uk',
        'DOMAIN-SUFFIX · api.service.example.co.uk',
        'DOMAIN-SUFFIX · example.co.uk',
        'PROCESS-NAME · example-app',
      ],
    );
  });

  test('supports private suffix boundaries without broadening to github.io', () {
    const analysis = CoreDomainAnalysis(
      input: 'bar.foo.github.io',
      normalizedHost: 'bar.foo.github.io',
      isIP: false,
      publicSuffix: 'github.io',
      registrableDomain: 'foo.github.io',
      icannSuffix: false,
    );

    final result = augmentQuickRoutingCandidatesWithDomainAnalysis(
      const [
        QuickRoutingCandidate(
          ruleAction: RuleAction.DOMAIN,
          content: 'bar.foo.github.io',
        ),
        QuickRoutingCandidate(
          ruleAction: RuleAction.DOMAIN_SUFFIX,
          content: 'bar.foo.github.io',
        ),
      ],
      analysis,
    );

    expect(result.last.content, 'foo.github.io');
    expect(result.any((candidate) => candidate.content == 'github.io'), isFalse);
  });

  test('does not duplicate an existing registrable-domain matcher', () {
    const analysis = CoreDomainAnalysis(
      input: 'api.example.com',
      normalizedHost: 'api.example.com',
      isIP: false,
      publicSuffix: 'com',
      registrableDomain: 'example.com',
      icannSuffix: true,
    );
    final result = augmentQuickRoutingCandidatesWithDomainAnalysis(
      const [
        QuickRoutingCandidate(
          ruleAction: RuleAction.DOMAIN_SUFFIX,
          content: 'api.example.com',
        ),
        QuickRoutingCandidate(
          ruleAction: RuleAction.DOMAIN_SUFFIX,
          content: 'example.com',
        ),
      ],
      analysis,
    );

    expect(
      result.where((candidate) => candidate.content == 'example.com'),
      hasLength(1),
    );
  });

  test('rejects stale, unknown, or already narrow analysis results', () {
    const unrelated = CoreDomainAnalysis(
      input: 'api.example.com',
      normalizedHost: 'api.example.com',
      isIP: false,
      publicSuffix: 'net',
      registrableDomain: 'other.net',
      icannSuffix: true,
    );
    const unknownLocalSuffix = CoreDomainAnalysis(
      input: 'api.service.internal',
      normalizedHost: 'api.service.internal',
      isIP: false,
      publicSuffix: 'internal',
      registrableDomain: 'service.internal',
      icannSuffix: false,
    );
    const alreadyRegistrable = CoreDomainAnalysis(
      input: 'example.com',
      normalizedHost: 'example.com',
      isIP: false,
      publicSuffix: 'com',
      registrableDomain: 'example.com',
      icannSuffix: true,
    );

    expect(
      augmentQuickRoutingCandidatesWithDomainAnalysis(base, unrelated),
      hasLength(base.length),
    );
    expect(
      augmentQuickRoutingCandidatesWithDomainAnalysis(
        base,
        unknownLocalSuffix,
      ),
      hasLength(base.length),
    );
    expect(
      augmentQuickRoutingCandidatesWithDomainAnalysis(base, alreadyRegistrable),
      hasLength(base.length),
    );
  });
}
