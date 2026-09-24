part of '../quick_routing.dart';

const _quickRoutingDomainAnalysisCacheLimit = 128;
final _quickRoutingDomainAnalysisCache = <String, CoreDomainAnalysis>{};

void _cacheQuickRoutingDomainAnalysis(
  String host,
  CoreDomainAnalysis analysis,
) {
  _quickRoutingDomainAnalysisCache.remove(host);
  while (_quickRoutingDomainAnalysisCache.length >=
      _quickRoutingDomainAnalysisCacheLimit) {
    _quickRoutingDomainAnalysisCache.remove(
      _quickRoutingDomainAnalysisCache.keys.first,
    );
  }
  _quickRoutingDomainAnalysisCache[host] = analysis;
}

List<QuickRoutingCandidate> augmentQuickRoutingCandidatesWithDomainAnalysis(
  Iterable<QuickRoutingCandidate> baseCandidates,
  CoreDomainAnalysis? analysis,
) {
  final candidates = baseCandidates.toList(growable: true);
  if (analysis == null || !analysis.hasRegistrableDomain) {
    return List.unmodifiable(candidates);
  }

  final host = analysis.normalizedHost.trim().toLowerCase();
  final registrable = analysis.registrableDomain.trim().toLowerCase();
  final suffix = analysis.publicSuffix.trim().toLowerCase();
  final suffixBoundaryIsKnown = analysis.icannSuffix || suffix.contains('.');
  if (!suffixBoundaryIsKnown ||
      host.isEmpty ||
      registrable.isEmpty ||
      host == registrable ||
      !host.endsWith('.$registrable') ||
      !_isValidQuickRoutingDomain(registrable)) {
    return List.unmodifiable(candidates);
  }

  final duplicate = candidates.any(
    (candidate) =>
        candidate.ruleAction == RuleAction.DOMAIN_SUFFIX &&
        candidate.content.trim().toLowerCase() == registrable,
  );
  if (duplicate) {
    return List.unmodifiable(candidates);
  }

  final candidate = QuickRoutingCandidate(
    ruleAction: RuleAction.DOMAIN_SUFFIX,
    content: registrable,
  );
  final firstNonDomain = candidates.indexWhere(
    (value) =>
        value.ruleAction != RuleAction.DOMAIN &&
        value.ruleAction != RuleAction.DOMAIN_SUFFIX,
  );
  candidates.insert(
    firstNonDomain < 0 ? candidates.length : firstNonDomain,
    candidate,
  );
  return List.unmodifiable(candidates);
}

Future<CoreDomainAnalysis?> _readCoreQuickRoutingDomainAnalysis(
  WidgetRef ref,
  TrackerInfo trackerInfo,
) async {
  if (ref.read(coreStatusProvider) != CoreStatus.connected) {
    return null;
  }
  final host = _normalizeQuickRoutingHost(
    trackerInfo.metadata.host,
  ).toLowerCase();
  if (host.isEmpty ||
      !host.contains('.') ||
      InternetAddress.tryParse(host) != null) {
    return null;
  }
  final cached = _quickRoutingDomainAnalysisCache[host];
  if (cached != null) {
    _cacheQuickRoutingDomainAnalysis(host, cached);
    return cached;
  }
  try {
    final analysis = await ref.read(coreHandlerProvider).analyzeDomain(host);
    _cacheQuickRoutingDomainAnalysis(host, analysis);
    return analysis;
  } catch (error, stackTrace) {
    commonPrint.log(
      'quick routing domain analysis unavailable: '
      '${compactError(error)}, $stackTrace',
      logLevel: error is CoreMethodException && error.code == 'not_implemented'
          ? LogLevel.debug
          : coreFailureLogLevel(error),
    );
    return null;
  }
}
