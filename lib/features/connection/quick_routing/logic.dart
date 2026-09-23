part of '../quick_routing.dart';

List<QuickRoutingCandidate> buildQuickRoutingCandidates(
  TrackerInfo trackerInfo,
) {
  final candidates = <QuickRoutingCandidate>[];
  final keys = <String>{};

  void add(
    RuleAction ruleAction,
    String? rawContent, {
    bool noResolve = false,
  }) {
    final content = rawContent?.trim() ?? '';
    if (content.isEmpty) {
      return;
    }
    final key = '${ruleAction.name}\u0000$content\u0000$noResolve';
    if (!keys.add(key)) {
      return;
    }
    candidates.add(
      QuickRoutingCandidate(
        ruleAction: ruleAction,
        content: content,
        noResolve: noResolve,
      ),
    );
  }

  void addIp(String rawIp, {required bool source}) {
    final ip = _normalizeQuickRoutingHost(rawIp);
    final address = InternetAddress.tryParse(ip);
    if (address == null) {
      return;
    }
    final prefix = address.type == InternetAddressType.IPv6 ? 128 : 32;
    final action = switch ((source, address.type)) {
      (true, _) => RuleAction.SRC_IP_CIDR,
      (false, InternetAddressType.IPv6) => RuleAction.IP_CIDR6,
      _ => RuleAction.IP_CIDR,
    };
    add(
      action,
      '${address.address}/$prefix',
      noResolve: !source,
    );
  }

  final metadata = trackerInfo.metadata;
  final host = _normalizeQuickRoutingHost(metadata.host);
  if (host.isNotEmpty) {
    if (InternetAddress.tryParse(host) != null) {
      addIp(host, source: false);
    } else {
      final normalizedDomain = host.toLowerCase();
      add(RuleAction.DOMAIN, normalizedDomain);
      add(RuleAction.DOMAIN_SUFFIX, normalizedDomain);
    }
  }

  addIp(metadata.destinationIP, source: false);
  addIp(metadata.sourceIP, source: true);
  for (final country in metadata.destinationGeoIP) {
    add(RuleAction.GEOIP, country.toUpperCase());
  }
  for (final country in metadata.sourceGeoIP) {
    add(RuleAction.SRC_GEOIP, country.toUpperCase());
  }
  add(RuleAction.IP_ASN, _normalizeQuickRoutingAsn(metadata.destinationIPASN));
  add(RuleAction.SRC_IP_ASN, _normalizeQuickRoutingAsn(metadata.sourceIPASN));
  add(RuleAction.PROCESS_NAME, metadata.process);
  add(RuleAction.PROCESS_PATH, metadata.processPath);
  if (metadata.uid > 0) {
    add(RuleAction.UID, metadata.uid.toString());
  }
  add(RuleAction.NETWORK, metadata.network.toUpperCase());
  add(RuleAction.DST_PORT, metadata.destinationPort);
  add(RuleAction.SRC_PORT, metadata.sourcePort);

  return List.unmodifiable(candidates);
}

List<String> buildQuickRoutingTargets(Iterable<Group> groups) {
  final targets = <String>[];
  final seen = <String>{};

  void add(String value) {
    final target = value.trim();
    if (target.isNotEmpty && seen.add(target)) {
      targets.add(target);
    }
  }

  for (final target in RuleTarget.baseTargetNames) {
    add(target);
  }
  for (final group in groups) {
    add(group.name);
  }
  for (final group in groups) {
    for (final proxy in group.all) {
      add(proxy.name);
    }
  }
  return List.unmodifiable(targets);
}

String pickQuickRoutingTarget(
  TrackerInfo trackerInfo,
  List<String> targets, {
  Iterable<String> preferredTargets = const [],
}) {
  final preferred = preferredTargets.toSet();
  for (final chain in trackerInfo.chains) {
    if (preferred.contains(chain) && targets.contains(chain)) {
      return chain;
    }
  }
  for (final chain in trackerInfo.chains) {
    if (targets.contains(chain)) {
      return chain;
    }
  }
  if (targets.contains(RuleTarget.DIRECT.name)) {
    return RuleTarget.DIRECT.name;
  }
  return targets.first;
}

List<TrackerInfo> buildQuickRoutingImpactSource(
  TrackerInfo current,
  Iterable<TrackerInfo> recent,
) {
  final values = recent.toList(growable: true);
  if (!values.any((trackerInfo) => trackerInfo.id == current.id)) {
    values.insert(0, current);
  }
  return List.unmodifiable(values);
}

QuickRoutingImpact buildQuickRoutingImpact(
  QuickRoutingCandidate candidate,
  Iterable<TrackerInfo> trackerInfos,
) {
  final hosts = <String>{};
  final processes = <String>{};
  var requestCount = 0;
  for (final trackerInfo in trackerInfos) {
    if (!_matchesQuickRoutingCandidate(candidate, trackerInfo)) {
      continue;
    }
    requestCount++;
    final host = _normalizeQuickRoutingHost(trackerInfo.metadata.host);
    if (host.isNotEmpty) {
      hosts.add(host);
    }
    final process = trackerInfo.metadata.process.trim();
    if (process.isNotEmpty) {
      processes.add(process);
    }
  }
  final sortedHosts = hosts.toList()..sort();
  final sortedProcesses = processes.toList()..sort();
  return QuickRoutingImpact(
    requestCount: requestCount,
    hosts: List.unmodifiable(sortedHosts),
    processes: List.unmodifiable(sortedProcesses),
  );
}

QuickRoutingRuleAnalysis buildQuickRoutingRuleAnalysis({
  required QuickRoutingCandidate candidate,
  required String target,
  required TrackerInfo trackerInfo,
  required Iterable<Rule> knownRules,
}) {
  final proposed = candidate.buildRule(target: target, id: -1);
  Rule? equivalentRule;
  var matchingKnownRuleCount = 0;
  for (final rule in knownRules) {
    if (equivalentRule == null &&
        quickRoutingRulesHaveSameMatcher(rule, proposed)) {
      equivalentRule = rule;
    }
    final knownCandidate = _quickRoutingCandidateFromRule(rule);
    if (knownCandidate != null &&
        _matchesQuickRoutingCandidate(knownCandidate, trackerInfo)) {
      matchingKnownRuleCount++;
    }
  }
  return QuickRoutingRuleAnalysis(
    equivalentRule: equivalentRule,
    matchingKnownRuleCount: matchingKnownRuleCount,
    targetAlreadyInChain: trackerInfo.chains.contains(target),
  );
}

QuickRoutingCandidate? _quickRoutingCandidateFromRule(Rule rule) {
  final content = rule.realContent?.trim();
  if (content == null || content.isEmpty) {
    return null;
  }
  final supported = switch (rule.ruleAction) {
    RuleAction.DOMAIN ||
    RuleAction.DOMAIN_SUFFIX ||
    RuleAction.IP_CIDR ||
    RuleAction.IP_CIDR6 ||
    RuleAction.SRC_IP_CIDR ||
    RuleAction.GEOIP ||
    RuleAction.SRC_GEOIP ||
    RuleAction.IP_ASN ||
    RuleAction.SRC_IP_ASN ||
    RuleAction.PROCESS_NAME ||
    RuleAction.PROCESS_PATH ||
    RuleAction.UID ||
    RuleAction.NETWORK ||
    RuleAction.DST_PORT ||
    RuleAction.SRC_PORT => true,
    _ => false,
  };
  if (!supported) {
    return null;
  }
  return QuickRoutingCandidate(
    ruleAction: rule.ruleAction,
    content: content,
    noResolve: rule.noResolve,
  );
}

bool _matchesQuickRoutingCandidate(
  QuickRoutingCandidate candidate,
  TrackerInfo trackerInfo,
) {
  final metadata = trackerInfo.metadata;
  final content = candidate.content;
  switch (candidate.ruleAction) {
    case RuleAction.DOMAIN:
      return _normalizeQuickRoutingHost(metadata.host).toLowerCase() ==
          content.toLowerCase();
    case RuleAction.DOMAIN_SUFFIX:
      final host = _normalizeQuickRoutingHost(metadata.host).toLowerCase();
      final suffix = content.toLowerCase();
      return host == suffix || host.endsWith('.$suffix');
    case RuleAction.IP_CIDR:
    case RuleAction.IP_CIDR6:
      return _matchesQuickRoutingAddress(
        content,
        [metadata.destinationIP, metadata.host],
      );
    case RuleAction.SRC_IP_CIDR:
      return _matchesQuickRoutingAddress(content, [metadata.sourceIP]);
    case RuleAction.GEOIP:
      return _containsQuickRoutingValue(metadata.destinationGeoIP, content);
    case RuleAction.SRC_GEOIP:
      return _containsQuickRoutingValue(metadata.sourceGeoIP, content);
    case RuleAction.IP_ASN:
      return _normalizeQuickRoutingAsn(metadata.destinationIPASN) ==
          _normalizeQuickRoutingAsn(content);
    case RuleAction.SRC_IP_ASN:
      return _normalizeQuickRoutingAsn(metadata.sourceIPASN) ==
          _normalizeQuickRoutingAsn(content);
    case RuleAction.PROCESS_NAME:
      return metadata.process.toLowerCase() == content.toLowerCase();
    case RuleAction.PROCESS_PATH:
      return metadata.processPath.toLowerCase() == content.toLowerCase();
    case RuleAction.UID:
      return metadata.uid.toString() == content;
    case RuleAction.NETWORK:
      return metadata.network.toLowerCase() == content.toLowerCase();
    case RuleAction.DST_PORT:
      return metadata.destinationPort == content;
    case RuleAction.SRC_PORT:
      return metadata.sourcePort == content;
    default:
      return false;
  }
}

bool _matchesQuickRoutingAddress(String cidr, Iterable<String> values) {
  final parts = cidr.split('/');
  final network = InternetAddress.tryParse(
    _normalizeQuickRoutingHost(parts.first),
  );
  if (network == null) {
    return false;
  }
  final maxBits = network.type == InternetAddressType.IPv6 ? 128 : 32;
  final prefix = parts.length > 1 ? int.tryParse(parts[1]) : maxBits;
  if (prefix == null || prefix < 0 || prefix > maxBits) {
    return false;
  }
  return values.any((value) {
    final address = InternetAddress.tryParse(_normalizeQuickRoutingHost(value));
    return address != null && _addressInPrefix(network, address, prefix);
  });
}

bool _addressInPrefix(
  InternetAddress network,
  InternetAddress address,
  int prefix,
) {
  if (network.type != address.type) {
    return false;
  }
  final networkBytes = network.rawAddress;
  final addressBytes = address.rawAddress;
  final fullBytes = prefix ~/ 8;
  final remainingBits = prefix % 8;
  for (var index = 0; index < fullBytes; index++) {
    if (networkBytes[index] != addressBytes[index]) {
      return false;
    }
  }
  if (remainingBits == 0) {
    return true;
  }
  final mask = (0xff << (8 - remainingBits)) & 0xff;
  return (networkBytes[fullBytes] & mask) ==
      (addressBytes[fullBytes] & mask);
}

bool _containsQuickRoutingValue(
  Iterable<String> values,
  String expected,
) {
  final normalized = expected.toLowerCase();
  return values.any((value) => value.toLowerCase() == normalized);
}

String _normalizeQuickRoutingHost(String value) {
  var host = value.trim();
  if (host.isEmpty) {
    return host;
  }
  if (host.startsWith('[')) {
    final closingBracket = host.indexOf(']');
    if (closingBracket > 1) {
      host = host.substring(1, closingBracket);
    }
  } else {
    final firstColon = host.indexOf(':');
    final lastColon = host.lastIndexOf(':');
    if (firstColon > 0 && firstColon == lastColon) {
      final port = host.substring(lastColon + 1);
      if (int.tryParse(port) != null) {
        host = host.substring(0, lastColon);
      }
    }
  }
  while (host.endsWith('.')) {
    host = host.substring(0, host.length - 1);
  }
  return host;
}

String _normalizeQuickRoutingAsn(String value) {
  return RegExp(r'\d+').firstMatch(value)?.group(0) ?? '';
}
