part of '../quick_routing.dart';

const quickRoutingRejectDropTarget = 'REJECT-DROP';

const _quickRoutingSupportedActions = <RuleAction>{
  RuleAction.DOMAIN,
  RuleAction.DOMAIN_SUFFIX,
  RuleAction.IP_CIDR,
  RuleAction.IP_CIDR6,
  RuleAction.SRC_IP_CIDR,
  RuleAction.GEOIP,
  RuleAction.SRC_GEOIP,
  RuleAction.IP_ASN,
  RuleAction.SRC_IP_ASN,
  RuleAction.PROCESS_NAME,
  RuleAction.PROCESS_PATH,
  RuleAction.UID,
  RuleAction.NETWORK,
  RuleAction.DST_PORT,
  RuleAction.SRC_PORT,
};

enum _QuickRoutingKnownRuleMatch {
  match,
  noMatch,
  unknown,
}

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
  add(quickRoutingRejectDropTarget);
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

QuickRoutingValidation validateQuickRoutingSelection({
  required QuickRoutingCandidate candidate,
  required String target,
  QuickRoutingGroupOverride? groupOverride,
  Iterable<Group> groups = const <Group>[],
}) {
  final issues = <QuickRoutingValidationIssue>[];
  final content = candidate.content.trim();
  final normalizedTarget = target.trim();

  if (content.isEmpty) {
    issues.add(QuickRoutingValidationIssue.emptyContent);
  }
  if (normalizedTarget.isEmpty) {
    issues.add(QuickRoutingValidationIssue.emptyTarget);
  }
  if (!_quickRoutingSupportedActions.contains(candidate.ruleAction)) {
    issues.add(QuickRoutingValidationIssue.unsupportedAction);
  } else if (content.isNotEmpty) {
    switch (candidate.ruleAction) {
      case RuleAction.DOMAIN:
      case RuleAction.DOMAIN_SUFFIX:
        if (!_isValidQuickRoutingDomain(content)) {
          issues.add(QuickRoutingValidationIssue.invalidDomain);
        }
      case RuleAction.IP_CIDR:
      case RuleAction.IP_CIDR6:
      case RuleAction.SRC_IP_CIDR:
        if (!_isValidQuickRoutingCidr(candidate.ruleAction, content)) {
          issues.add(QuickRoutingValidationIssue.invalidCidr);
        }
      case RuleAction.DST_PORT:
      case RuleAction.SRC_PORT:
        final port = int.tryParse(content);
        if (port == null || port < 1 || port > 65535) {
          issues.add(QuickRoutingValidationIssue.invalidPort);
        }
      case RuleAction.UID:
        final uid = int.tryParse(content);
        if (uid == null || uid < 0) {
          issues.add(QuickRoutingValidationIssue.invalidUid);
        }
      case RuleAction.NETWORK:
        if (!const {'tcp', 'udp'}.contains(content.toLowerCase())) {
          issues.add(QuickRoutingValidationIssue.invalidNetwork);
        }
      case RuleAction.IP_ASN:
      case RuleAction.SRC_IP_ASN:
        if (!RegExp(r'^(?:AS)?\d+$', caseSensitive: false).hasMatch(content) ||
            int.tryParse(_normalizeQuickRoutingAsn(content)) == 0) {
          issues.add(QuickRoutingValidationIssue.invalidAsn);
        }
      case RuleAction.GEOIP:
      case RuleAction.SRC_GEOIP:
      case RuleAction.PROCESS_NAME:
      case RuleAction.PROCESS_PATH:
        break;
      default:
        break;
    }
  }

  if (groupOverride != null && groupOverride.changes) {
    Group? group;
    for (final value in groups) {
      if (value.name == groupOverride.groupName) {
        group = value;
        break;
      }
    }
    final desired = groupOverride.desiredFixed;
    final validMember = desired.isEmpty ||
        (group?.all.any((proxy) => proxy.name == desired) ?? false);
    if (group == null ||
        group.name != normalizedTarget ||
        !group.type.isComputedSelected ||
        !validMember) {
      issues.add(QuickRoutingValidationIssue.invalidGroupOverride);
    }
  }

  return QuickRoutingValidation(issues: List.unmodifiable(issues));
}

QuickRoutingRuleAnalysis buildQuickRoutingRuleAnalysis({
  required QuickRoutingCandidate candidate,
  required String target,
  required TrackerInfo trackerInfo,
  required Iterable<Rule> knownRules,
}) {
  final rules = knownRules.toList(growable: false);
  final proposed = candidate.buildRule(target: target, id: -1);
  Rule? equivalentRule;
  Rule? firstKnownMatch;
  var firstKnownMatchIndex = -1;
  var matchingKnownRuleCount = 0;
  var unknownKnownRuleCount = 0;
  var unknownRuleCountBeforeFirstMatch = 0;

  for (var index = 0; index < rules.length; index++) {
    final rule = rules[index];
    if (equivalentRule == null &&
        quickRoutingRulesHaveSameMatcher(rule, proposed)) {
      equivalentRule = rule;
    }
    final match = _matchKnownQuickRoutingRule(rule, trackerInfo);
    switch (match) {
      case _QuickRoutingKnownRuleMatch.match:
        matchingKnownRuleCount++;
        if (firstKnownMatch == null) {
          firstKnownMatch = rule;
          firstKnownMatchIndex = index;
        }
      case _QuickRoutingKnownRuleMatch.unknown:
        unknownKnownRuleCount++;
        if (firstKnownMatch == null) {
          unknownRuleCountBeforeFirstMatch++;
        }
      case _QuickRoutingKnownRuleMatch.noMatch:
        break;
    }
  }

  return QuickRoutingRuleAnalysis(
    equivalentRule: equivalentRule,
    firstKnownMatch: firstKnownMatch,
    firstKnownMatchIndex: firstKnownMatchIndex,
    matchingKnownRuleCount: matchingKnownRuleCount,
    unknownKnownRuleCount: unknownKnownRuleCount,
    unknownRuleCountBeforeFirstMatch: unknownRuleCountBeforeFirstMatch,
    targetAlreadyInChain: trackerInfo.chains.contains(target),
  );
}

_QuickRoutingKnownRuleMatch _matchKnownQuickRoutingRule(
  Rule rule,
  TrackerInfo trackerInfo,
) {
  if (rule.ruleAction == RuleAction.MATCH) {
    return _QuickRoutingKnownRuleMatch.match;
  }
  final content = rule.realContent?.trim();
  if (content == null || content.isEmpty) {
    return _QuickRoutingKnownRuleMatch.unknown;
  }
  final metadata = trackerInfo.metadata;
  switch (rule.ruleAction) {
    case RuleAction.DOMAIN:
    case RuleAction.DOMAIN_SUFFIX:
      if (_normalizeQuickRoutingHost(metadata.host).isEmpty) {
        return _QuickRoutingKnownRuleMatch.unknown;
      }
      return _matchResult(
        _matchesQuickRoutingCandidate(
          QuickRoutingCandidate(
            ruleAction: rule.ruleAction,
            content: content,
            noResolve: rule.noResolve,
          ),
          trackerInfo,
        ),
      );
    case RuleAction.DOMAIN_KEYWORD:
      final host = _normalizeQuickRoutingHost(metadata.host).toLowerCase();
      if (host.isEmpty) {
        return _QuickRoutingKnownRuleMatch.unknown;
      }
      return _matchResult(host.contains(content.toLowerCase()));
    case RuleAction.DOMAIN_REGEX:
      return _matchQuickRoutingRegex(content, metadata.host);
    case RuleAction.DOMAIN_WILDCARD:
      return _matchQuickRoutingWildcard(content, metadata.host);
    case RuleAction.IP_CIDR:
    case RuleAction.IP_CIDR6:
      final values = [metadata.destinationIP, metadata.host]
          .map(_normalizeQuickRoutingHost)
          .where((value) => InternetAddress.tryParse(value) != null)
          .toList(growable: false);
      if (values.isEmpty) {
        return _QuickRoutingKnownRuleMatch.unknown;
      }
      return _matchResult(_matchesQuickRoutingAddress(content, values));
    case RuleAction.SRC_IP_CIDR:
      if (InternetAddress.tryParse(metadata.sourceIP) == null) {
        return _QuickRoutingKnownRuleMatch.unknown;
      }
      return _matchResult(
        _matchesQuickRoutingAddress(content, [metadata.sourceIP]),
      );
    case RuleAction.GEOIP:
      if (metadata.destinationGeoIP.isEmpty) {
        return _QuickRoutingKnownRuleMatch.unknown;
      }
      return _matchResult(
        _containsQuickRoutingValue(metadata.destinationGeoIP, content),
      );
    case RuleAction.SRC_GEOIP:
      if (metadata.sourceGeoIP.isEmpty) {
        return _QuickRoutingKnownRuleMatch.unknown;
      }
      return _matchResult(
        _containsQuickRoutingValue(metadata.sourceGeoIP, content),
      );
    case RuleAction.IP_ASN:
      final asn = _normalizeQuickRoutingAsn(metadata.destinationIPASN);
      if (asn.isEmpty) {
        return _QuickRoutingKnownRuleMatch.unknown;
      }
      return _matchResult(asn == _normalizeQuickRoutingAsn(content));
    case RuleAction.SRC_IP_ASN:
      final asn = _normalizeQuickRoutingAsn(metadata.sourceIPASN);
      if (asn.isEmpty) {
        return _QuickRoutingKnownRuleMatch.unknown;
      }
      return _matchResult(asn == _normalizeQuickRoutingAsn(content));
    case RuleAction.PROCESS_NAME:
      if (metadata.process.isEmpty) {
        return _QuickRoutingKnownRuleMatch.unknown;
      }
      return _matchResult(
        metadata.process.toLowerCase() == content.toLowerCase(),
      );
    case RuleAction.PROCESS_PATH:
      if (metadata.processPath.isEmpty) {
        return _QuickRoutingKnownRuleMatch.unknown;
      }
      return _matchResult(
        metadata.processPath.toLowerCase() == content.toLowerCase(),
      );
    case RuleAction.PROCESS_NAME_REGEX:
      return _matchQuickRoutingRegex(content, metadata.process);
    case RuleAction.PROCESS_PATH_REGEX:
      return _matchQuickRoutingRegex(content, metadata.processPath);
    case RuleAction.PROCESS_NAME_WILDCARD:
      return _matchQuickRoutingWildcard(content, metadata.process);
    case RuleAction.PROCESS_PATH_WILDCARD:
      return _matchQuickRoutingWildcard(content, metadata.processPath);
    case RuleAction.UID:
      if (metadata.uid <= 0) {
        return _QuickRoutingKnownRuleMatch.unknown;
      }
      return _matchResult(metadata.uid.toString() == content);
    case RuleAction.NETWORK:
      if (metadata.network.isEmpty) {
        return _QuickRoutingKnownRuleMatch.unknown;
      }
      return _matchResult(
        metadata.network.toLowerCase() == content.toLowerCase(),
      );
    case RuleAction.DST_PORT:
      if (metadata.destinationPort.isEmpty) {
        return _QuickRoutingKnownRuleMatch.unknown;
      }
      return _matchResult(metadata.destinationPort == content);
    case RuleAction.SRC_PORT:
      if (metadata.sourcePort.isEmpty) {
        return _QuickRoutingKnownRuleMatch.unknown;
      }
      return _matchResult(metadata.sourcePort == content);
    default:
      return _QuickRoutingKnownRuleMatch.unknown;
  }
}

_QuickRoutingKnownRuleMatch _matchQuickRoutingRegex(
  String pattern,
  String value,
) {
  if (value.isEmpty) {
    return _QuickRoutingKnownRuleMatch.unknown;
  }
  try {
    return _matchResult(
      RegExp(pattern, caseSensitive: false).hasMatch(value),
    );
  } on FormatException {
    return _QuickRoutingKnownRuleMatch.unknown;
  }
}

_QuickRoutingKnownRuleMatch _matchQuickRoutingWildcard(
  String pattern,
  String value,
) {
  if (value.isEmpty) {
    return _QuickRoutingKnownRuleMatch.unknown;
  }
  final expression = StringBuffer('^');
  for (final rune in pattern.runes) {
    final character = String.fromCharCode(rune);
    switch (character) {
      case '*':
        expression.write('.*');
      case '?':
        expression.write('.');
      default:
        expression.write(RegExp.escape(character));
    }
  }
  expression.write(r'$');
  return _matchQuickRoutingRegex(expression.toString(), value);
}

_QuickRoutingKnownRuleMatch _matchResult(bool value) {
  return value
      ? _QuickRoutingKnownRuleMatch.match
      : _QuickRoutingKnownRuleMatch.noMatch;
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

bool _isValidQuickRoutingDomain(String value) {
  final domain = _normalizeQuickRoutingHost(value);
  if (domain.isEmpty ||
      domain.length > 253 ||
      domain.contains(RegExp(r'\s')) ||
      domain.contains('://') ||
      domain.contains('/') ||
      domain.contains(',') ||
      InternetAddress.tryParse(domain) != null) {
    return false;
  }
  final labels = domain.split('.');
  return labels.every(
    (label) =>
        label.isNotEmpty &&
        label.length <= 63 &&
        !label.startsWith('-') &&
        !label.endsWith('-'),
  );
}

bool _isValidQuickRoutingCidr(RuleAction action, String value) {
  final parts = value.split('/');
  if (parts.length != 2) {
    return false;
  }
  final address = InternetAddress.tryParse(
    _normalizeQuickRoutingHost(parts.first),
  );
  if (address == null) {
    return false;
  }
  final maxBits = address.type == InternetAddressType.IPv6 ? 128 : 32;
  final prefix = int.tryParse(parts[1]);
  if (prefix == null || prefix < 0 || prefix > maxBits) {
    return false;
  }
  if (action == RuleAction.IP_CIDR &&
      address.type != InternetAddressType.IPv4) {
    return false;
  }
  if (action == RuleAction.IP_CIDR6 &&
      address.type != InternetAddressType.IPv6) {
    return false;
  }
  return true;
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
