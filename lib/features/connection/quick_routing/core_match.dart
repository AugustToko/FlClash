part of '../quick_routing.dart';

Future<CoreRuleMatchResult?> _readCoreQuickRoutingMatch(
  WidgetRef ref,
  TrackerInfo trackerInfo,
) async {
  if (ref.read(coreStatusProvider) != CoreStatus.connected) {
    return null;
  }
  try {
    return await ref.read(coreHandlerProvider).matchRule(trackerInfo.metadata);
  } catch (error, stackTrace) {
    commonPrint.log(
      'quick routing core match unavailable: '
      '${compactError(error)}, $stackTrace',
      logLevel: LogLevel.warning,
    );
    return null;
  }
}

String _quickRoutingCoreWarningLabel(
  BuildContext context,
  String warning,
) {
  final appLocalizations = context.appLocalizations;
  return switch (warning) {
    'missing-inbound-port' =>
      '${appLocalizations.unknown}: IN-PORT',
    'missing-inbound-name' =>
      '${appLocalizations.unknown}: IN-NAME',
    'missing-inbound-user' =>
      '${appLocalizations.unknown}: IN-USER',
    'missing-inbound-type' =>
      '${appLocalizations.unknown}: IN-TYPE',
    'missing-dscp' => '${appLocalizations.unknown}: DSCP',
    'sub-rule-context-unavailable' ||
    'special-rules-not-expanded' =>
      '${appLocalizations.unknown}: SUB-RULE',
    'process-lookup-source-unavailable' ||
    'process-lookup-failed' =>
      '${appLocalizations.unknown}: ${appLocalizations.application}',
    'dns-resolution-failed' =>
      '${appLocalizations.unknown}: DNS',
    'matched-target-unavailable' =>
      '${appLocalizations.unknown}: ${appLocalizations.ruleTarget}',
    'rematch-target-not-expanded' =>
      '${appLocalizations.unknown}: REMATCH',
    'udp-policy-capability-not-evaluated' =>
      '${appLocalizations.unknown}: UDP',
    _ => warning,
  };
}

List<Widget> _buildCoreQuickRoutingMatchPreview(
  BuildContext context,
  CoreRuleMatchResult result,
) {
  final appLocalizations = context.appLocalizations;
  final marker = result.complete ? '✓' : '≈';
  final ruleIndex = result.ruleIndex >= 0 ? '#${result.ruleIndex + 1} ' : '';
  final summary = result.matched
      ? '$ruleIndex${result.ruleText} → ${result.target}'
      : '${result.mode.toUpperCase()} → ${result.target}';
  return [
    Text('$marker Core: $summary'),
    if (result.providerNames.isNotEmpty)
      Text(
        '${appLocalizations.providers}: '
        '${result.providerNames.join(', ')}',
        maxLines: 2,
        overflow: TextOverflow.ellipsis,
      ),
    if (result.resolvedIP.isNotEmpty)
      Text('${appLocalizations.intranetIP}: ${result.resolvedIP}'),
    if (result.warnings.isNotEmpty)
      Text(
        result.warnings
            .map((warning) => _quickRoutingCoreWarningLabel(context, warning))
            .join(' · '),
        maxLines: 3,
        overflow: TextOverflow.ellipsis,
        style: context.textTheme.bodySmall?.copyWith(
          color: context.colorScheme.tertiary,
        ),
      ),
  ];
}
