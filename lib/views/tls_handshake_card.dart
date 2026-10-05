import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/core/core.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/tls_inspection.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_ui/material_ui.dart';

class TlsHandshakeCard extends ConsumerStatefulWidget {
  const TlsHandshakeCard({super.key});

  @override
  ConsumerState<TlsHandshakeCard> createState() => _TlsHandshakeCardState();
}

class _TlsHandshakeCardState extends ConsumerState<TlsHandshakeCard> {
  final _hostController = TextEditingController();
  TlsInspectionLeafCertificateStatus? _result;
  bool _running = false;
  String _errorCode = '';

  @override
  void dispose() {
    _hostController.dispose();
    super.dispose();
  }

  Future<void> _verify() async {
    final state = ref.read(tlsInspectionProvider);
    final input = _hostController.text.trim();
    if (_running ||
        state.busy ||
        state.loading ||
        !state.prepared ||
        input.isEmpty) {
      return;
    }
    setState(() {
      _running = true;
      _result = null;
      _errorCode = '';
    });
    try {
      final result = await ref
          .read(tlsInspectionProvider.notifier)
          .prepareLeafCertificate(input, verifyHandshake: true);
      if (mounted) {
        setState(() => _result = result);
      }
    } catch (error) {
      if (mounted) {
        setState(() {
          _errorCode = switch (error) {
            final CoreMethodException value => value.code,
            final TlsInspectionPolicyException value => value.code,
            _ => 'leaf_handshake_failed',
          };
        });
      }
    } finally {
      if (mounted) {
        setState(() => _running = false);
      }
    }
  }

  Widget _field(String label, String value) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 6),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(label, style: Theme.of(context).textTheme.labelMedium),
        const SizedBox(height: 4),
        SelectableText(value),
      ],
    ),
  );

  @override
  Widget build(BuildContext context) {
    final l = context.appLocalizations;
    final state = ref.watch(tlsInspectionProvider);
    final result = _result;
    final currentResult =
        result != null &&
        result.contractValid &&
        state.isAllowed(result.host) &&
        result.validFor(
          state.authority,
          state.leafCache.policyDigest,
          expectedHost: result.host,
        );
    final enabled =
        state.prepared && !state.busy && !state.loading && !_running;
    final errorMessage = switch (_errorCode) {
      'leaf_handshake_unverified' => l.tlsInspectionHandshakeUnsupported,
      'domain_not_allowed' ||
      'invalid_domain' ||
      'domain_too_broad' ||
      'ip_not_supported' => l.tlsInspectionHandshakeDomainError,
      _ => l.tlsInspectionHandshakeError,
    };

    return Card(
      margin: EdgeInsets.zero,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.verified_user_outlined),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    l.tlsInspectionHandshakeTitle,
                    style: Theme.of(context).textTheme.titleMedium,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            Text(l.tlsInspectionHandshakeDescription),
            const SizedBox(height: 16),
            TextField(
              key: const Key('tls-handshake-domain'),
              controller: _hostController,
              enabled: !_running,
              maxLength: 253,
              autocorrect: false,
              enableSuggestions: false,
              keyboardType: TextInputType.url,
              textInputAction: TextInputAction.done,
              decoration: InputDecoration(
                labelText: l.tlsInspectionHandshakeDomain,
                hintText: 'api.example.com',
                counterText: '',
              ),
              onSubmitted: (_) => _verify(),
              onChanged: (_) => setState(() {
                _result = null;
                _errorCode = '';
              }),
            ),
            const SizedBox(height: 12),
            FilledButton.icon(
              key: const Key('tls-handshake-run'),
              onPressed: enabled && _hostController.text.trim().isNotEmpty
                  ? _verify
                  : null,
              icon: _running
                  ? const SizedBox.square(
                      dimension: 18,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.play_arrow),
              label: Text(
                _running
                    ? l.tlsInspectionHandshakeRunning
                    : l.tlsInspectionHandshakeRun,
              ),
            ),
            if (!state.prepared) ...[
              const SizedBox(height: 8),
              Text(l.tlsInspectionHandshakeRequirements),
            ],
            if (_errorCode.isNotEmpty) ...[
              const SizedBox(height: 12),
              Text(
                errorMessage,
                key: const Key('tls-handshake-error'),
                style: TextStyle(color: Theme.of(context).colorScheme.error),
              ),
            ],
            if (result != null) ...[
              const Divider(height: 24),
              Text(
                currentResult
                    ? l.tlsInspectionHandshakePassed
                    : l.tlsInspectionHandshakeStale,
                key: const Key('tls-handshake-result'),
                style: Theme.of(context).textTheme.titleSmall,
              ),
              if (currentResult) ...[
                _field(l.tlsInspectionHandshakeDomain, result.host),
                const Wrap(
                  spacing: 8,
                  runSpacing: 4,
                  children: [
                    Chip(label: Text('TLS 1.2')),
                    Chip(label: Text('TLS 1.3')),
                    Chip(label: Text('ALPN: http/1.1')),
                  ],
                ),
                _field(
                  l.tlsInspectionHandshakeScope,
                  l.tlsInspectionHandshakeScopeValue,
                ),
                _field(
                  l.tlsInspectionHandshakeFingerprint,
                  result.fingerprintSha256,
                ),
              ],
            ],
            const SizedBox(height: 12),
            Text(
              l.tlsInspectionHandshakeBoundary,
              style: Theme.of(context).textTheme.bodySmall,
            ),
          ],
        ),
      ),
    );
  }
}
