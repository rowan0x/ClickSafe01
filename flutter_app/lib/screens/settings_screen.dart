// lib/screens/settings_screen.dart
//
// CHANGE LOG vs original:
//   • Added "CONNECTION SETTINGS" section at the top:
//       – Backend URL text field (pre-loaded from SharedPreferences)
//       – Intel API Key text field (pre-loaded, obscured by default)
//       – Save and Reset-to-defaults buttons
//   • _buildBackendStatus() now shows the live URL from SettingsService
//     instead of the static string 'app_config.dart → baseUrl'.
//   • The Intel Loop section's "Requires INTEL_API_KEY in app_config.dart"
//     note updated to reflect the new Settings-based configuration.
//   • All other sections (Backend Status, Feature Importances, Intel Loop)
//     are unchanged in behaviour.

import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../config/app_config.dart';
import '../services/api_service.dart';
import '../services/settings_service.dart';
import '../theme/app_theme.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  final _api      = ApiService.instance;
  final _settings = SettingsService.instance;

  // ── Connection Settings controllers ───────────────────────────────────────
  final _urlController    = TextEditingController();
  final _apiKeyController = TextEditingController();
  bool  _apiKeyObscured   = true;
  bool  _savingConnection = false;
  String? _connectionMessage;
  Color   _connectionMessageColor = AppTheme.safeGreen;

  // ── Intel Loop ─────────────────────────────────────────────────────────────
  final _intelUrlController = TextEditingController();
  bool  _intelLoading = false;
  String? _intelMessage;
  Color   _intelMessageColor = AppTheme.safeGreen;

  // ── Feature importances ────────────────────────────────────────────────────
  List<Map<String, dynamic>> _importances = [];
  bool _importsLoading = false;

  // ── Backend health ─────────────────────────────────────────────────────────
  BackendHealth? _health;
  bool _healthLoading = false;
  String _currentUrl = '';

  @override
  void initState() {
    super.initState();
    _loadConnectionSettings();
    _refreshHealth();
    _loadImportances();
  }

  // ── Loaders ────────────────────────────────────────────────────────────────

  Future<void> _loadConnectionSettings() async {
    final url = await _settings.getBaseUrl();
    final key = await _settings.getApiKey();
    if (mounted) {
      setState(() {
        _currentUrl = url;
        // Pre-fill with current values.
        // Show empty if they are the compile-time defaults so the user knows
        // the field is using the fallback — they can type to override.
        _urlController.text =
            url == AppConfig.defaultBaseUrl ? '' : url;
        _apiKeyController.text =
            key == AppConfig.defaultIntelApiKey ? '' : key;
      });
    }
  }

  Future<void> _refreshHealth() async {
    setState(() => _healthLoading = true);
    final h = await _api.checkHealth();
    if (mounted) {
      setState(() {
        _health       = h;
        _healthLoading = false;
      });
    }
  }

  Future<void> _loadImportances() async {
    setState(() => _importsLoading = true);
    try {
      final importances = await _api.getFeatureImportances();
      if (mounted) {
        setState(() {
          _importances    = importances;
          _importsLoading = false;
        });
      }
    } catch (_) {
      if (mounted) setState(() => _importsLoading = false);
    }
  }

  // ── Connection Settings actions ────────────────────────────────────────────

  Future<void> _saveConnectionSettings() async {
    setState(() {
      _savingConnection  = true;
      _connectionMessage = null;
    });

    final newUrl = _urlController.text.trim();
    final newKey = _apiKeyController.text.trim();

    // Validate URL format (basic check — full validation happens on health call)
    if (newUrl.isNotEmpty &&
        !newUrl.startsWith('http://') &&
        !newUrl.startsWith('https://')) {
      setState(() {
        _savingConnection  = false;
        _connectionMessage = 'URL must start with http:// or https://';
        _connectionMessageColor = AppTheme.dangerRed;
      });
      return;
    }

    await _settings.setBaseUrl(newUrl);
    await _settings.setApiKey(newKey);

    final saved = await _settings.getBaseUrl();
    if (mounted) {
      setState(() {
        _currentUrl        = saved;
        _savingConnection  = false;
        _connectionMessage = 'Saved! Testing connection…';
        _connectionMessageColor = AppTheme.accentCyan;
      });
    }

    // Re-test the health with the new URL
    await _refreshHealth();
    if (mounted) {
      final ok = _health?.ok ?? false;
      setState(() {
        _connectionMessage      = ok ? '✅ Connection successful!' : '❌ Backend not reachable at the new URL.';
        _connectionMessageColor = ok ? AppTheme.safeGreen : AppTheme.dangerRed;
      });
    }
  }

  Future<void> _resetConnectionSettings() async {
    await _settings.resetToDefaults();
    if (mounted) {
      setState(() {
        _urlController.text    = '';
        _apiKeyController.text = '';
        _connectionMessage     = 'Reset to defaults.';
        _connectionMessageColor = AppTheme.accentCyan;
      });
      await _loadConnectionSettings();
      await _refreshHealth();
    }
  }

  // ── Intel Loop actions ─────────────────────────────────────────────────────

  Future<void> _submitIntelReport() async {
    final raw = _intelUrlController.text.trim();
    if (raw.isEmpty) {
      _setIntelMsg('Please enter at least one URL.', AppTheme.warnAmber);
      return;
    }
    final urls = raw.split('\n').map((u) => u.trim()).where((u) => u.isNotEmpty).toList();

    setState(() { _intelLoading = true; _intelMessage = null; });
    try {
      final result = await _api.ingestPhishingUrls(urls: urls, source: 'mobile_settings');
      final retrained = result['retrained'] as bool? ?? false;
      final ingested  = result['ingested'] as int? ?? 0;
      _setIntelMsg(
        'Ingested $ingested URL(s). '
        // FIX: use double quotes for inner ternary strings so that
        // result['min_for_retrain'] is correctly resolved inside ${...}
        // without the single-quote nesting causing a parse ambiguity.
        '${retrained ? "✅ Model retrained!" : "Queued (need ${(result['min_for_retrain'] as int?) ?? 10} total to retrain)."}',
        retrained ? AppTheme.safeGreen : AppTheme.accentCyan,
      );
      _intelUrlController.clear();
    } catch (e) {
      _setIntelMsg('Error: $e', AppTheme.dangerRed);
    } finally {
      if (mounted) setState(() => _intelLoading = false);
    }
  }

  void _setIntelMsg(String msg, Color color) {
    if (mounted) setState(() { _intelMessage = msg; _intelMessageColor = color; });
  }

  // ── Build ──────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) => Scaffold(
    backgroundColor: AppTheme.bgPrimary,
    appBar: AppBar(title: const Text('Settings')),
    body: SingleChildScrollView(
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // ── NEW: Connection Settings section ──────────────────────────────
          _buildSection('CONNECTION SETTINGS', _buildConnectionSettings()),
          const SizedBox(height: 24),

          _buildSection('BACKEND STATUS', _buildBackendStatus()),
          const SizedBox(height: 24),
          _buildSection('MODEL — FEATURE IMPORTANCES', _buildImportances()),
          const SizedBox(height: 24),
          _buildSection('INTEL LOOP — REPORT PHISHING', _buildIntelLoop()),
          const SizedBox(height: 32),
        ],
      ),
    ),
  );

  // ── Section helpers ────────────────────────────────────────────────────────

  Widget _buildSection(String title, Widget child) => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Text(title,
          style: const TextStyle(
              color: AppTheme.textMuted,
              fontSize: 11,
              fontWeight: FontWeight.w700,
              letterSpacing: 1.2)),
      const SizedBox(height: 10),
      child,
    ],
  );

  // ── NEW: Connection Settings ───────────────────────────────────────────────

  Widget _buildConnectionSettings() => Container(
    padding: const EdgeInsets.all(16),
    decoration: BoxDecoration(
      color: AppTheme.bgCard,
      borderRadius: BorderRadius.circular(14),
      border: Border.all(color: AppTheme.accentBlue.withOpacity(0.30)),
    ),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        // Info banner
        Container(
          padding: const EdgeInsets.all(10),
          decoration: BoxDecoration(
            color: AppTheme.accentBlue.withOpacity(0.08),
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: AppTheme.accentBlue.withOpacity(0.25)),
          ),
          child: Row(
            children: [
              const Icon(Icons.info_outline_rounded,
                  color: AppTheme.accentBlue, size: 16),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  'Leave fields empty to use the built-in default URL and key.',
                  style: TextStyle(
                      color: AppTheme.accentBlue.withOpacity(0.85),
                      fontSize: 11,
                      height: 1.4),
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 16),

        // Backend URL
        const Text('BACKEND URL',
            style: TextStyle(
                color: AppTheme.textMuted,
                fontSize: 10,
                fontWeight: FontWeight.w700,
                letterSpacing: 1.0)),
        const SizedBox(height: 6),
        TextField(
          controller: _urlController,
          keyboardType: TextInputType.url,
          autocorrect: false,
          style: AppTheme.monoUrl.copyWith(fontSize: 13),
          decoration: InputDecoration(
            hintText: AppConfig.defaultBaseUrl,
            suffixIcon: _urlController.text.isNotEmpty
                ? IconButton(
                    icon: const Icon(Icons.clear, size: 16),
                    onPressed: () => setState(() => _urlController.clear()),
                  )
                : null,
          ),
          onChanged: (_) => setState(() {}),
        ),
        const SizedBox(height: 14),

        // Intel API Key
        const Text('INTEL API KEY',
            style: TextStyle(
                color: AppTheme.textMuted,
                fontSize: 10,
                fontWeight: FontWeight.w700,
                letterSpacing: 1.0)),
        const SizedBox(height: 6),
        TextField(
          controller: _apiKeyController,
          obscureText: _apiKeyObscured,
          autocorrect: false,
          enableSuggestions: false,
          style: const TextStyle(
              color: AppTheme.textPrimary,
              fontSize: 13,
              fontFamily: 'monospace'),
          decoration: InputDecoration(
            hintText: 'your-intel-api-key',
            suffixIcon: IconButton(
              icon: Icon(
                _apiKeyObscured
                    ? Icons.visibility_off_rounded
                    : Icons.visibility_rounded,
                size: 18,
                color: AppTheme.textMuted,
              ),
              onPressed: () =>
                  setState(() => _apiKeyObscured = !_apiKeyObscured),
            ),
          ),
        ),
        const SizedBox(height: 14),

        // Feedback message
        if (_connectionMessage != null) ...[
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: _connectionMessageColor.withOpacity(0.08),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(
                  color: _connectionMessageColor.withOpacity(0.3)),
            ),
            child: Text(
              _connectionMessage!,
              style: TextStyle(color: _connectionMessageColor, fontSize: 12),
            ),
          ),
          const SizedBox(height: 10),
        ],

        // Save / Reset row
        Row(
          children: [
            Expanded(
              child: ElevatedButton.icon(
                icon: _savingConnection
                    ? const SizedBox(
                        width: 14,
                        height: 14,
                        child: CircularProgressIndicator(
                            strokeWidth: 2, color: Colors.white))
                    : const Icon(Icons.save_rounded, size: 16),
                label: Text(_savingConnection ? 'Saving…' : 'Save & Test'),
                onPressed: _savingConnection ? null : _saveConnectionSettings,
              ),
            ),
            const SizedBox(width: 10),
            OutlinedButton.icon(
              icon: const Icon(Icons.restart_alt_rounded, size: 16),
              label: const Text('Reset'),
              onPressed: _savingConnection ? null : _resetConnectionSettings,
            ),
          ],
        ),
      ],
    ),
  );

  // ── Backend Status ─────────────────────────────────────────────────────────

  Widget _buildBackendStatus() => Container(
    padding: const EdgeInsets.all(16),
    decoration: BoxDecoration(
      color: AppTheme.bgCard,
      borderRadius: BorderRadius.circular(14),
      border: Border.all(color: AppTheme.bgCardBorder),
    ),
    child: Column(
      children: [
        // Shows the LIVE URL from SettingsService (not the static string)
        _InfoRow(
          label: 'Backend URL',
          value: _currentUrl.isEmpty ? AppConfig.defaultBaseUrl : _currentUrl,
          valueColor: AppTheme.accentCyan,
        ),
        const Divider(height: 20),
        if (_healthLoading)
          const Center(child: CircularProgressIndicator())
        else if (_health == null)
          const Text('Not connected',
              style: TextStyle(color: AppTheme.warnAmber))
        else ...[
          _InfoRow(
            label: 'Status',
            value: _health!.ok ? '✅ Online' : '❌ Offline',
            valueColor: _health!.ok ? AppTheme.safeGreen : AppTheme.dangerRed,
          ),
          _InfoRow(
            label: 'Tranco domains',
            value: '${_health!.trancodomains}',
          ),
          _InfoRow(
            label: 'Intel signatures',
            value: '${_health!.intelSigs}',
          ),
        ],
        const SizedBox(height: 12),
        SizedBox(
          width: double.infinity,
          child: OutlinedButton.icon(
            icon: const Icon(Icons.refresh_rounded, size: 16),
            label: const Text('Refresh'),
            onPressed: _refreshHealth,
          ),
        ),
      ],
    ),
  );

  // ── Feature Importances ────────────────────────────────────────────────────

  Widget _buildImportances() {
    if (_importsLoading) {
      return const Center(child: Padding(
        padding: EdgeInsets.all(20),
        child: CircularProgressIndicator(),
      ));
    }
    if (_importances.isEmpty) {
      return Container(
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: AppTheme.bgCard,
          borderRadius: BorderRadius.circular(14),
          border: Border.all(color: AppTheme.bgCardBorder),
        ),
        child: Column(
          children: [
            const Text('Backend offline — importances unavailable.',
                style: TextStyle(color: AppTheme.textMuted, fontSize: 13)),
            const SizedBox(height: 10),
            OutlinedButton.icon(
              icon: const Icon(Icons.refresh_rounded, size: 16),
              label: const Text('Retry'),
              onPressed: _loadImportances,
            ),
          ],
        ),
      );
    }

    final max = (_importances.first['importance'] as num?)?.toDouble() ?? 1.0;

    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: AppTheme.accentPurple.withOpacity(0.25)),
      ),
      child: Column(
        children: _importances.map((imp) {
          final name       = imp['feature'] as String? ?? '';
          final importance = (imp['importance'] as num?)?.toDouble() ?? 0.0;
          final desc       = imp['description'] as String? ?? '';
          final barWidth   = importance / max;

          return Padding(
            padding: const EdgeInsets.only(bottom: 10),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Expanded(
                      child: Text(
                        name.replaceAll('_', ' '),
                        style: const TextStyle(
                            color: AppTheme.textPrimary,
                            fontSize: 12,
                            fontWeight: FontWeight.w600),
                      ),
                    ),
                    Text(
                      importance.toStringAsFixed(4),
                      style: const TextStyle(
                          color: AppTheme.accentPurple,
                          fontSize: 11,
                          fontFamily: 'monospace'),
                    ),
                  ],
                ),
                const SizedBox(height: 4),
                LayoutBuilder(
                  builder: (ctx, constraints) => Stack(
                    children: [
                      Container(
                        height: 5,
                        width: constraints.maxWidth,
                        decoration: BoxDecoration(
                          color: AppTheme.bgCardBorder,
                          borderRadius: BorderRadius.circular(3),
                        ),
                      ),
                      Container(
                        height: 5,
                        width: constraints.maxWidth * barWidth,
                        decoration: BoxDecoration(
                          gradient: const LinearGradient(
                            colors: [AppTheme.accentBlue, AppTheme.accentPurple],
                          ),
                          borderRadius: BorderRadius.circular(3),
                        ),
                      ),
                    ],
                  ),
                ),
                if (desc.isNotEmpty) ...[
                  const SizedBox(height: 2),
                  Text(desc,
                      style: const TextStyle(
                          color: AppTheme.textMuted, fontSize: 10),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis),
                ],
              ],
            ),
          );
        }).toList(),
      ),
    );
  }

  // ── Intel Loop ─────────────────────────────────────────────────────────────

  Widget _buildIntelLoop() => Container(
    padding: const EdgeInsets.all(16),
    decoration: BoxDecoration(
      color: AppTheme.bgCard,
      borderRadius: BorderRadius.circular(14),
      border: Border.all(color: AppTheme.dangerRed.withOpacity(0.25)),
    ),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Row(
          children: [
            Icon(Icons.biotech_rounded, color: AppTheme.dangerRed, size: 18),
            SizedBox(width: 8),
            Expanded(
              child: Text(
                'Submit confirmed phishing URLs to update the Random Forest model.',
                style: TextStyle(
                    color: AppTheme.textSecondary, fontSize: 12, height: 1.4),
              ),
            ),
          ],
        ),
        const SizedBox(height: 14),

        const Text('PHISHING URLS (one per line)',
            style: TextStyle(
                color: AppTheme.textMuted,
                fontSize: 10,
                fontWeight: FontWeight.w700,
                letterSpacing: 1.0)),
        const SizedBox(height: 6),
        TextField(
          controller: _intelUrlController,
          maxLines: 5,
          keyboardType: TextInputType.multiline,
          style: AppTheme.monoUrl.copyWith(fontSize: 12),
          decoration: const InputDecoration(
            hintText: 'http://phishing1.com/login\nhttp://steal-creds.xyz/...',
          ),
        ),
        const SizedBox(height: 12),

        if (_intelMessage != null) ...[
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: _intelMessageColor.withOpacity(0.08),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: _intelMessageColor.withOpacity(0.3)),
            ),
            child: Text(
              _intelMessage!,
              style: TextStyle(color: _intelMessageColor, fontSize: 12),
            ),
          ),
          const SizedBox(height: 10),
        ],

        SizedBox(
          width: double.infinity,
          child: ElevatedButton.icon(
            icon: _intelLoading
                ? const SizedBox(
                    width: 16,
                    height: 16,
                    child: CircularProgressIndicator(
                        strokeWidth: 2, color: Colors.white))
                : const Icon(Icons.upload_rounded),
            label: Text(_intelLoading ? 'Submitting…' : 'Submit to Intel Loop'),
            style: ElevatedButton.styleFrom(
                backgroundColor: AppTheme.dangerRed),
            onPressed: _intelLoading ? null : _submitIntelReport,
          ),
        ),
        const SizedBox(height: 8),
        const Text(
          'The Intel API key is now configured via the Connection Settings section above. '
          'URLs are feature-extracted and added to the training set. '
          'Model retraining triggers automatically after 10+ new samples.',
          style: TextStyle(color: AppTheme.textMuted, fontSize: 10, height: 1.4),
        ),
      ],
    ),
  );

  @override
  void dispose() {
    _urlController.dispose();
    _apiKeyController.dispose();
    _intelUrlController.dispose();
    super.dispose();
  }
}

// ── Info row helper ────────────────────────────────────────────────────────────

class _InfoRow extends StatelessWidget {
  final String label;
  final String value;
  final Color? valueColor;

  const _InfoRow({required this.label, required this.value, this.valueColor});

  @override
  Widget build(BuildContext context) => Row(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Expanded(
        flex: 2,
        child: Text(label,
            style: const TextStyle(color: AppTheme.textMuted, fontSize: 13)),
      ),
      Expanded(
        flex: 3,
        child: Text(
          value,
          style: TextStyle(
              color: valueColor ?? AppTheme.textPrimary,
              fontSize: 12,
              fontWeight: FontWeight.w600,
              fontFamily: valueColor == AppTheme.accentCyan ? 'monospace' : null),
          textAlign: TextAlign.end,
          maxLines: 2,
          overflow: TextOverflow.ellipsis,
        ),
      ),
    ],
  );
}