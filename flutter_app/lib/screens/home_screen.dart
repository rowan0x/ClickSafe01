// lib/screens/home_screen.dart

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:image_picker/image_picker.dart';
import '../config/app_config.dart';
import '../models/scan_result.dart';
import '../services/api_service.dart';
import '../services/fast_path_analyzer.dart';
import '../services/history_service.dart';
import '../theme/app_theme.dart';
import 'result_screen.dart';
import 'history_screen.dart';
import 'settings_screen.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  final _urlController    = TextEditingController();
  final _textController   = TextEditingController(); // visible link text
  final _api              = ApiService.instance;
  final _fastAnalyzer     = FastPathAnalyzer();
  final _history          = HistoryService.instance;
  // Shared controller: used for both live camera scanning and
  // analyzeImage() gallery decoding (mobile_scanner ^5.x API).
  final _scannerController = MobileScannerController();

  bool _isScanning    = false;
  bool _showQrScanner = false;
  BackendHealth? _health;
  String? _statusMessage;
  bool _showLinkText  = false;

  @override
  void initState() {
    super.initState();
    _checkBackend();
  }

  Future<void> _checkBackend() async {
    final health = await _api.checkHealth();
    if (mounted) setState(() => _health = health);
  }

  // ── Main scan flow ─────────────────────────────────────────────────────────

  Future<void> _onScanPressed() async {
    final raw = _urlController.text.trim();
    if (raw.isEmpty) {
      _showSnack('Please enter a URL to scan.');
      return;
    }
    await _scan(raw, visibleText: _textController.text.trim());
  }

  Future<void> _scan(String url, {String visibleText = ''}) async {
    setState(() {
      _isScanning    = true;
      _statusMessage = 'Running Fast Path analysis…';
    });

    // ── Step 1: Instant on-device Fast Path ───────────────────────────────
    final fastLocal = _fastAnalyzer.analyze(url, visibleText: visibleText);

    // ── Step 2: Backend Fast Path (ML + full rules) ────────────────────────
    ScanResult? result;
    try {
      setState(() => _statusMessage = 'Consulting ML engine…');
      result = await _api.analyze(url, visibleText: visibleText);
    } catch (e) {
      // If backend unreachable, show on-device result only
      if (mounted) {
        setState(() => _isScanning = false);
        _showSnack('Backend unreachable — showing on-device analysis only.');
        _navigateToResult(
          _buildFallbackResult(fastLocal, url),
        );
      }
      return;
    }

    // ── Step 3: Deep Path if suspicious ───────────────────────────────────
    if (result.shouldTriggerDeepPath) {
      try {
        setState(() => _statusMessage =
            '⚠️ Suspicious — triggering Deep Path analysis…');
        result = await _api.deepAnalyze(url);
      } catch (e) {
        // Deep path failed — proceed with fast result, note the failure
        if (mounted) {
          _showSnack('Deep Path unavailable (Selenium not configured). '
              'Showing Fast Path result.');
        }
      }
    }

    if (!mounted) return;

    setState(() => _isScanning = false);

    // Save to history
    await _history.save(result!);

    _navigateToResult(result);
  }

  void _navigateToResult(ScanResult result) {
    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (_) => ResultScreen(result: result, onRescan: _onRescan),
      ),
    );
  }

  void _onRescan(String url) {
    _urlController.text = url;
    _scan(url);
  }

  // ── Paste from clipboard ───────────────────────────────────────────────────

  Future<void> _pasteFromClipboard() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    if (data?.text != null && data!.text!.isNotEmpty) {
      _urlController.text = data.text!;
      _showSnack('URL pasted from clipboard.');
    } else {
      _showSnack('Clipboard is empty.');
    }
  }

  // ── QR code scan ───────────────────────────────────────────────────────────

  /// Lets the user pick an image from the gallery and decodes any QR code
  /// found in it via [MobileScannerController.analyzeImage].
  /// The decoded URL is fed directly into the existing [_scan] pipeline —
  /// no change to how results are displayed.
  Future<void> _pickQrFromGallery() async {
    final XFile? image =
        await ImagePicker().pickImage(source: ImageSource.gallery);
    if (image == null) return; // user cancelled — do nothing

    final BarcodeCapture? capture =
        await _scannerController.analyzeImage(image.path);

    if (!mounted) return;

    if (capture == null || capture.barcodes.isEmpty) {
      _showSnack('No QR code found in the selected image.');
      return;
    }

    final String? raw = capture.barcodes.first.rawValue;
    if (raw != null && raw.isNotEmpty) {
      _urlController.text = raw;
      _scan(raw); // identical entry point as the live camera path
    } else {
      _showSnack('QR code found but contained no readable URL.');
    }
  }

  void _onQrDetected(BarcodeCapture capture) {
    final barcode = capture.barcodes.firstOrNull;
    final raw     = barcode?.rawValue;
    if (raw != null && raw.isNotEmpty) {
      setState(() => _showQrScanner = false);
      _urlController.text = raw;
      _scan(raw);
    }
  }

  // ── Fallback result (backend offline) ─────────────────────────────────────

  ScanResult _buildFallbackResult(FastPathResult fast, String url) {
    return ScanResult(
      success:       true,
      error:         'Backend offline — on-device analysis only.',
      url:           url,
      verdict:       fast.verdict,
      verdictLabel:  '${fast.verdict.emoji} ${fast.verdict.label}',
      triggeredRules: fast.triggeredRules
          .map((r) => TriggeredRule(
                name:        r.name,
                description: r.description,
                severity:    r.severity,
              ))
          .toList(),
      ruleRiskScore: fast.riskScore,
      explanation:   'On-device lexical analysis only (backend offline). '
          '${fast.triggeredRules.length} rule(s) triggered.',
      combinedScore: fast.riskScore.toDouble(),
      pathType:      ScanPathType.fast,
      scannedAt:     DateTime.now(),
    );
  }

  // ── UI ─────────────────────────────────────────────────────────────────────

  void _showSnack(String msg) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(msg),
        backgroundColor: AppTheme.bgCard,
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    if (_showQrScanner) return _buildQrScanner();

    return Scaffold(
      backgroundColor: AppTheme.bgPrimary,
      appBar: AppBar(
        title: const Row(
          children: [
            Icon(Icons.security_rounded, color: AppTheme.accentBlue, size: 22),
            SizedBox(width: 8),
            Text('clicksafe'),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.history_rounded),
            tooltip: 'Scan history',
            onPressed: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const HistoryScreen()),
            ),
          ),
          IconButton(
            icon: const Icon(Icons.settings_outlined),
            tooltip: 'Settings',
            onPressed: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const SettingsScreen()),
            ),
          ),
        ],
      ),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(20),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // ── Hero ───────────────────────────────────────────────────────
              _buildHero(),
              const SizedBox(height: 28),

              // ── Backend status ─────────────────────────────────────────────
              _buildBackendStatus(),
              const SizedBox(height: 24),

              // ── URL input ──────────────────────────────────────────────────
              _buildUrlInput(),
              const SizedBox(height: 12),

              // ── Link text toggle ───────────────────────────────────────────
              _buildLinkTextToggle(),
              const SizedBox(height: 20),

              // ── Action buttons ─────────────────────────────────────────────
              _buildActionButtons(),
              const SizedBox(height: 32),

              // ── How it works ───────────────────────────────────────────────
              _buildHowItWorks(),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildHero() => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      RichText(
        text: const TextSpan(
          style: AppTheme.headingLarge,
          children: [
            TextSpan(text: 'Is this link\n'),
            TextSpan(
              text: 'safe to click?',
              style: TextStyle(color: AppTheme.accentBlue),
            ),
          ],
        ),
      ),
      const SizedBox(height: 8),
      const Text(
        'Hybrid ML + rule-based phishing detection.\n'
        'Fast Path runs in milliseconds. Deep Path inspects the live page.',
        style: AppTheme.bodyText,
      ),
    ],
  );

  Widget _buildBackendStatus() {
    final h = _health;
    if (h == null) {
      return _statusRow(
        Icons.sync_rounded, 'Connecting to backend…', AppTheme.textMuted);
    }
    if (!h.ok) {
      return _statusRow(
        Icons.cloud_off_rounded,
        'Backend offline — on-device analysis only',
        AppTheme.warnAmber,
      );
    }
    return _statusRow(
      Icons.cloud_done_rounded,
      'Backend online · Tranco: ${h.trancodomains} domains · '
      'Intel sigs: ${h.intelSigs}',
      AppTheme.safeGreen,
    );
  }

  Widget _statusRow(IconData icon, String text, Color color) => Row(
    children: [
      Icon(icon, color: color, size: 16),
      const SizedBox(width: 8),
      Expanded(
        child: Text(
          text,
          style: TextStyle(color: color, fontSize: 12),
          overflow: TextOverflow.ellipsis,
        ),
      ),
      IconButton(
        icon: const Icon(Icons.refresh_rounded, size: 16),
        color: AppTheme.textMuted,
        tooltip: 'Refresh',
        onPressed: _checkBackend,
        padding: EdgeInsets.zero,
        constraints: const BoxConstraints(),
      ),
    ],
  );

  Widget _buildUrlInput() => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      const Text('URL to check',
          style: TextStyle(
              color: AppTheme.textSecondary,
              fontSize: 12,
              fontWeight: FontWeight.w600,
              letterSpacing: 0.5)),
      const SizedBox(height: 8),
      TextField(
        controller: _urlController,
        keyboardType: TextInputType.url,
        autocorrect: false,
        style: AppTheme.monoUrl,
        decoration: InputDecoration(
          hintText: 'https://example.com/...',
          prefixIcon: const Icon(Icons.link_rounded,
              color: AppTheme.textMuted, size: 20),
          suffixIcon: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              IconButton(
                icon: const Icon(Icons.content_paste_rounded,
                    color: AppTheme.textMuted, size: 20),
                tooltip: 'Paste from clipboard',
                onPressed: _pasteFromClipboard,
              ),
              // ── Gallery QR upload ─────────────────────────────────────
              IconButton(
                icon: const Icon(Icons.photo_library_outlined,
                    color: AppTheme.accentPurple, size: 20),
                tooltip: 'Upload QR code from gallery',
                onPressed: _pickQrFromGallery,
              ),
              // ─────────────────────────────────────────────────────────
              IconButton(
                icon: const Icon(Icons.qr_code_scanner_rounded,
                    color: AppTheme.accentCyan, size: 20),
                tooltip: 'Scan QR code with camera',
                onPressed: () => setState(() => _showQrScanner = true),
              ),
            ],
          ),
        ),
        onSubmitted: (_) => _onScanPressed(),
      ),
    ],
  );

  Widget _buildLinkTextToggle() => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      GestureDetector(
        onTap: () => setState(() => _showLinkText = !_showLinkText),
        child: Row(
          children: [
            Icon(
              _showLinkText ? Icons.expand_less : Icons.expand_more,
              color: AppTheme.textMuted,
              size: 18,
            ),
            const SizedBox(width: 4),
            const Text(
              'Check for link masking (visible text vs. URL)',
              style: TextStyle(color: AppTheme.textMuted, fontSize: 12),
            ),
          ],
        ),
      ),
      if (_showLinkText) ...[
        const SizedBox(height: 8),
        TextField(
          controller: _textController,
          style: const TextStyle(color: AppTheme.textPrimary, fontSize: 14),
          decoration: const InputDecoration(
            hintText: 'Paste the visible link text here (e.g. "www.paypal.com")',
            prefixIcon: Icon(Icons.text_fields_rounded,
                color: AppTheme.textMuted, size: 20),
          ),
        ),
      ],
    ],
  );

  Widget _buildActionButtons() => Column(
    children: [
      SizedBox(
        width: double.infinity,
        child: ElevatedButton.icon(
          icon: _isScanning
              ? const SizedBox(
                  width: 18, height: 18,
                  child: CircularProgressIndicator(
                      strokeWidth: 2, color: Colors.white))
              : const Icon(Icons.shield_rounded),
          label: Text(_isScanning
              ? (_statusMessage ?? 'Analysing…')
              : 'Analyse URL'),
          onPressed: _isScanning ? null : _onScanPressed,
        ),
      ),
    ],
  );

  Widget _buildHowItWorks() => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      const Text('HOW IT WORKS',
          style: TextStyle(
              color: AppTheme.textMuted,
              fontSize: 11,
              fontWeight: FontWeight.w600,
              letterSpacing: 1.0)),
      const SizedBox(height: 12),
      _FeatureRow(
        icon: Icons.flash_on_rounded,
        color: AppTheme.accentBlue,
        title: 'Fast Path',
        desc: 'On-device lexical rules + backend ML (< 1s)',
      ),
      _FeatureRow(
        icon: Icons.manage_search_rounded,
        color: AppTheme.warnAmber,
        title: 'Deep Path',
        desc: 'Selenium redirect tracing, WHOIS, BiTB detection (5–30s)',
      ),
      _FeatureRow(
        icon: Icons.list_alt_rounded,
        color: AppTheme.safeGreen,
        title: 'Tranco Top 100k',
        desc: 'Major global brands skip ML — zero false positives',
      ),
      _FeatureRow(
        icon: Icons.psychology_rounded,
        color: AppTheme.accentPurple,
        title: 'Explainable AI',
        desc: 'See which features triggered every alert',
      ),
      _FeatureRow(
        icon: Icons.font_download_off_rounded,
        color: AppTheme.accentCyan,
        title: 'Homoglyph Detection',
        desc: 'Catches Cyrillic/Greek look-alike impersonations',
      ),
    ],
  );

  Widget _buildQrScanner() => Scaffold(
    appBar: AppBar(
      title: const Text('Scan QR Code'),
      leading: IconButton(
        icon: const Icon(Icons.arrow_back),
        onPressed: () => setState(() => _showQrScanner = false),
      ),
    ),
    body: MobileScanner(
      controller: _scannerController, // shared with analyzeImage()
      onDetect:   _onQrDetected,
    ),
  );

  @override
  void dispose() {
    _urlController.dispose();
    _textController.dispose();
    _scannerController.dispose();
    super.dispose();
  }
}

// ── Small feature row widget ──────────────────────────────────────────────────

class _FeatureRow extends StatelessWidget {
  final IconData icon;
  final Color color;
  final String title;
  final String desc;

  const _FeatureRow({
    required this.icon,
    required this.color,
    required this.title,
    required this.desc,
  });

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.only(bottom: 12),
    child: Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Container(
          padding: const EdgeInsets.all(8),
          decoration: BoxDecoration(
            color: color.withOpacity(0.12),
            borderRadius: BorderRadius.circular(10),
          ),
          child: Icon(icon, color: color, size: 18),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(title,
                  style: const TextStyle(
                      color: AppTheme.textPrimary,
                      fontSize: 13,
                      fontWeight: FontWeight.w600)),
              Text(desc,
                  style: const TextStyle(
                      color: AppTheme.textMuted, fontSize: 12)),
            ],
          ),
        ),
      ],
    ),
  );
}
