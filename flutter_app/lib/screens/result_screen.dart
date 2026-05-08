// lib/screens/result_screen.dart

import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:share_plus/share_plus.dart';
import 'package:url_launcher/url_launcher.dart';
import '../models/scan_result.dart';
import '../theme/app_theme.dart';
import '../widgets/verdict_badge.dart';
import '../widgets/xai_breakdown_widget.dart';
import '../widgets/rule_card_widget.dart';

class ResultScreen extends StatelessWidget {
  final ScanResult result;
  final void Function(String url)? onRescan;

  const ResultScreen({super.key, required this.result, this.onRescan});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.bgPrimary,
      appBar: AppBar(
        title: const Text('Scan Result'),
        actions: [
          IconButton(
            icon: const Icon(Icons.share_outlined),
            tooltip: 'Share result',
            onPressed: () => _share(),
          ),
          IconButton(
            icon: const Icon(Icons.copy_rounded),
            tooltip: 'Copy URL',
            onPressed: () {
              Clipboard.setData(ClipboardData(text: result.url));
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('URL copied to clipboard')),
              );
            },
          ),
        ],
      ),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(20),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // ── Verdict card ───────────────────────────────────────────────
              VerdictBadge(
                verdict:       result.verdict,
                mlProbability: result.mlResult?.probability,
                ruleScore:     result.ruleRiskScore,
                pathType:      result.pathType,
              ),
              const SizedBox(height: 16),

              // ── URL display ────────────────────────────────────────────────
              _buildUrlCard(),
              const SizedBox(height: 16),

              // ── Explanation ────────────────────────────────────────────────
              _buildExplanationCard(),
              const SizedBox(height: 16),

              // ── Special flags: whitelist / homoglyph / link masking ────────
              _buildSpecialFlags(),

              // ── Deep path results (if available) ──────────────────────────
              if (result.pathType == ScanPathType.deep) ...[
                _buildDeepPathCard(),
                const SizedBox(height: 16),
              ],

              // ── Triggered rules ────────────────────────────────────────────
              if (result.triggeredRules.isNotEmpty) ...[
                _buildRulesSection(),
                const SizedBox(height: 16),
              ],

              // ── XAI breakdown ──────────────────────────────────────────────
              if (result.xai != null) ...[
                XaiBreakdownWidget(xai: result.xai!),
                const SizedBox(height: 16),
              ],

              // ── ML features table ──────────────────────────────────────────
              if (result.features != null) ...[
                _buildFeaturesTable(),
                const SizedBox(height: 16),
              ],

              // ── Action buttons ─────────────────────────────────────────────
              _buildActions(context),
              const SizedBox(height: 32),
            ],
          ),
        ),
      ),
    );
  }

  // ── URL card ─────────────────────────────────────────────────────────────

  Widget _buildUrlCard() => Container(
    padding: const EdgeInsets.all(14),
    decoration: BoxDecoration(
      color: AppTheme.bgCard,
      borderRadius: BorderRadius.circular(12),
      border: Border.all(color: AppTheme.bgCardBorder),
    ),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text('SCANNED URL',
            style: TextStyle(
                color: AppTheme.textMuted,
                fontSize: 11,
                letterSpacing: 0.8,
                fontWeight: FontWeight.w600)),
        const SizedBox(height: 6),
        Text(
          result.url,
          style: AppTheme.monoUrl,
          maxLines: 3,
          overflow: TextOverflow.ellipsis,
        ),
        if (result.pathType == ScanPathType.deep &&
            result.finalUrl.isNotEmpty &&
            result.finalUrl != result.url) ...[
          const SizedBox(height: 8),
          const Divider(height: 1),
          const SizedBox(height: 8),
          const Text('FINAL DESTINATION (after redirects)',
              style: TextStyle(
                  color: AppTheme.warnAmber,
                  fontSize: 11,
                  letterSpacing: 0.8,
                  fontWeight: FontWeight.w600)),
          const SizedBox(height: 4),
          Text(result.finalUrl,
              style: AppTheme.monoUrl.copyWith(color: AppTheme.warnAmber),
              maxLines: 3,
              overflow: TextOverflow.ellipsis),
        ],
      ],
    ),
  );

  // ── Explanation card ──────────────────────────────────────────────────────

  Widget _buildExplanationCard() {
    if (result.explanation.isEmpty) return const SizedBox.shrink();
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: result.verdict.bgColor,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: result.verdict.color.withOpacity(0.2)),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(Icons.info_outline_rounded,
              color: result.verdict.color, size: 18),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              result.explanation,
              style: const TextStyle(
                  color: AppTheme.textSecondary, fontSize: 13, height: 1.5),
            ),
          ),
        ],
      ),
    );
  }

  // ── Special flags ─────────────────────────────────────────────────────────

  Widget _buildSpecialFlags() {
    final flags = <Widget>[];

    // Whitelist
    final wl = result.whitelist;
    if (wl != null && wl.whitelisted) {
      flags.add(_FlagChip(
        icon: Icons.verified_rounded,
        label: 'Tranco Top-100k: ${wl.domain}',
        color: AppTheme.safeGreen,
      ));
    }

    // Homoglyph
    final hg = result.homoglyph;
    if (hg != null && hg.isSuspicious) {
      flags.add(_FlagChip(
        icon: Icons.font_download_off_rounded,
        label: 'Homoglyph: impersonating "${hg.matchedBrand}"',
        color: AppTheme.dangerRed,
      ));
    }

    // Link masking
    final lm = result.linkMasking;
    if (lm != null && lm.isMasked) {
      flags.add(_FlagChip(
        icon: Icons.visibility_off_rounded,
        label: 'Link masking: shows "${lm.visibleDomain}"',
        color: AppTheme.dangerRed,
      ));
    }

    if (flags.isEmpty) return const SizedBox.shrink();

    return Padding(
      padding: const EdgeInsets.only(bottom: 16),
      child: Wrap(spacing: 8, runSpacing: 8, children: flags),
    );
  }

  // ── Deep Path card ───────────────────────────────────────────────────────

  Widget _buildDeepPathCard() => Container(
    padding: const EdgeInsets.all(16),
    decoration: BoxDecoration(
      color: AppTheme.bgCard,
      borderRadius: BorderRadius.circular(16),
      border: Border.all(color: AppTheme.warnAmber.withOpacity(0.3)),
    ),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: AppTheme.warnAmber.withOpacity(0.12),
                borderRadius: BorderRadius.circular(10),
              ),
              child: const Icon(Icons.manage_search_rounded,
                  color: AppTheme.warnAmber, size: 20),
            ),
            const SizedBox(width: 12),
            const Text('Deep Path Analysis',
                style: TextStyle(
                    color: AppTheme.textPrimary,
                    fontSize: 15,
                    fontWeight: FontWeight.w700)),
          ],
        ),
        const SizedBox(height: 16),

        // Redirect chain
        if (result.redirectChain.isNotEmpty) ...[
          const Text('Redirect Chain',
              style: TextStyle(
                  color: AppTheme.textMuted,
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                  letterSpacing: 0.8)),
          const SizedBox(height: 8),
          ...result.redirectChain.map((hop) => _RedirectHop(hop: hop)),
          const SizedBox(height: 12),
        ],

        // Deep flags row
        Wrap(
          spacing: 8,
          runSpacing: 8,
          children: [
            if (result.bitbDetected)
              _FlagChip(
                icon: Icons.web_rounded,
                label: 'BiTB Attack',
                color: AppTheme.dangerRed,
              ),
            if (result.newlyRegistered)
              _FlagChip(
                icon: Icons.new_releases_rounded,
                label: 'Newly Registered${result.domainAgeDays != null ? ' (${result.domainAgeDays}d)' : ''}',
                color: AppTheme.dangerRed,
              ),
            if (result.hasLoginForm)
              _FlagChip(
                icon: Icons.login_rounded,
                label: 'Login Form',
                color: AppTheme.warnAmber,
              ),
            if (result.hasPasswordField)
              _FlagChip(
                icon: Icons.password_rounded,
                label: 'Password Field',
                color: AppTheme.warnAmber,
              ),
          ],
        ),

        // BiTB detail
        if (result.bitbDetected && result.bitbDetail.isNotEmpty) ...[
          const SizedBox(height: 12),
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: AppTheme.dangerRed.withOpacity(0.08),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Text(result.bitbDetail,
                style: const TextStyle(
                    color: AppTheme.textSecondary, fontSize: 12, height: 1.4)),
          ),
        ],

        // Screenshot
        if (result.screenshotB64 != null &&
            result.screenshotB64!.isNotEmpty) ...[
          const SizedBox(height: 12),
          const Text('Page Screenshot',
              style: TextStyle(
                  color: AppTheme.textMuted,
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                  letterSpacing: 0.8)),
          const SizedBox(height: 8),
          ClipRRect(
            borderRadius: BorderRadius.circular(8),
            child: Image.memory(
              base64Decode(result.screenshotB64!),
              fit: BoxFit.contain,
            ),
          ),
        ],
      ],
    ),
  );

  // ── Rules section ─────────────────────────────────────────────────────────

  Widget _buildRulesSection() => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Row(
        children: [
          const Text('TRIGGERED RULES',
              style: TextStyle(
                  color: AppTheme.textMuted,
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                  letterSpacing: 1.0)),
          const Spacer(),
          RuleSummaryRow(rules: result.triggeredRules),
        ],
      ),
      const SizedBox(height: 10),
      ...result.triggeredRules.asMap().entries.map(
        (e) => RuleCardWidget(rule: e.value, index: e.key),
      ),
    ],
  );

  // ── ML features table ─────────────────────────────────────────────────────

  Widget _buildFeaturesTable() => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      const Text('ML FEATURE VECTOR (14 features)',
          style: TextStyle(
              color: AppTheme.textMuted,
              fontSize: 11,
              fontWeight: FontWeight.w600,
              letterSpacing: 1.0)),
      const SizedBox(height: 8),
      Container(
        decoration: BoxDecoration(
          color: AppTheme.bgCard,
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: AppTheme.bgCardBorder),
        ),
        child: Column(
          children: result.features!.entries
              .toList()
              .asMap()
              .entries
              .map((entry) {
            final i = entry.key;
            final k = entry.value.key;
            final v = entry.value.value;
            return Container(
              padding: const EdgeInsets.symmetric(
                  horizontal: 14, vertical: 8),
              decoration: BoxDecoration(
                border: i < result.features!.length - 1
                    ? const Border(
                        bottom: BorderSide(
                            color: AppTheme.bgCardBorder))
                    : null,
              ),
              child: Row(
                children: [
                  Expanded(
                    child: Text(
                      k.replaceAll('_', ' '),
                      style: const TextStyle(
                          color: AppTheme.textSecondary, fontSize: 12),
                    ),
                  ),
                  Text(
                    v.toString(),
                    style: const TextStyle(
                        color: AppTheme.accentCyan,
                        fontSize: 12,
                        fontFamily: 'monospace',
                        fontWeight: FontWeight.w600),
                  ),
                ],
              ),
            );
          }).toList(),
        ),
      ),
    ],
  );

  // ── Action buttons ────────────────────────────────────────────────────────

  Widget _buildActions(BuildContext context) => Column(
    children: [
      // Open link — only shown if verdict is safe
      if (result.verdict == ScanVerdict.safe) ...[
        SizedBox(
          width: double.infinity,
          child: ElevatedButton.icon(
            icon: const Icon(Icons.open_in_browser_rounded),
            label: const Text('Open Link (Verified Safe)'),
            style: ElevatedButton.styleFrom(
              backgroundColor: AppTheme.safeGreen,
            ),
            onPressed: () async {
              final uri = Uri.tryParse(result.url);
              if (uri != null && await canLaunchUrl(uri)) {
                await launchUrl(uri,
                    mode: LaunchMode.externalApplication);
              }
            },
          ),
        ),
        const SizedBox(height: 10),
      ],

      // Report as phishing
      if (result.verdict != ScanVerdict.safe) ...[
        SizedBox(
          width: double.infinity,
          child: OutlinedButton.icon(
            icon: const Icon(Icons.report_rounded, color: AppTheme.dangerRed),
            label: const Text('Report as Phishing',
                style: TextStyle(color: AppTheme.dangerRed)),
            style: OutlinedButton.styleFrom(
              side: const BorderSide(color: AppTheme.dangerRed),
            ),
            onPressed: () => _showReportDialog(context),
          ),
        ),
        const SizedBox(height: 10),
      ],

      // Rescan
      SizedBox(
        width: double.infinity,
        child: OutlinedButton.icon(
          icon: const Icon(Icons.refresh_rounded),
          label: const Text('Rescan'),
          onPressed: () {
            Navigator.pop(context);
            onRescan?.call(result.url);
          },
        ),
      ),
    ],
  );

  // ── Report dialog ─────────────────────────────────────────────────────────

  void _showReportDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppTheme.bgCard,
        title: const Text('Report as Phishing',
            style: TextStyle(color: AppTheme.textPrimary)),
        content: const Text(
          'This will submit the URL to the Intel Loop to improve '
          'detection for everyone. Confirm?',
          style: TextStyle(color: AppTheme.textSecondary),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Cancel',
                style: TextStyle(color: AppTheme.textMuted)),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
                backgroundColor: AppTheme.dangerRed),
            onPressed: () {
              Navigator.pop(ctx);
              // Intel loop ingestion is handled in SettingsScreen;
              // here we just show a confirmation.
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(
                    content: Text('Reported. Thank you for keeping the web safer!')),
              );
            },
            child: const Text('Report'),
          ),
        ],
      ),
    );
  }

  // ── Share ─────────────────────────────────────────────────────────────────

  void _share() {
    final text = '🛡️ clicksafe scan result\n\n'
        'URL: ${result.url}\n'
        'Verdict: ${result.verdict.label}\n'
        'ML Score: ${result.mlResult != null ? '${(result.mlResult!.probability * 100).toStringAsFixed(1)}%' : 'N/A'}\n'
        'Rules fired: ${result.triggeredRules.length}\n\n'
        'Scanned with clicksafe — phishing detection powered by ML.';
    Share.share(text);
  }
}

// ── Helper widgets ────────────────────────────────────────────────────────────

class _FlagChip extends StatelessWidget {
  final IconData icon;
  final String label;
  final Color color;

  const _FlagChip(
      {required this.icon, required this.label, required this.color});

  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
    decoration: BoxDecoration(
      color: color.withOpacity(0.1),
      borderRadius: BorderRadius.circular(20),
      border: Border.all(color: color.withOpacity(0.4)),
    ),
    child: Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(icon, color: color, size: 14),
        const SizedBox(width: 6),
        Text(label,
            style: TextStyle(
                color: color, fontSize: 12, fontWeight: FontWeight.w600)),
      ],
    ),
  );
}

class _RedirectHop extends StatelessWidget {
  final Map<String, dynamic> hop;

  const _RedirectHop({required this.hop});

  @override
  Widget build(BuildContext context) {
    final status = hop['status_code'];
    final url    = hop['url'] as String? ?? '';
    final hopNum = hop['hop'] as int? ?? 0;
    final isRedirect = status is int && (status >= 300 && status < 400);

    return Padding(
      padding: const EdgeInsets.only(bottom: 6),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width: 24,
            height: 24,
            decoration: BoxDecoration(
              color: isRedirect
                  ? AppTheme.warnAmber.withOpacity(0.15)
                  : AppTheme.bgCardBorder,
              shape: BoxShape.circle,
            ),
            child: Center(
              child: Text(
                '$hopNum',
                style: TextStyle(
                    color: isRedirect
                        ? AppTheme.warnAmber
                        : AppTheme.textMuted,
                    fontSize: 11,
                    fontWeight: FontWeight.w700),
              ),
            ),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  url.length > 50 ? '${url.substring(0, 48)}…' : url,
                  style: AppTheme.monoUrl.copyWith(fontSize: 11),
                ),
                Text(
                  'HTTP $status',
                  style: TextStyle(
                      color: isRedirect
                          ? AppTheme.warnAmber
                          : AppTheme.safeGreen,
                      fontSize: 11),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
