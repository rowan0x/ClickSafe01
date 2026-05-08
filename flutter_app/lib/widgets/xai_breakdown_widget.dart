// lib/widgets/xai_breakdown_widget.dart
//
// Explainable AI breakdown panel.
// Shows the Random Forest feature contributions as horizontal bar charts.

import 'package:flutter/material.dart';
import '../models/scan_result.dart';
import '../theme/app_theme.dart';

class XaiBreakdownWidget extends StatefulWidget {
  final XaiResult xai;

  const XaiBreakdownWidget({super.key, required this.xai});

  @override
  State<XaiBreakdownWidget> createState() => _XaiBreakdownWidgetState();
}

class _XaiBreakdownWidgetState extends State<XaiBreakdownWidget> {
  bool _expanded = false;

  @override
  Widget build(BuildContext context) {
    final xai = widget.xai;

    return Container(
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: AppTheme.accentPurple.withOpacity(0.3)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // ── Header ─────────────────────────────────────────────────────────
          InkWell(
            onTap: () => setState(() => _expanded = !_expanded),
            borderRadius: BorderRadius.circular(16),
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Row(
                children: [
                  Container(
                    padding: const EdgeInsets.all(8),
                    decoration: BoxDecoration(
                      color: AppTheme.accentPurple.withOpacity(0.15),
                      borderRadius: BorderRadius.circular(10),
                    ),
                    child: const Icon(Icons.psychology_rounded,
                        color: AppTheme.accentPurple, size: 20),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Text(
                          'Explainable AI (XAI)',
                          style: TextStyle(
                            color: AppTheme.textPrimary,
                            fontSize: 15,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                        Text(
                          '${xai.ruleCount} rules fired · '
                          '${xai.highSeverityRules} high-severity',
                          style: const TextStyle(
                            color: AppTheme.textMuted,
                            fontSize: 12,
                          ),
                        ),
                      ],
                    ),
                  ),
                  Icon(
                    _expanded ? Icons.expand_less : Icons.expand_more,
                    color: AppTheme.textMuted,
                  ),
                ],
              ),
            ),
          ),

          // ── Why summary ────────────────────────────────────────────────────
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
            child: Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: AppTheme.accentPurple.withOpacity(0.06),
                borderRadius: BorderRadius.circular(10),
              ),
              child: Text(
                xai.whySummary,
                style: const TextStyle(
                  color: AppTheme.textSecondary,
                  fontSize: 13,
                  height: 1.5,
                ),
              ),
            ),
          ),

          // ── Feature bars (collapsible) ─────────────────────────────────────
          if (_expanded) ...[
            const Divider(height: 1),
            const Padding(
              padding: EdgeInsets.fromLTRB(16, 12, 16, 8),
              child: Text(
                'FEATURE CONTRIBUTIONS',
                style: TextStyle(
                  color: AppTheme.textMuted,
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                  letterSpacing: 1.0,
                ),
              ),
            ),
            ...xai.featureContributions.take(10).map(
              (fc) => _FeatureBar(contribution: fc),
            ),
            const SizedBox(height: 12),
          ],
        ],
      ),
    );
  }
}

class _FeatureBar extends StatelessWidget {
  final FeatureContribution contribution;

  const _FeatureBar({required this.contribution});

  @override
  Widget build(BuildContext context) {
    final fc  = contribution;
    final pct = (fc.normalised * 100).clamp(0.0, 100.0);

    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  _formatFeatureName(fc.feature),
                  style: const TextStyle(
                    color: AppTheme.textPrimary,
                    fontSize: 13,
                    fontWeight: FontWeight.w500,
                  ),
                ),
              ),
              const SizedBox(width: 8),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
                decoration: BoxDecoration(
                  color: fc.riskColor.withOpacity(0.15),
                  borderRadius: BorderRadius.circular(6),
                ),
                child: Text(
                  '${fc.value}',
                  style: TextStyle(
                    color: fc.riskColor,
                    fontSize: 11,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 4),
          // Progress bar
          LayoutBuilder(
            builder: (ctx, constraints) => Stack(
              children: [
                Container(
                  height: 6,
                  width: constraints.maxWidth,
                  decoration: BoxDecoration(
                    color: AppTheme.bgCardBorder,
                    borderRadius: BorderRadius.circular(3),
                  ),
                ),
                AnimatedContainer(
                  duration: const Duration(milliseconds: 600),
                  curve: Curves.easeOut,
                  height: 6,
                  width: constraints.maxWidth * (pct / 100),
                  decoration: BoxDecoration(
                    gradient: LinearGradient(
                      colors: [
                        fc.riskColor.withOpacity(0.6),
                        fc.riskColor,
                      ],
                    ),
                    borderRadius: BorderRadius.circular(3),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 2),
          Text(
            fc.description,
            style: const TextStyle(color: AppTheme.textMuted, fontSize: 11),
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
          const SizedBox(height: 6),
        ],
      ),
    );
  }

  String _formatFeatureName(String name) =>
      name.replaceAll('_', ' ').split(' ')
          .map((w) => w.isEmpty ? '' : '${w[0].toUpperCase()}${w.substring(1)}')
          .join(' ');
}
