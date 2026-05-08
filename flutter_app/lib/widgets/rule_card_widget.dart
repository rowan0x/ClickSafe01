// lib/widgets/rule_card_widget.dart

import 'package:flutter/material.dart';
import '../models/scan_result.dart';
import '../theme/app_theme.dart';

class RuleCardWidget extends StatelessWidget {
  final TriggeredRule rule;
  final int index;

  const RuleCardWidget({super.key, required this.rule, required this.index});

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: rule.severityColor.withOpacity(0.06),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: rule.severityColor.withOpacity(0.25)),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Severity icon
          Container(
            width: 32,
            height: 32,
            decoration: BoxDecoration(
              color: rule.severityColor.withOpacity(0.15),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Icon(rule.severityIcon, color: rule.severityColor, size: 18),
          ),
          const SizedBox(width: 12),
          // Content
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Expanded(
                      child: Text(
                        rule.name,
                        style: const TextStyle(
                          color: AppTheme.textPrimary,
                          fontSize: 13,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ),
                    Container(
                      padding: const EdgeInsets.symmetric(
                          horizontal: 7, vertical: 2),
                      decoration: BoxDecoration(
                        color: rule.severityColor.withOpacity(0.15),
                        borderRadius: BorderRadius.circular(6),
                      ),
                      child: Text(
                        rule.severity.toUpperCase(),
                        style: TextStyle(
                          color: rule.severityColor,
                          fontSize: 10,
                          fontWeight: FontWeight.w700,
                          letterSpacing: 0.5,
                        ),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 4),
                Text(
                  rule.description,
                  style: const TextStyle(
                    color: AppTheme.textSecondary,
                    fontSize: 12,
                    height: 1.4,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

// ── Summary chip row for compact display ──────────────────────────────────────

class RuleSummaryRow extends StatelessWidget {
  final List<TriggeredRule> rules;

  const RuleSummaryRow({super.key, required this.rules});

  @override
  Widget build(BuildContext context) {
    if (rules.isEmpty) {
      return const Row(
        children: [
          Icon(Icons.check_circle_outline, color: AppTheme.safeGreen, size: 16),
          SizedBox(width: 6),
          Text('No rules triggered',
              style: TextStyle(color: AppTheme.safeGreen, fontSize: 13)),
        ],
      );
    }

    final highCount = rules.where((r) => r.severity == 'high').length;
    final medCount  = rules.where((r) => r.severity == 'medium').length;

    return Wrap(
      spacing: 8,
      runSpacing: 6,
      children: [
        if (highCount > 0)
          _SeverityChip(
            count: highCount,
            label: 'High',
            color: AppTheme.dangerRed,
          ),
        if (medCount > 0)
          _SeverityChip(
            count: medCount,
            label: 'Medium',
            color: AppTheme.warnAmber,
          ),
      ],
    );
  }
}

class _SeverityChip extends StatelessWidget {
  final int count;
  final String label;
  final Color color;

  const _SeverityChip({
    required this.count,
    required this.label,
    required this.color,
  });

  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
    decoration: BoxDecoration(
      color: color.withOpacity(0.12),
      borderRadius: BorderRadius.circular(20),
      border: Border.all(color: color.withOpacity(0.3)),
    ),
    child: Text(
      '$count $label',
      style: TextStyle(color: color, fontSize: 12, fontWeight: FontWeight.w600),
    ),
  );
}
