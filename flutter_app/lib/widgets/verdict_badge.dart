// lib/widgets/verdict_badge.dart

import 'package:flutter/material.dart';
import '../models/scan_result.dart';
import '../theme/app_theme.dart';

class VerdictBadge extends StatelessWidget {
  final ScanVerdict verdict;
  final double? mlProbability;
  final int ruleScore;
  final ScanPathType pathType;
  final bool isLoading;

  const VerdictBadge({
    super.key,
    required this.verdict,
    this.mlProbability,
    this.ruleScore = 0,
    this.pathType = ScanPathType.fast,
    this.isLoading = false,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        color: verdict.bgColor,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: verdict.color.withOpacity(0.4), width: 1.5),
        boxShadow: [
          BoxShadow(
            color: verdict.color.withOpacity(0.15),
            blurRadius: 24,
            spreadRadius: 2,
          ),
        ],
      ),
      child: isLoading
          ? _buildLoading()
          : _buildContent(),
    );
  }

  Widget _buildLoading() => Column(
    children: [
      SizedBox(
        width: 48,
        height: 48,
        child: CircularProgressIndicator(
          strokeWidth: 3,
          color: AppTheme.accentBlue,
        ),
      ),
      const SizedBox(height: 12),
      const Text(
        'Analysing…',
        style: TextStyle(
          color: AppTheme.textSecondary,
          fontSize: 14,
          fontWeight: FontWeight.w500,
        ),
      ),
    ],
  );

  Widget _buildContent() => Column(
    children: [
      // Verdict emoji
      Text(verdict.emoji, style: const TextStyle(fontSize: 52)),
      const SizedBox(height: 8),

      // Verdict label
      Text(
        verdict.label.toUpperCase(),
        style: TextStyle(
          fontSize: 22,
          fontWeight: FontWeight.w800,
          color: verdict.color,
          letterSpacing: 1.5,
        ),
      ),
      const SizedBox(height: 16),

      // Score row
      Row(
        mainAxisAlignment: MainAxisAlignment.spaceEvenly,
        children: [
          _ScoreChip(
            label: 'ML Score',
            value: mlProbability != null
                ? '${(mlProbability! * 100).toStringAsFixed(1)}%'
                : '—',
            icon: Icons.psychology_rounded,
            color: AppTheme.accentPurple,
          ),
          _ScoreChip(
            label: 'Rule Score',
            value: ruleScore.toString(),
            icon: Icons.rule_rounded,
            color: AppTheme.accentCyan,
          ),
          _ScoreChip(
            label: 'Path',
            value: pathType == ScanPathType.deep ? 'Deep' : 'Fast',
            icon: pathType == ScanPathType.deep
                ? Icons.manage_search_rounded
                : Icons.flash_on_rounded,
            color: pathType == ScanPathType.deep
                ? AppTheme.warnAmber
                : AppTheme.accentBlue,
          ),
        ],
      ),
    ],
  );
}

class _ScoreChip extends StatelessWidget {
  final String label;
  final String value;
  final IconData icon;
  final Color color;

  const _ScoreChip({
    required this.label,
    required this.value,
    required this.icon,
    required this.color,
  });

  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
    decoration: BoxDecoration(
      color: color.withOpacity(0.1),
      borderRadius: BorderRadius.circular(10),
      border: Border.all(color: color.withOpacity(0.3)),
    ),
    child: Column(
      children: [
        Icon(icon, color: color, size: 18),
        const SizedBox(height: 4),
        Text(
          value,
          style: TextStyle(
            color: color,
            fontSize: 15,
            fontWeight: FontWeight.w700,
          ),
        ),
        Text(
          label,
          style: const TextStyle(
            color: AppTheme.textMuted,
            fontSize: 10,
            letterSpacing: 0.5,
          ),
        ),
      ],
    ),
  );
}
