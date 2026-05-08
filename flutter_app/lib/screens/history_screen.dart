// lib/screens/history_screen.dart

import 'package:flutter/material.dart';
import '../models/scan_history_item.dart';
import '../models/scan_result.dart';
import '../services/history_service.dart';
import '../theme/app_theme.dart';

class HistoryScreen extends StatefulWidget {
  const HistoryScreen({super.key});

  @override
  State<HistoryScreen> createState() => _HistoryScreenState();
}

class _HistoryScreenState extends State<HistoryScreen> {
  final _history = HistoryService.instance;

  List<ScanHistoryItem> _items = [];
  Map<String, int> _stats = {};
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    setState(() => _loading = true);
    final items = await _history.load();
    final stats = await _history.getStats();
    if (mounted) {
      setState(() {
        _items   = items;
        _stats   = stats;
        _loading = false;
      });
    }
  }

  Future<void> _clearHistory() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppTheme.bgCard,
        title: const Text('Clear History',
            style: TextStyle(color: AppTheme.textPrimary)),
        content: const Text(
          'Delete all scan history? This cannot be undone.',
          style: TextStyle(color: AppTheme.textSecondary),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancel',
                style: TextStyle(color: AppTheme.textMuted)),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
                backgroundColor: AppTheme.dangerRed),
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('Clear All'),
          ),
        ],
      ),
    );
    if (confirmed == true) {
      await _history.clear();
      await _load();
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.bgPrimary,
      appBar: AppBar(
        title: const Text('Scan History'),
        actions: [
          if (_items.isNotEmpty)
            IconButton(
              icon: const Icon(Icons.delete_outline_rounded),
              tooltip: 'Clear history',
              onPressed: _clearHistory,
            ),
        ],
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : _items.isEmpty
              ? _buildEmpty()
              : _buildList(),
    );
  }

  Widget _buildEmpty() => Center(
    child: Column(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        Icon(Icons.history_rounded,
            size: 64, color: AppTheme.textMuted.withOpacity(0.4)),
        const SizedBox(height: 16),
        const Text('No scans yet',
            style: TextStyle(color: AppTheme.textMuted, fontSize: 16)),
        const SizedBox(height: 8),
        const Text('Scanned URLs will appear here.',
            style: TextStyle(color: AppTheme.textMuted, fontSize: 13)),
      ],
    ),
  );

  Widget _buildList() => CustomScrollView(
    slivers: [
      // ── Stats header ─────────────────────────────────────────────────────
      SliverToBoxAdapter(
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: _buildStats(),
        ),
      ),

      // ── List ──────────────────────────────────────────────────────────────
      SliverPadding(
        padding: const EdgeInsets.symmetric(horizontal: 20),
        sliver: SliverList(
          delegate: SliverChildBuilderDelegate(
            (ctx, i) => _HistoryTile(item: _items[i]),
            childCount: _items.length,
          ),
        ),
      ),

      const SliverToBoxAdapter(child: SizedBox(height: 40)),
    ],
  );

  Widget _buildStats() => Row(
    children: [
      _StatBox(
        label: 'Total',
        value: '${_stats['total'] ?? 0}',
        color: AppTheme.accentBlue,
        icon: Icons.bar_chart_rounded,
      ),
      const SizedBox(width: 10),
      _StatBox(
        label: 'Safe',
        value: '${_stats['safe'] ?? 0}',
        color: AppTheme.safeGreen,
        icon: Icons.check_circle_outline_rounded,
      ),
      const SizedBox(width: 10),
      _StatBox(
        label: 'Suspicious',
        value: '${_stats['suspicious'] ?? 0}',
        color: AppTheme.warnAmber,
        icon: Icons.warning_amber_rounded,
      ),
      const SizedBox(width: 10),
      _StatBox(
        label: 'Phishing',
        value: '${_stats['phishing'] ?? 0}',
        color: AppTheme.dangerRed,
        icon: Icons.dangerous_rounded,
      ),
    ],
  );
}

// ── Stat box ──────────────────────────────────────────────────────────────────

class _StatBox extends StatelessWidget {
  final String label;
  final String value;
  final Color color;
  final IconData icon;

  const _StatBox({
    required this.label,
    required this.value,
    required this.color,
    required this.icon,
  });

  @override
  Widget build(BuildContext context) => Expanded(
    child: Container(
      padding: const EdgeInsets.symmetric(vertical: 12, horizontal: 8),
      decoration: BoxDecoration(
        color: color.withOpacity(0.08),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color.withOpacity(0.2)),
      ),
      child: Column(
        children: [
          Icon(icon, color: color, size: 18),
          const SizedBox(height: 4),
          Text(value,
              style: TextStyle(
                  color: color,
                  fontSize: 18,
                  fontWeight: FontWeight.w800)),
          Text(label,
              style: const TextStyle(
                  color: AppTheme.textMuted, fontSize: 10)),
        ],
      ),
    ),
  );
}

// ── History list tile ──────────────────────────────────────────────────────────

class _HistoryTile extends StatelessWidget {
  final ScanHistoryItem item;

  const _HistoryTile({required this.item});

  @override
  Widget build(BuildContext context) {
    final verdict = item.verdict;
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: verdict.color.withOpacity(0.2)),
      ),
      child: Row(
        children: [
          // Verdict icon
          Container(
            width: 36,
            height: 36,
            decoration: BoxDecoration(
              color: verdict.bgColor,
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: verdict.color.withOpacity(0.3)),
            ),
            child: Center(
              child: Text(verdict.emoji,
                  style: const TextStyle(fontSize: 18)),
            ),
          ),
          const SizedBox(width: 12),

          // URL + meta
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  item.hostDisplay,
                  style: const TextStyle(
                      color: AppTheme.textPrimary,
                      fontSize: 13,
                      fontWeight: FontWeight.w600),
                  overflow: TextOverflow.ellipsis,
                ),
                const SizedBox(height: 2),
                Row(
                  children: [
                    Text(
                      verdict.label,
                      style: TextStyle(
                          color: verdict.color,
                          fontSize: 11,
                          fontWeight: FontWeight.w600),
                    ),
                    const Text(' · ',
                        style: TextStyle(
                            color: AppTheme.textMuted, fontSize: 11)),
                    Text(
                      _timeAgo(item.scannedAt),
                      style: const TextStyle(
                          color: AppTheme.textMuted, fontSize: 11),
                    ),
                    if (item.pathType == ScanPathType.deep) ...[
                      const Text(' · ',
                          style: TextStyle(
                              color: AppTheme.textMuted, fontSize: 11)),
                      const Text('Deep',
                          style: TextStyle(
                              color: AppTheme.warnAmber,
                              fontSize: 11,
                              fontWeight: FontWeight.w600)),
                    ],
                  ],
                ),
                if (item.bitbDetected || item.homoglyphDetected) ...[
                  const SizedBox(height: 4),
                  Wrap(
                    spacing: 4,
                    children: [
                      if (item.bitbDetected)
                        _MiniChip(label: 'BiTB', color: AppTheme.dangerRed),
                      if (item.homoglyphDetected)
                        _MiniChip(
                            label: 'Homoglyph',
                            color: AppTheme.warnAmber),
                    ],
                  ),
                ],
              ],
            ),
          ),

          // ML score
          if (item.mlProbability > 0)
            Column(
              crossAxisAlignment: CrossAxisAlignment.end,
              children: [
                Text(
                  '${(item.mlProbability * 100).toStringAsFixed(0)}%',
                  style: const TextStyle(
                      color: AppTheme.accentPurple,
                      fontSize: 13,
                      fontWeight: FontWeight.w700,
                      fontFamily: 'monospace'),
                ),
                const Text('ML',
                    style: TextStyle(
                        color: AppTheme.textMuted, fontSize: 10)),
              ],
            ),
        ],
      ),
    );
  }

  String _timeAgo(DateTime dt) {
    final diff = DateTime.now().difference(dt);
    if (diff.inSeconds < 60) return 'just now';
    if (diff.inMinutes < 60) return '${diff.inMinutes}m ago';
    if (diff.inHours < 24)   return '${diff.inHours}h ago';
    return '${diff.inDays}d ago';
  }
}

class _MiniChip extends StatelessWidget {
  final String label;
  final Color color;

  const _MiniChip({required this.label, required this.color});

  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 1),
    decoration: BoxDecoration(
      color: color.withOpacity(0.1),
      borderRadius: BorderRadius.circular(4),
      border: Border.all(color: color.withOpacity(0.3)),
    ),
    child: Text(label,
        style: TextStyle(color: color, fontSize: 9, fontWeight: FontWeight.w700)),
  );
}
