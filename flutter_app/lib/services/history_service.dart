// lib/services/history_service.dart

import 'package:shared_preferences/shared_preferences.dart';
import '../config/app_config.dart';
import '../models/scan_history_item.dart';
import '../models/scan_result.dart';

class HistoryService {
  HistoryService._();
  static final HistoryService instance = HistoryService._();

  static const String _key = 'scan_history_v1';

  // ── Save a new scan result ─────────────────────────────────────────────────

  Future<void> save(ScanResult result) async {
    final prefs = await SharedPreferences.getInstance();
    final existing = await load();
    final item = ScanHistoryItem.fromResult(result);

    // Prepend newest
    final updated = [item, ...existing];

    // Trim to max
    final trimmed = updated.take(AppConfig.maxHistoryItems).toList();

    await prefs.setStringList(
      _key,
      trimmed.map((i) => i.toJsonString()).toList(),
    );
  }

  // ── Load all history items ─────────────────────────────────────────────────

  Future<List<ScanHistoryItem>> load() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getStringList(_key) ?? [];
    final items = <ScanHistoryItem>[];
    for (final s in raw) {
      try {
        items.add(ScanHistoryItem.fromJsonString(s));
      } catch (_) {
        // Skip corrupt entries
      }
    }
    return items;
  }

  // ── Clear all history ──────────────────────────────────────────────────────

  Future<void> clear() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_key);
  }

  // ── Statistics ─────────────────────────────────────────────────────────────

  Future<Map<String, int>> getStats() async {
    final items = await load();
    return {
      'total':    items.length,
      'safe':     items.where((i) => i.verdict == ScanVerdict.safe).length,
      'suspicious': items.where((i) => i.verdict == ScanVerdict.suspicious).length,
      'phishing': items.where((i) => i.verdict == ScanVerdict.likelyPhishing).length,
    };
  }
}
