// lib/models/scan_history_item.dart
//
// Lightweight model for persisting scan history to shared_preferences.
// We don't store the full ScanResult (too large), just the key fields.

import 'dart:convert';
import 'scan_result.dart';

class ScanHistoryItem {
  final String url;
  final ScanVerdict verdict;
  final double mlProbability;
  final int ruleScore;
  final ScanPathType pathType;
  final DateTime scannedAt;
  final bool whitelisted;
  final bool homoglyphDetected;
  final bool bitbDetected;

  const ScanHistoryItem({
    required this.url,
    required this.verdict,
    required this.mlProbability,
    required this.ruleScore,
    required this.pathType,
    required this.scannedAt,
    required this.whitelisted,
    required this.homoglyphDetected,
    required this.bitbDetected,
  });

  factory ScanHistoryItem.fromResult(ScanResult result) => ScanHistoryItem(
    url:               result.url,
    verdict:           result.verdict,
    mlProbability:     result.mlResult?.probability ?? 0.0,
    ruleScore:         result.ruleRiskScore,
    pathType:          result.pathType,
    scannedAt:         result.scannedAt,
    whitelisted:       result.whitelist?.whitelisted ?? false,
    homoglyphDetected: result.homoglyph?.isSuspicious ?? false,
    bitbDetected:      result.bitbDetected,
  );

  Map<String, dynamic> toJson() => {
    'url':               url,
    'verdict':           verdict.name,
    'mlProbability':     mlProbability,
    'ruleScore':         ruleScore,
    'pathType':          pathType.name,
    'scannedAt':         scannedAt.toIso8601String(),
    'whitelisted':       whitelisted,
    'homoglyphDetected': homoglyphDetected,
    'bitbDetected':      bitbDetected,
  };

  factory ScanHistoryItem.fromJson(Map<String, dynamic> j) => ScanHistoryItem(
    url:               j['url'] as String? ?? '',
    verdict:           ScanVerdict.values.firstWhere(
                         (v) => v.name == (j['verdict'] as String? ?? 'unknown'),
                         orElse: () => ScanVerdict.unknown,
                       ),
    mlProbability:     (j['mlProbability'] as num?)?.toDouble() ?? 0.0,
    ruleScore:         j['ruleScore'] as int? ?? 0,
    pathType:          ScanPathType.values.firstWhere(
                         (p) => p.name == (j['pathType'] as String? ?? 'fast'),
                         orElse: () => ScanPathType.fast,
                       ),
    scannedAt:         DateTime.tryParse(j['scannedAt'] as String? ?? '') ?? DateTime.now(),
    whitelisted:       j['whitelisted'] as bool? ?? false,
    homoglyphDetected: j['homoglyphDetected'] as bool? ?? false,
    bitbDetected:      j['bitbDetected'] as bool? ?? false,
  );

  String toJsonString() => jsonEncode(toJson());
  factory ScanHistoryItem.fromJsonString(String s) =>
      ScanHistoryItem.fromJson(jsonDecode(s) as Map<String, dynamic>);

  String get hostDisplay {
    final host = Uri.tryParse(url)?.host ?? url;
    return host.length > 40 ? '${host.substring(0, 38)}…' : host;
  }
}
