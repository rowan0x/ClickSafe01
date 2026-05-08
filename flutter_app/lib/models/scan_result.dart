// lib/models/scan_result.dart
//
// Data model that mirrors the JSON response from the Flask /analyze endpoint.
// Every field name matches the Python dict keys exactly.

import 'package:flutter/material.dart';

// ── Enums ─────────────────────────────────────────────────────────────────────

enum ScanVerdict { safe, suspicious, likelyPhishing, unknown }

enum ScanPathType { fast, deep }

// ── Helper extensions ──────────────────────────────────────────────────────────

extension ScanVerdictExt on ScanVerdict {
  String get label {
    switch (this) {
      case ScanVerdict.safe:           return 'Safe';
      case ScanVerdict.suspicious:     return 'Suspicious';
      case ScanVerdict.likelyPhishing: return 'Likely Phishing';
      case ScanVerdict.unknown:        return 'Unknown';
    }
  }

  String get emoji {
    switch (this) {
      case ScanVerdict.safe:           return '✅';
      case ScanVerdict.suspicious:     return '⚠️';
      case ScanVerdict.likelyPhishing: return '🚨';
      case ScanVerdict.unknown:        return '❓';
    }
  }

  Color get color {
    switch (this) {
      case ScanVerdict.safe:           return const Color(0xFF22C55E); // green-500
      case ScanVerdict.suspicious:     return const Color(0xFFF59E0B); // amber-500
      case ScanVerdict.likelyPhishing: return const Color(0xFFEF4444); // red-500
      case ScanVerdict.unknown:        return const Color(0xFF6B7280); // gray-500
    }
  }

  Color get bgColor {
    switch (this) {
      case ScanVerdict.safe:           return const Color(0xFF052E16);
      case ScanVerdict.suspicious:     return const Color(0xFF451A03);
      case ScanVerdict.likelyPhishing: return const Color(0xFF450A0A);
      case ScanVerdict.unknown:        return const Color(0xFF111827);
    }
  }

  static ScanVerdict fromString(String? s) {
    switch (s) {
      case 'safe':            return ScanVerdict.safe;
      case 'suspicious':      return ScanVerdict.suspicious;
      case 'likely_phishing': return ScanVerdict.likelyPhishing;
      default:                return ScanVerdict.unknown;
    }
  }
}

// ── Sub-models ────────────────────────────────────────────────────────────────

class MlResult {
  final String label;
  final double probability;

  const MlResult({required this.label, required this.probability});

  factory MlResult.fromJson(Map<String, dynamic> j) => MlResult(
    label:       j['label'] as String? ?? 'unknown',
    probability: (j['probability'] as num?)?.toDouble() ?? 0.0,
  );

  double get probabilityPct => probability * 100;
}

class TriggeredRule {
  final String name;
  final String description;
  final String severity; // 'high' | 'medium'

  const TriggeredRule({
    required this.name,
    required this.description,
    required this.severity,
  });

  factory TriggeredRule.fromJson(Map<String, dynamic> j) => TriggeredRule(
    name:        j['name'] as String? ?? '',
    description: j['description'] as String? ?? '',
    severity:    j['severity'] as String? ?? 'medium',
  );

  Color get severityColor =>
      severity == 'high' ? const Color(0xFFEF4444) : const Color(0xFFF59E0B);

  IconData get severityIcon =>
      severity == 'high' ? Icons.dangerous_rounded : Icons.warning_amber_rounded;
}

class WhitelistResult {
  final bool whitelisted;
  final String domain;
  final String rank;
  final String source;

  const WhitelistResult({
    required this.whitelisted,
    required this.domain,
    required this.rank,
    required this.source,
  });

  factory WhitelistResult.fromJson(Map<String, dynamic> j) => WhitelistResult(
    whitelisted: j['whitelisted'] as bool? ?? false,
    domain:      j['domain'] as String? ?? '',
    rank:        j['rank'] as String? ?? 'unranked',
    source:      j['source'] as String? ?? '',
  );
}

class HomoglyphResult {
  final bool isSuspicious;
  final String technique;
  final String matchedBrand;
  final String normalised;
  final int levenshteinDistance;
  final String detail;

  const HomoglyphResult({
    required this.isSuspicious,
    required this.technique,
    required this.matchedBrand,
    required this.normalised,
    required this.levenshteinDistance,
    required this.detail,
  });

  factory HomoglyphResult.fromJson(Map<String, dynamic> j) => HomoglyphResult(
    isSuspicious:        j['is_suspicious'] as bool? ?? false,
    technique:           j['technique'] as String? ?? 'none',
    matchedBrand:        j['matched_brand'] as String? ?? '',
    normalised:          j['normalised'] as String? ?? '',
    levenshteinDistance: j['levenshtein_distance'] as int? ?? -1,
    detail:              j['detail'] as String? ?? '',
  );
}

class LinkMaskingResult {
  final bool checked;
  final bool isMasked;
  final String visibleDomain;
  final String actualDomain;
  final String detail;

  const LinkMaskingResult({
    required this.checked,
    required this.isMasked,
    required this.visibleDomain,
    required this.actualDomain,
    required this.detail,
  });

  factory LinkMaskingResult.fromJson(Map<String, dynamic> j) => LinkMaskingResult(
    checked:       j['checked'] as bool? ?? false,
    isMasked:      j['is_masked'] as bool? ?? false,
    visibleDomain: j['visible_domain'] as String? ?? '',
    actualDomain:  j['actual_domain'] as String? ?? '',
    detail:        j['detail'] as String? ?? '',
  );
}

class FeatureContribution {
  final String feature;
  final dynamic value;
  final double normalised;
  final double importance;
  final double contribution;
  final String description;
  final String riskLevel; // 'high' | 'medium' | 'low'

  const FeatureContribution({
    required this.feature,
    required this.value,
    required this.normalised,
    required this.importance,
    required this.contribution,
    required this.description,
    required this.riskLevel,
  });

  factory FeatureContribution.fromJson(Map<String, dynamic> j) => FeatureContribution(
    feature:      j['feature'] as String? ?? '',
    value:        j['value'],
    normalised:   (j['normalised'] as num?)?.toDouble() ?? 0.0,
    importance:   (j['importance'] as num?)?.toDouble() ?? 0.0,
    contribution: (j['contribution'] as num?)?.toDouble() ?? 0.0,
    description:  j['description'] as String? ?? '',
    riskLevel:    j['risk_level'] as String? ?? 'low',
  );

  Color get riskColor {
    switch (riskLevel) {
      case 'high':   return const Color(0xFFEF4444);
      case 'medium': return const Color(0xFFF59E0B);
      default:       return const Color(0xFF22C55E);
    }
  }
}

class XaiResult {
  final String whySummary;
  final List<FeatureContribution> featureContributions;
  final double mlProbabilityPct;
  final List<String> topRiskFeatures;
  final int ruleCount;
  final int highSeverityRules;

  const XaiResult({
    required this.whySummary,
    required this.featureContributions,
    required this.mlProbabilityPct,
    required this.topRiskFeatures,
    required this.ruleCount,
    required this.highSeverityRules,
  });

  factory XaiResult.fromJson(Map<String, dynamic> j) => XaiResult(
    whySummary: j['why_summary'] as String? ?? '',
    featureContributions: ((j['feature_contributions'] as List?) ?? [])
        .map((e) => FeatureContribution.fromJson(e as Map<String, dynamic>))
        .toList(),
    mlProbabilityPct: (j['ml_probability_pct'] as num?)?.toDouble() ?? 0.0,
    topRiskFeatures: ((j['top_risk_features'] as List?) ?? [])
        .map((e) => e.toString())
        .toList(),
    ruleCount:        j['rule_count'] as int? ?? 0,
    highSeverityRules: j['high_severity_rules'] as int? ?? 0,
  );
}

// ── Main ScanResult ───────────────────────────────────────────────────────────

class ScanResult {
  final bool success;
  final String error;
  final String url;
  final ScanVerdict verdict;
  final String verdictLabel;
  final List<TriggeredRule> triggeredRules;
  final int ruleRiskScore;
  final MlResult? mlResult;
  final Map<String, dynamic>? features;
  final String explanation;
  final WhitelistResult? whitelist;
  final HomoglyphResult? homoglyph;
  final LinkMaskingResult? linkMasking;
  final XaiResult? xai;
  final double combinedScore;
  final ScanPathType pathType;
  final DateTime scannedAt;

  // Deep path extras (populated when pathType == ScanPathType.deep)
  final List<Map<String, dynamic>> redirectChain;
  final String finalUrl;
  final bool bitbDetected;
  final String bitbDetail;
  final bool newlyRegistered;
  final int? domainAgeDays;
  final bool hasLoginForm;
  final bool hasPasswordField;
  final String? screenshotB64;
  final List<String> deepFlags;

  const ScanResult({
    required this.success,
    required this.error,
    required this.url,
    required this.verdict,
    required this.verdictLabel,
    required this.triggeredRules,
    required this.ruleRiskScore,
    this.mlResult,
    this.features,
    required this.explanation,
    this.whitelist,
    this.homoglyph,
    this.linkMasking,
    this.xai,
    required this.combinedScore,
    required this.pathType,
    required this.scannedAt,
    this.redirectChain = const [],
    this.finalUrl = '',
    this.bitbDetected = false,
    this.bitbDetail = '',
    this.newlyRegistered = false,
    this.domainAgeDays,
    this.hasLoginForm = false,
    this.hasPasswordField = false,
    this.screenshotB64,
    this.deepFlags = const [],
  });

  // ── Factory: Fast Path (/analyze response) ───────────────────────────────
  factory ScanResult.fromFastPathJson(Map<String, dynamic> j) {
    final mlJson = j['ml_result'] as Map<String, dynamic>?;
    final whJson = j['whitelist'] as Map<String, dynamic>?;
    final hgJson = j['homoglyph'] as Map<String, dynamic>?;
    final lmJson = j['link_masking'] as Map<String, dynamic>?;
    final xiJson = j['xai'] as Map<String, dynamic>?;

    return ScanResult(
      success:        j['success'] as bool? ?? false,
      error:          j['error'] as String? ?? '',
      url:            j['url'] as String? ?? '',
      verdict:        ScanVerdictExt.fromString(j['verdict'] as String?),
      verdictLabel:   j['verdict_label'] as String? ?? '',
      triggeredRules: ((j['triggered_rules'] as List?) ?? [])
          .map((e) => TriggeredRule.fromJson(e as Map<String, dynamic>))
          .toList(),
      ruleRiskScore:  j['rule_risk_score'] as int? ?? 0,
      mlResult:       mlJson != null ? MlResult.fromJson(mlJson) : null,
      features:       j['features'] as Map<String, dynamic>?,
      explanation:    j['explanation'] as String? ?? '',
      whitelist:      whJson != null ? WhitelistResult.fromJson(whJson) : null,
      homoglyph:      hgJson != null ? HomoglyphResult.fromJson(hgJson) : null,
      linkMasking:    lmJson != null ? LinkMaskingResult.fromJson(lmJson) : null,
      xai:            xiJson != null ? XaiResult.fromJson(xiJson) : null,
      combinedScore:  (j['combined_score'] as num?)?.toDouble() ?? 0.0,
      pathType:       ScanPathType.fast,
      scannedAt:      DateTime.now(),
    );
  }

  // ── Factory: Deep Path (/deep-analyze response) ──────────────────────────
  factory ScanResult.fromDeepPathJson(Map<String, dynamic> j) {
    final fastJson = j['fast_path'] as Map<String, dynamic>? ?? {};
    final deepJson = j['deep_path'] as Map<String, dynamic>? ?? {};
    final fast     = ScanResult.fromFastPathJson(fastJson);

    final deepFlagsRaw = deepJson['deep_flags'] as List? ?? [];
    final deepFlags    = deepFlagsRaw
        .map((e) => (e as Map<String, dynamic>)['flag']?.toString() ?? '')
        .where((s) => s.isNotEmpty)
        .toList();

    return ScanResult(
      success:          j['success'] as bool? ?? false,
      error:            '',
      url:              fast.url,
      verdict:          ScanVerdictExt.fromString(j['final_verdict'] as String?),
      verdictLabel:     j['final_verdict_label'] as String? ?? '',
      triggeredRules:   fast.triggeredRules,
      ruleRiskScore:    fast.ruleRiskScore,
      mlResult:         fast.mlResult,
      features:         fast.features,
      explanation:      fast.explanation,
      whitelist:        fast.whitelist,
      homoglyph:        fast.homoglyph,
      linkMasking:      fast.linkMasking,
      xai:              fast.xai,
      combinedScore:    fast.combinedScore,
      pathType:         ScanPathType.deep,
      scannedAt:        DateTime.now(),
      // Deep path fields
      redirectChain:    (deepJson['redirect_chain'] as List? ?? [])
          .map((e) => e as Map<String, dynamic>)
          .toList(),
      finalUrl:         deepJson['final_url'] as String? ?? fast.url,
      bitbDetected:     deepJson['bitb_detected'] as bool? ?? false,
      bitbDetail:       deepJson['bitb_detail'] as String? ?? '',
      newlyRegistered:  deepJson['newly_registered'] as bool? ?? false,
      domainAgeDays:    deepJson['domain_age_days'] as int?,
      hasLoginForm:     deepJson['has_login_form'] as bool? ?? false,
      hasPasswordField: deepJson['has_password_field'] as bool? ?? false,
      screenshotB64:    deepJson['screenshot_b64'] as String?,
      deepFlags:        deepFlags,
    );
  }

  /// Returns true if this result warrants triggering the Deep Path analysis.
  bool get shouldTriggerDeepPath =>
      verdict == ScanVerdict.suspicious ||
      verdict == ScanVerdict.likelyPhishing;

  /// Short summary for history list items.
  String get shortSummary {
    final host = Uri.tryParse(url)?.host ?? url;
    return '$host — ${verdict.label}';
  }
}
