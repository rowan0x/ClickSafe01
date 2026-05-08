// lib/config/app_config.dart
//
// CHANGE LOG vs original:
//   • Removed `static const String baseUrl` (was hardcoded production URL).
//     Replaced with `defaultBaseUrl` — a compile-time fallback only.
//     The live URL is now stored/read via SettingsService (SharedPreferences).
//
//   • Removed `static const String intelApiKey` (was hardcoded secret).
//     Replaced with `defaultIntelApiKey` — a compile-time fallback only.
//     The live key is now stored/read via SettingsService (SharedPreferences).
//
//   • Endpoint constants (analyzeEndpoint, etc.) are now static methods that
//     accept a `base` URL parameter, because they can no longer be `const`
//     compile-time values once the base URL is dynamic.
//
//   • Thresholds, timeouts, and Fast Path scores are unchanged.

class AppConfig {
  AppConfig._();

  // ── Default Backend URL (compile-time fallback only) ───────────────────────
  // Used when the user has not configured a custom URL in Settings.
  // To override at runtime: Settings screen → save to SharedPreferences.
  static const String defaultBaseUrl = 'https://click-safe-api.onrender.com';

  // ── Default Intel API Key (compile-time fallback only) ────────────────────
  // IMPORTANT: In production, set a real secret via the Settings screen.
  // The key is sent in the X-Intel-Key header and must match the server's
  // INTEL_API_KEY environment variable.
  static const String defaultIntelApiKey = 'your-super-secret-key-from-render';

  // ── Runtime Endpoint Builders ──────────────────────────────────────────────
  // Call with the base URL from SettingsService.instance.getBaseUrl().
  // Example:
  //   final base = await SettingsService.instance.getBaseUrl();
  //   final uri  = Uri.parse(AppConfig.analyzeEndpoint(base));
  static String analyzeEndpoint(String base)           => '$base/analyze';
  static String deepAnalyzeEndpoint(String base)       => '$base/deep-analyze';
  static String healthEndpoint(String base)            => '$base/health';
  static String intelIngestEndpoint(String base)       => '$base/intel-loop/ingest';
  static String intelStatsEndpoint(String base)        => '$base/intel-loop/stats';
  static String featureImportanceEndpoint(String base) => '$base/feature-importances';

  // ── Detection Thresholds (mirrors Python backend — do NOT change) ─────────
  static const double mlPhishingThreshold    = 0.7;
  static const double mlSuspiciousThreshold  = 0.4;
  static const int    rulePhishingThreshold  = 8;
  static const int    ruleSuspiciousThreshold = 4;

  // ── Fast Path thresholds (on-device heuristics — intentionally lower) ──────
  // These are deliberately more aggressive than the backend thresholds because
  // the on-device Fast Path has no ML support.
  static const int fastPathPhishingScore   = 6;
  static const int fastPathSuspiciousScore = 2;

  // ── UI & Networking ────────────────────────────────────────────────────────
  static const int maxHistoryItems    = 100;
  // 60s to handle Render's free-tier cold start spin-up.
  static const int requestTimeoutSec  = 60;
  static const int deepPathTimeoutSec = 90;
}