// lib/services/settings_service.dart
//
// Persistent user-configurable settings stored in SharedPreferences.
// Provides the backend URL and Intel API key used by ApiService at runtime.
//
// KEY DESIGN DECISIONS:
//   • AppConfig.defaultBaseUrl / defaultIntelApiKey are the compile-time fallbacks.
//   • SettingsService reads the user's overrides (if any) at call time — no caching —
//     so a URL change takes effect immediately on the next API call.
//   • All public methods are async because SharedPreferences.getInstance() is async.

import 'package:shared_preferences/shared_preferences.dart';
import '../config/app_config.dart';

class SettingsService {
  SettingsService._();
  static final SettingsService instance = SettingsService._();

  // ── SharedPreferences keys ─────────────────────────────────────────────────
  static const _kBaseUrl  = 'setting_base_url';
  static const _kIntelKey = 'setting_intel_api_key';

  // ── Getters ────────────────────────────────────────────────────────────────

  /// Returns the user-configured backend URL, or the compile-time default.
  Future<String> getBaseUrl() async {
    final prefs = await SharedPreferences.getInstance();
    final stored = prefs.getString(_kBaseUrl) ?? '';
    return stored.isEmpty ? AppConfig.defaultBaseUrl : stored;
  }

  /// Returns the user-configured Intel API key, or the compile-time default.
  Future<String> getApiKey() async {
    final prefs = await SharedPreferences.getInstance();
    final stored = prefs.getString(_kIntelKey) ?? '';
    return stored.isEmpty ? AppConfig.defaultIntelApiKey : stored;
  }

  // ── Setters ────────────────────────────────────────────────────────────────

  /// Persists [newUrl] as the backend base URL.
  /// Pass an empty string to revert to the compile-time default.
  Future<void> setBaseUrl(String newUrl) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_kBaseUrl, newUrl.trim());
  }

  /// Persists [newKey] as the Intel Loop API key.
  /// Pass an empty string to revert to the compile-time default.
  Future<void> setApiKey(String newKey) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_kIntelKey, newKey.trim());
  }

  // ── Reset ──────────────────────────────────────────────────────────────────

  /// Removes all user overrides; getters will return compile-time defaults.
  Future<void> resetToDefaults() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_kBaseUrl);
    await prefs.remove(_kIntelKey);
  }
}