// lib/services/api_service.dart
//
// HTTP client for the ClickSafe Flask backend.
//
// CHANGE LOG vs original:
//   • All methods now call SettingsService.instance.getBaseUrl() and
//     SettingsService.instance.getApiKey() at the START of each request.
//     This means a URL or key change in Settings takes effect immediately
//     without needing to restart the app.
//
//   • Removed all references to the old AppConfig.healthEndpoint,
//     AppConfig.analyzeEndpoint, etc. (which were const strings).
//     They are now replaced with AppConfig.healthEndpoint(base) method calls.
//
//   • FIX: dispose() is now correctly wired to the app lifecycle via main.dart.
//     The _client field remains a singleton to prevent connection churn.

import 'dart:async';
import 'dart:convert';
import 'package:http/http.dart' as http;
import '../config/app_config.dart';
import '../models/scan_result.dart';
import '../services/settings_service.dart';

class ApiException implements Exception {
  final String message;
  final int? statusCode;
  const ApiException(this.message, {this.statusCode});
  @override
  String toString() => 'ApiException($statusCode): $message';
}

class BackendHealth {
  final bool ok;
  final int trancodomains;
  final int intelSigs;
  final String? error;

  const BackendHealth({
    required this.ok,
    required this.trancodomains,
    required this.intelSigs,
    this.error,
  });
}

class ApiService {
  ApiService._();
  static final ApiService instance = ApiService._();

  // Single persistent client — prevents repeated TCP handshake overhead.
  // Closed via dispose() which is called from main.dart's WidgetsBindingObserver.
  final _client = http.Client();

  // ── Health check ──────────────────────────────────────────────────────────

  Future<BackendHealth> checkHealth() async {
    final base = await SettingsService.instance.getBaseUrl();
    try {
      final resp = await _client
          .get(Uri.parse(AppConfig.healthEndpoint(base)))
          .timeout(const Duration(seconds: 5));

      if (resp.statusCode == 200) {
        final j = jsonDecode(resp.body) as Map<String, dynamic>;
        return BackendHealth(
          ok:            j['status'] == 'ok',
          trancodomains: j['tranco_domains'] as int? ?? 0,
          intelSigs:     j['intel_sigs'] as int? ?? 0,
        );
      }
      return BackendHealth(
        ok: false, trancodomains: 0, intelSigs: 0,
        error: 'HTTP ${resp.statusCode}',
      );
    } catch (e) {
      return BackendHealth(
        ok: false, trancodomains: 0, intelSigs: 0,
        error: e.toString(),
      );
    }
  }

  // ── Fast Path: POST /analyze ───────────────────────────────────────────────

  Future<ScanResult> analyze(String url, {String visibleText = ''}) async {
    final base = await SettingsService.instance.getBaseUrl();
    final body = jsonEncode({
      'url':          url,
      'visible_text': visibleText,
    });

    http.Response resp;
    try {
      resp = await _client
          .post(
            Uri.parse(AppConfig.analyzeEndpoint(base)),
            headers: {'Content-Type': 'application/json'},
            body: body,
          )
          .timeout(Duration(seconds: AppConfig.requestTimeoutSec));
    } on TimeoutException {
      throw const ApiException('Request timed out. Is the backend running?');
    } catch (e) {
      throw ApiException('Network error: $e');
    }

    final j = _decodeJson(resp);
    if (resp.statusCode != 200) {
      throw ApiException(
        j['error'] as String? ?? 'Unknown error',
        statusCode: resp.statusCode,
      );
    }

    return ScanResult.fromFastPathJson(j);
  }

  // ── Deep Path: POST /deep-analyze ─────────────────────────────────────────

  Future<ScanResult> deepAnalyze(String url) async {
    final base = await SettingsService.instance.getBaseUrl();
    final body = jsonEncode({'url': url});

    http.Response resp;
    try {
      resp = await _client
          .post(
            Uri.parse(AppConfig.deepAnalyzeEndpoint(base)),
            headers: {'Content-Type': 'application/json'},
            body: body,
          )
          .timeout(Duration(seconds: AppConfig.deepPathTimeoutSec));
    } on TimeoutException {
      throw const ApiException(
        'Deep analysis timed out. The server may be busy.',
      );
    } catch (e) {
      throw ApiException('Network error: $e');
    }

    final j = _decodeJson(resp);
    if (resp.statusCode != 200) {
      throw ApiException(
        j['error'] as String? ?? 'Unknown error',
        statusCode: resp.statusCode,
      );
    }

    return ScanResult.fromDeepPathJson(j);
  }

  // ── XAI: GET /feature-importances ─────────────────────────────────────────

  Future<List<Map<String, dynamic>>> getFeatureImportances() async {
    final base = await SettingsService.instance.getBaseUrl();

    http.Response resp;
    try {
      resp = await _client
          .get(Uri.parse(AppConfig.featureImportanceEndpoint(base)))
          .timeout(const Duration(seconds: 10));
    } catch (e) {
      throw ApiException('Network error: $e');
    }
    final j = _decodeJson(resp);
    final list = j['importances'] as List? ?? [];
    return list.cast<Map<String, dynamic>>();
  }

  // ── Intel Loop: POST /intel-loop/ingest ───────────────────────────────────

  Future<Map<String, dynamic>> ingestPhishingUrls({
    required List<String> urls,
    int label = 1,
    String source = 'mobile_app',
  }) async {
    final base   = await SettingsService.instance.getBaseUrl();
    final apiKey = await SettingsService.instance.getApiKey();

    final body = jsonEncode({
      'urls':   urls,
      'label':  label,
      'source': source,
    });

    http.Response resp;
    try {
      resp = await _client
          .post(
            Uri.parse(AppConfig.intelIngestEndpoint(base)),
            headers: {
              'Content-Type': 'application/json',
              'X-Intel-Key':  apiKey,
            },
            body: body,
          )
          .timeout(Duration(seconds: AppConfig.requestTimeoutSec));
    } catch (e) {
      throw ApiException('Network error: $e');
    }

    return _decodeJson(resp);
  }

  // ── Private ────────────────────────────────────────────────────────────────

  Map<String, dynamic> _decodeJson(http.Response resp) {
    try {
      return jsonDecode(resp.body) as Map<String, dynamic>;
    } catch (_) {
      throw ApiException('Invalid JSON response from server.');
    }
  }

  /// Closes the underlying HTTP client. Call this when the app is shutting down.
  /// Hooked to WidgetsBindingObserver.didChangeAppLifecycleState in main.dart.
  void dispose() => _client.close();
}