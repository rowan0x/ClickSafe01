// lib/services/fast_path_analyzer.dart
//
// ON-DEVICE Fast Path — mirrors Python rule_engine.py EXACTLY.
// Provides instant lexical feedback before the backend responds.
//
// ┌─────────────────────────────────────────────────────────────────────────┐
// │  THRESHOLDS (AppConfig — intentionally more aggressive than backend):   │
// │    fastPathPhishingScore  = 6   (backend uses 8 — on-device has no ML) │
// │    fastPathSuspiciousScore = 2  (backend uses 4)                        │
// │    URL length: medium ≥ 54 chars, high ≥ 75 chars                       │
// │    Subdomain:  > 3 dot-separated labels                                 │
// │    Risk score: high=3 pts, medium=1 pt                                  │
// │                                                                          │
// │  RULES MIRRORED FROM rule_engine.py (13 rules total):                  │
// │    0. Punycode / homograph prefix                                        │
// │    1. IP address as host                                                 │
// │    2. URL length (with safe-long suppression)                            │
// │    3. Excessive subdomains                                               │
// │    4. @ symbol                                                           │
// │    5. Double slash in path                                               │
// │    6. Multiple hyphens                                                   │
// │    7. No HTTPS                                                           │
// │    8. Suspicious TLD                                                     │
// │    9. URL shortener                                                      │
// │   10. Excessive percent-encoding                                         │
// │   NEW A. Brand name in path (impersonation)                              │
// │   NEW B. Multiple phishing keywords                                      │
// │   NEW C. Free hosting subdomain                                          │
// │                                                                          │
// │  ADDITIONAL CLIENT-SIDE CHECKS (not in rule_engine.py):                │
// │    • Homoglyph character detection (basic Unicode normalisation)         │
// │    • Link masking (visible text vs. href)                                │
// └─────────────────────────────────────────────────────────────────────────┘

import '../config/app_config.dart';
import '../models/scan_result.dart';

class FastPathTriggeredRule {
  final String name;
  final String description;
  final String severity; // 'high' | 'medium'
  final int points;

  const FastPathTriggeredRule({
    required this.name,
    required this.description,
    required this.severity,
    required this.points,
  });
}

class FastPathResult {
  final String url;
  final ScanVerdict verdict;
  final int riskScore;
  final List<FastPathTriggeredRule> triggeredRules;
  final bool shouldTriggerDeepPath;
  final Duration analysisTime;

  const FastPathResult({
    required this.url,
    required this.verdict,
    required this.riskScore,
    required this.triggeredRules,
    required this.shouldTriggerDeepPath,
    required this.analysisTime,
  });
}

class FastPathAnalyzer {
  // ── Constants (mirrors rule_engine.py) ────────────────────────────────────
  static const int _lengthMediumThreshold = 54;
  static const int _lengthHighThreshold   = 75;
  static const int _subdomainThreshold    = 3;

  static const Set<String> _suspiciousTlds = {
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz',
    '.top', '.click', '.link', '.win', '.download',
  };

  static const Set<String> _shortenerDomains = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co',
    'is.gd', 'buff.ly', 'adf.ly', 'shorte.st',
  };

  // NEW RULE A — brand names checked against the URL path.
  static const Set<String> _brands = {
    'paypal', 'amazon', 'apple', 'microsoft', 'google',
    'facebook', 'instagram', 'netflix', 'dropbox', 'linkedin',
    'twitter', 'chase', 'wellsfargo', 'bankofamerica', 'citibank',
    'ebay', 'spotify', 'adobe', 'yahoo', 'github',
  };

  // NEW RULE B — phishing-associated keywords; 2+ required to fire.
  static const Set<String> _phishingKeywords = {
    'verify', 'confirm', 'update', 'secure', 'login',
    'signin', 'account', 'banking', 'password', 'credential',
    'suspend', 'limited', 'urgent', 'alert', 'validate',
    'authenticate', 'recover', 'unlock', 'unusual',
  };

  // NEW RULE C — free hosting providers; subdomain form triggers, root does not.
  static const Set<String> _freeHosting = {
    'weebly.com', 'wix.com', 'web.app', 'firebaseapp.com',
    'ngrok.io', 'netlify.app', 'vercel.app', 'glitch.me',
    'pages.dev', 'github.io', 'repl.co', '000webhostapp.com',
    'myfreesites.net', 'hostfree.pw', 'byet.host',
  };

  // FALSE POSITIVE REDUCTION — reputable sites that produce long URLs.
  // Matches amazon product pages, YouTube, Google Maps, LinkedIn, GitHub, Twitter/X.
  static final RegExp _safeLongPattern = RegExp(
    r'(amazon\.[a-z]{2,6}/(dp|gp|s|product)/|'
    r'ebay\.[a-z]{2,6}/itm/|'
    r'google\.[a-z]{2,6}/maps|'
    r'youtube\.com/watch\?|'
    r'linkedin\.com/(in|posts)/|'
    r'github\.com/[^/]+/[^/]+|'
    r'twitter\.com/[^/]+/status/|'
    r'x\.com/[^/]+/status/)',
    caseSensitive: false,
  );

  // Homoglyph → ASCII map (Cyrillic + Greek subset)
  static const Map<String, String> _homoglyphMap = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'r', 'с': 'c',
    'у': 'u', 'х': 'x', 'і': 'i', 'ϳ': 'j',
    'ο': 'o', 'ρ': 'p', 'α': 'a', 'ε': 'e', 'ι': 'i',
  };

  // ── Public API ─────────────────────────────────────────────────────────────

  FastPathResult analyze(String rawUrl, {String visibleText = ''}) {
    final stopwatch = Stopwatch()..start();

    String url = rawUrl.trim();
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'http://$url';
    }

    final triggered = <FastPathTriggeredRule>[];

    Uri? parsed;
    try {
      parsed = Uri.parse(url);
    } catch (_) {
      stopwatch.stop();
      return FastPathResult(
        url:                   url,
        verdict:               ScanVerdict.unknown,
        riskScore:             0,
        triggeredRules:        [],
        shouldTriggerDeepPath: false,
        analysisTime:          stopwatch.elapsed,
      );
    }

    final netloc   = parsed.host.toLowerCase();
    final path     = parsed.path.toLowerCase();
    final scheme   = parsed.scheme;
    final fullUrl  = url.toLowerCase();

    final hostname  = netloc.contains(':') ? netloc.split(':').first : netloc;
    final cleanHost = hostname.startsWith('www.') ? hostname.substring(4) : hostname;

    // ── Rule 0: Punycode / Homograph prefix ──────────────────────────────────
    if (cleanHost.startsWith('xn--')) {
      triggered.add(FastPathTriggeredRule(
        name: 'Punycode (Homograph Attack) Detected',
        description: "Domain '$hostname' uses Punycode (xn-- prefix). "
            'International characters mimic trusted brands visually.',
        severity: 'high',
        points: 5, // matches Python scoring (5 pts for punycode)
      ));
    }

    // ── Rule 1: IP address as host ────────────────────────────────────────────
    if (_isIpHost(hostname)) {
      triggered.add(FastPathTriggeredRule(
        name: 'IP Address as Host',
        description: 'URL uses a raw IP instead of a domain name. '
            'Legitimate services almost always use registered domain names.',
        severity: 'high',
        points: 3,
      ));
    }

    // ── Rule 2: URL length (with safe-long suppression) ───────────────────────
    final isSafeLong = _safeLongPattern.hasMatch(url);
    if (url.length > _lengthHighThreshold && !isSafeLong) {
      triggered.add(FastPathTriggeredRule(
        name: 'Excessively Long URL',
        description: 'URL length is ${url.length} characters '
            '(threshold: $_lengthHighThreshold). Long URLs hide the real '
            'malicious domain.',
        severity: 'high',
        points: 3,
      ));
    } else if (url.length > _lengthMediumThreshold && !isSafeLong) {
      triggered.add(FastPathTriggeredRule(
        name: 'Unusually Long URL',
        description: 'URL length is ${url.length} characters '
            '(threshold: $_lengthMediumThreshold). Slightly above normal.',
        severity: 'medium',
        points: 1,
      ));
    }

    // ── Rule 3: Excessive subdomains ──────────────────────────────────────────
    final parts = cleanHost.split('.');
    if (parts.length > _subdomainThreshold) {
      triggered.add(FastPathTriggeredRule(
        name: 'Excessive Subdomains',
        description: 'Hostname has ${parts.length} labels ($cleanHost). '
            'Deep nesting embeds trusted brand names while hiding the real domain.',
        severity: 'high',
        points: 3,
      ));
    }

    // ── Rule 4: @ symbol ──────────────────────────────────────────────────────
    if (url.contains('@')) {
      triggered.add(const FastPathTriggeredRule(
        name: '@ Symbol in URL',
        description: 'Browsers discard everything BEFORE "@", so '
            '"http://trusted.com@evil.com" silently takes you to evil.com.',
        severity: 'high',
        points: 3,
      ));
    }

    // ── Rule 5: Double slash in path ──────────────────────────────────────────
    final afterScheme = url.contains('://') ? url.split('://').last : url;
    if (afterScheme.contains('//')) {
      triggered.add(const FastPathTriggeredRule(
        name: 'Double Slash Redirection',
        description: 'URL contains "//" outside "://". '
            'Tricks parsers into treating the next segment as a new host.',
        severity: 'high',
        points: 3,
      ));
    }

    // ── Rule 6: Multiple hyphens in hostname ──────────────────────────────────
    if (RegExp(r'-{2,}').hasMatch(hostname)) {
      triggered.add(FastPathTriggeredRule(
        name: 'Multiple Hyphens in Domain',
        description: 'Domain "$hostname" contains consecutive hyphens. '
            'Phishing domains use hyphens to mimic legitimate brands.',
        severity: 'medium',
        points: 1,
      ));
    }

    // ── Rule 7: HTTP (no TLS) ─────────────────────────────────────────────────
    if (scheme == 'http') {
      triggered.add(const FastPathTriggeredRule(
        name: 'No HTTPS (Unencrypted)',
        description: 'Uses plain HTTP instead of HTTPS. Combined with other '
            'signals, absence of TLS increases risk.',
        severity: 'medium',
        points: 1,
      ));
    }

    // ── Rule 8: Suspicious TLD ────────────────────────────────────────────────
    for (final tld in _suspiciousTlds) {
      if (hostname.endsWith(tld)) {
        triggered.add(FastPathTriggeredRule(
          name: 'Suspicious Top-Level Domain',
          description: 'Domain ends with "$tld", a TLD disproportionately '
              'used in phishing campaigns due to low/free registration cost.',
          severity: 'high',
          points: 3,
        ));
        break;
      }
    }

    // ── Rule 9: URL shortener ─────────────────────────────────────────────────
    for (final shortener in _shortenerDomains) {
      if (cleanHost == shortener || cleanHost.endsWith('.$shortener')) {
        triggered.add(FastPathTriggeredRule(
          name: 'URL Shortener Detected',
          description: 'Uses "$shortener". Shortened URLs mask the true destination.',
          severity: 'medium',
          points: 1,
        ));
        break;
      }
    }

    // ── Rule 10: Excessive percent-encoding ───────────────────────────────────
    final percentMatches = RegExp(r'%[0-9a-fA-F]{2}').allMatches(url).length;
    if (percentMatches >= 3) {
      triggered.add(FastPathTriggeredRule(
        name: 'Excessive Percent-Encoding',
        description: 'Found $percentMatches percent-encoded characters. '
            'High count indicates deliberate obfuscation.',
        severity: 'medium',
        points: 1,
      ));
    }

    // ── NEW RULE A: Brand Name in Path (Impersonation) ────────────────────────
    // Fires when a known brand is in the path but NOT in the hostname.
    // paypal.com/login → no fire. evil.com/paypal/login → fires.
    for (final brand in _brands) {
      if (path.contains(brand) && !cleanHost.contains(brand)) {
        triggered.add(FastPathTriggeredRule(
          name: 'Brand Name in Path (Impersonation)',
          description: "Brand '$brand' appears in the URL path but not in the "
              'domain. Classic technique to make phishing pages look legitimate.',
          severity: 'high',
          points: 3,
        ));
        break;
      }
    }

    // ── NEW RULE B: Multiple Phishing Keywords ────────────────────────────────
    // Requires 2+ hits to avoid false positives on legitimate security sites.
    final kwHits = _phishingKeywords.where((k) => fullUrl.contains(k)).toList();
    if (kwHits.length >= 2) {
      triggered.add(FastPathTriggeredRule(
        name: 'Multiple Phishing Keywords',
        description: 'URL contains ${kwHits.length} phishing-associated terms: '
            '${kwHits.take(5).join(', ')}. '
            'Legitimate sites rarely combine this many credential-related words.',
        severity: 'medium',
        points: 1,
      ));
    }

    // ── NEW RULE C: Free Hosting Subdomain ────────────────────────────────────
    // cleanHost strips www. so weebly.com and www.weebly.com are safe;
    // only attacker.weebly.com (endsWith '.weebly.com') fires.
    for (final freeHost in _freeHosting) {
      if (cleanHost.endsWith('.$freeHost')) {
        triggered.add(FastPathTriggeredRule(
          name: 'Phishing on Free Hosting Platform',
          description: "This URL is hosted as a subdomain on '$freeHost', "
              'a free platform commonly abused to host phishing pages '
              'with no domain registration or identity verification.',
          severity: 'high',
          points: 3,
        ));
        break;
      }
    }

    // ── Additional client-side: Homoglyph detection ───────────────────────────
    final homoglyphNormalised = _normaliseHomoglyphs(hostname);
    if (homoglyphNormalised != hostname) {
      triggered.add(FastPathTriggeredRule(
        name: 'Possible Homoglyph Characters',
        description: 'Domain "$hostname" contains Unicode look-alike characters. '
            'Normalised: "$homoglyphNormalised". May be impersonating a known brand.',
        severity: 'high',
        points: 3,
      ));
    }

    // ── Additional client-side: Link masking ──────────────────────────────────
    if (visibleText.isNotEmpty) {
      final masking = _checkLinkMasking(url, hostname, visibleText);
      if (masking != null) triggered.add(masking);
    }

    // ── Compute risk score ─────────────────────────────────────────────────────
    final riskScore = triggered.fold<int>(0, (sum, r) => sum + r.points);

    // ── Assign verdict ─────────────────────────────────────────────────────────
    ScanVerdict verdict;
    if (riskScore >= AppConfig.fastPathPhishingScore) {
      verdict = ScanVerdict.likelyPhishing;
    } else if (riskScore >= AppConfig.fastPathSuspiciousScore) {
      verdict = ScanVerdict.suspicious;
    } else {
      verdict = ScanVerdict.safe;
    }

    stopwatch.stop();

    return FastPathResult(
      url:                   url,
      verdict:               verdict,
      riskScore:             riskScore,
      triggeredRules:        triggered,
      shouldTriggerDeepPath: verdict == ScanVerdict.suspicious ||
                             verdict == ScanVerdict.likelyPhishing,
      analysisTime:          stopwatch.elapsed,
    );
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  static bool _isIpHost(String host) {
    final parts = host.split('.');
    if (parts.length != 4) return false;
    return parts.every((p) {
      final n = int.tryParse(p);
      return n != null && n >= 0 && n <= 255;
    });
  }

  static String _normaliseHomoglyphs(String text) =>
      text.split('').map((ch) => _homoglyphMap[ch] ?? ch).join();

  static FastPathTriggeredRule? _checkLinkMasking(
    String url,
    String actualHost,
    String visibleText,
  ) {
    final domainPattern = RegExp(
      r'([a-z0-9\-]+\.[a-z]{2,})',
      caseSensitive: false,
    );
    final matches = domainPattern.allMatches(visibleText.toLowerCase());

    for (final m in matches) {
      final visibleDomain =
          (m.group(1) ?? '').replaceFirst(RegExp(r'^www\.'), '');
      final actualClean = actualHost.replaceFirst(RegExp(r'^www\.'), '');

      if (visibleDomain.isNotEmpty &&
          !visibleDomain.contains(actualClean) &&
          !actualClean.contains(visibleDomain)) {
        return FastPathTriggeredRule(
          name: 'Link Masking Detected',
          description: 'Hyperlink shows "$visibleDomain" but points to '
              '"$actualHost". Classic phishing technique to hide the real destination.',
          severity: 'high',
          points: 3,
        );
      }
    }
    return null;
  }
}
