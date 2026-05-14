# =============================================================================
# modules/analyzer.py  —  URLAnalyzer (Enhanced Hybrid Orchestrator)
# =============================================================================
# IMPROVEMENTS IN THIS VERSION:
#
#   BLOCKLIST INTEGRATION:
#     BlocklistChecker (Google Safe Browsing v4) is now called after the
#     Tranco whitelist check.  A confirmed blocklist hit short-circuits the
#     pipeline: verdict is set to 'likely_phishing' immediately, a high-
#     severity triggered rule is injected, and ML/heuristic scoring still
#     runs so the XAI breakdown is populated.
#
#   19-FEATURE SUPPORT:
#     _FEATURE_IMPORTANCE_APPROX, _FEATURE_DESCRIPTIONS, FEATURE_RANGES, and
#     get_feature_importances() all updated for the five new ML features:
#     has_suspicious_tld, hostname_digit_ratio, vowel_ratio,
#     has_non_standard_port, http_count_in_url.
#     Approximate importances reflect the actual values from the retrained model.
#
#   PREVIOUSLY FIXED (retained):
#   • BUG-01: _build_xai() returns high_severity_rules + top_risk_features.
#   • ML-01:  try/except FileNotFoundError around MLEngine(); heuristic-only
#             mode when model.pkl is absent.
#   • app.py model_loaded field now reads analyzer.ml_engine is not None.
#
#   ZERO TRUST + ZERO-DAY (new):
#   • Stage 3.5 — _zero_trust_validate(): enforces DNS resolution and
#     SSL/TLS certificate validity on every non-whitelisted, non-blocklisted
#     URL.  Uses only stdlib (ssl, socket) — no new dependencies.
#     ⚠ Adds up to ~5 s latency (TLS handshake timeout).  If you need the
#     Fast Path to remain sub-second, move this call into deep_analyzer.py
#     and remove it from here.
#   • Stage 6.5 — rule_engine.check_zero_day(): pure-heuristic scan for
#     newly minted phishing infrastructure (DGA hostnames, stacked
#     obfuscation, entropy anomalies).  Zero I/O — no latency impact.
#   • Both results are surfaced in the response dict as 'zero_trust' and
#     'zero_day', parsed by ZeroTrustCheck / ZeroDayCheck in scan_result.dart,
#     and rendered as _FlagChip badges in result_screen.dart.
# =============================================================================

import logging

from .validator          import URLValidator
from .rule_engine        import RuleEngine
from .ml_engine          import MLEngine
from .tranco_checker     import TrancoChecker
from .homoglyph_detector import HomoglyphDetector
from .blocklist_checker  import BlocklistChecker

logger = logging.getLogger(__name__)

# ── Feature importance fallback values (from retrained 19-feature model) ──────
# Used by get_feature_importances() when the live model is unavailable.
_FEATURE_IMPORTANCE_APPROX: dict[str, float] = {
    'path_length':          0.324062,
    'num_slashes':          0.313584,
    'num_special_chars':    0.132997,
    'url_entropy':          0.081047,
    'subdomain_count':      0.033798,
    'num_dots':             0.032261,
    'url_length':           0.027813,
    'hostname_length':      0.025456,
    'has_https':            0.012593,
    'num_hyphens':          0.009436,
    'vowel_ratio':          0.002556,
    'hostname_digit_ratio': 0.001920,
    'num_query_params':     0.001909,
    'num_underscores':      0.000528,
    'has_suspicious_tld':   0.000040,
    'has_ip_host':          0.0,
    'has_at_sign':          0.0,
    'has_non_standard_port': 0.0,
    'http_count_in_url':    0.0,
}

_FEATURE_DESCRIPTIONS: dict[str, str] = {
    'url_length':           'Total URL length — phishing URLs are typically much longer',
    'url_entropy':          'Character randomness — high entropy suggests generated/obfuscated URLs',
    'num_special_chars':    'Special characters (@, %, =, ?) — used to confuse URL parsers',
    'hostname_length':      'Hostname length — long hostnames often embed brand names as decoys',
    'path_length':          'Path depth — deep paths hide malicious payloads',
    'num_dots':             'Dot count — many dots indicate excessive subdomain nesting',
    'subdomain_count':      'Subdomain depth — e.g. "secure.login.paypal.evil.com"',
    'num_slashes':          'Slash count — extra slashes enable redirect tricks',
    'has_https':            'HTTPS presence — absence of TLS is a weak but real signal',
    'num_hyphens':          'Hyphen count — hyphens used in typosquatting (pay-pal.com)',
    'has_ip_host':          'IP as host — raw IP addresses avoid domain registration',
    'num_query_params':     'Query parameter count — many params suggest tracking/redirect',
    'has_at_sign':          '@ symbol — browsers ignore everything before @ in a URL',
    'num_underscores':      'Underscore count — underscores are uncommon in legitimate domains',
    'is_punycode':          'Punycode/Homograph prefix (xn--) — used for look-alike domain attacks',
    # New v2 features
    'has_suspicious_tld':   'Suspicious TLD (.tk, .ml, .xyz…) — free/abused registries',
    'hostname_digit_ratio': 'Digit fraction in hostname — machine-generated domains have high ratios',
    'vowel_ratio':          'Vowel fraction in hostname — gibberish domains deviate from natural language',
    'has_non_standard_port': 'Non-standard port — legitimate sites use 80/443; unusual ports are red flags',
    'http_count_in_url':    'Embedded HTTP in URL — proxy for URL-in-URL redirect chain tricks',
}

LABEL_MAP = {
    'safe':            '✅  Safe',
    'suspicious':      '⚠️  Suspicious',
    'likely_phishing': '🚨  Likely Phishing',
}

_NULL_ML_RESULT = {'label': 'safe', 'probability': 0.0}
_NULL_FEATURES  = {}


class URLAnalyzer:
    """
    Enhanced hybrid orchestrator: Tranco whitelist → Google Safe Browsing
    blocklist → Zero Trust validation → homoglyph detection → link masking
    → heuristic rules → Zero-Day check → ML.
    """

    def __init__(self):
        self.validator         = URLValidator()
        self.rule_engine       = RuleEngine()
        self.tranco            = TrancoChecker()
        self.homoglyph         = HomoglyphDetector()
        self.blocklist         = BlocklistChecker()
        self.SHORTENER_DOMAINS = {
            'tinyurl.com', 'bit.ly', 't.co', 'rb.gy', 'goo.gl', 'is.gd', 'ow.ly',
        }

        # Domains that are Tranco-whitelisted yet host arbitrary user content.
        # For these, the fast-path Tranco early-return is DISABLED so that path
        # heuristics, ML features, and the @ sign rule are always evaluated.
        # Suffix matching catches subdomains, e.g. <cid>.ipfs.dweb.link.
        self.SHARED_INFRASTRUCTURE = {
            # IPFS / Web3 gateways
            'ipfs.io', 'dweb.link', 'cloudflare-ipfs.com',
            'nftstorage.link', 'w3s.link',
            # Firebase / Google Cloud
            'firebaseapp.com', 'web.app',
            'storage.googleapis.com', 'appspot.com',
            # Cloudflare Workers / Pages
            'workers.dev', 'pages.dev',
            # Other serverless / notebook platforms
            'azurewebsites.net', 'blob.core.windows.net',
            'notion.site', 'sites.google.com',
        }

        # OAuth / SSO endpoints whose URLs are legitimately long and
        # percent-encoded (e.g. continue=https%3A%2F%2F...).
        # These get Tranco-like treatment: ML is bypassed entirely.
        self.TRUSTED_OAUTH_DOMAINS = {
            'accounts.google.com',
            'login.microsoftonline.com',
            'login.live.com',
            'appleid.apple.com',
            'auth.amazon.com',
        }

        # ML-01: graceful degradation when model.pkl is absent
        try:
            self.ml_engine = MLEngine()
            logger.info('MLEngine loaded — %d features.', self.ml_engine.model.n_features_in_)
        except (FileNotFoundError, ValueError) as exc:
            self.ml_engine = None
            logger.warning(
                'MLEngine unavailable — heuristic-only mode. (%s)', exc
            )

    # ── Private ML guards ──────────────────────────────────────────────────────

    def _extract_features(self, url: str) -> dict:
        if self.ml_engine is None:
            return _NULL_FEATURES
        return self.ml_engine.extract_features(url)

    def _predict(self, features: dict) -> dict:
        if self.ml_engine is None or not features:
            return _NULL_ML_RESULT
        return self.ml_engine.predict(features)

    # ── Public API ─────────────────────────────────────────────────────────────

    def analyze(self, raw_url: str, visible_text: str = '') -> dict:
        """Full pipeline: validate → whitelist → blocklist → Zero Trust →
        rules + Zero-Day → ML → verdict."""

        # ── Stage 1: Validate & Normalise ────────────────────────────────────
        validation = self.validator.validate(raw_url)
        if not validation['is_valid']:
            return {
                'success': False, 'error': validation['error'], 'url': raw_url,
                'verdict': None, 'verdict_label': None, 'triggered_rules': [],
                'rule_risk_score': 0, 'ml_result': None, 'features': None,
                'explanation': '', 'whitelist': None, 'homoglyph': None,
                'link_masking': None, 'xai': None, 'combined_score': 0,
                'blocklist': None,
                'zero_trust': None,
                'zero_day':   None,
            }

        url = validation['url']

        # ── Stage 2: Tranco Whitelist (Shortener + Shared-Infrastructure Bypass) ─
        whitelist_result = self.tranco.is_whitelisted(url)
        domain = whitelist_result.get('domain', '').lower()

        # Shared-infrastructure: domain is Tranco-trusted but hosts arbitrary
        # user content (IPFS gateways, Firebase, Cloudflare Workers, etc.).
        # Suffix match catches subdomain variants like <hash>.ipfs.dweb.link.
        is_shared = any(
            domain == si or domain.endswith('.' + si)
            for si in self.SHARED_INFRASTRUCTURE
        )

        if whitelist_result['whitelisted'] and domain not in self.SHORTENER_DOMAINS and not is_shared:
            return {
                'success':         True,
                'error':           '',
                'url':             url,
                'verdict':         'safe',
                'verdict_label':   LABEL_MAP['safe'],
                'triggered_rules': [],
                'rule_risk_score': 0,
                'ml_result':       {'label': 'safe', 'probability': 0.02},
                'features':        self._extract_features(url) or None,
                'explanation':     (
                    f"Domain '{whitelist_result['domain']}' is in the Tranco "
                    f"Top-100k list — a globally recognised, legitimate website."
                ),
                'whitelist':       whitelist_result,
                'homoglyph':       {'is_suspicious': False, 'technique': 'none', 'detail': ''},
                'link_masking':    self._check_link_masking(url, visible_text),
                'xai':             None,
                'combined_score':  0.2,
                'blocklist':       {'is_blocked': False, 'source': 'skipped_whitelist'},
                # Tranco-whitelisted domains are globally vetted —
                # Zero Trust pre-validation is implicitly satisfied.
                'zero_trust': {
                    'passed':       True,
                    'ssl_valid':    True,
                    'dns_resolved': True,
                    'checks': [{
                        'check':  'skipped_whitelist',
                        'passed': True,
                        'detail': (
                            'Domain is in the Tranco Top-100k list — '
                            'Zero Trust checks are pre-satisfied for globally '
                            'recognised, audited domains.'
                        ),
                    }],
                },
                'zero_day': {
                    'is_zero_day':    False,
                    'zero_day_score': 0,
                    'indicators':     [],
                },
            }

        # ── Stage 3: Real-Time Blocklist (Google Safe Browsing) ───────────────
        blocklist_result = self.blocklist.check(url)

        # ── Stage 3d: Trusted OAuth / SSO Fast-Return ────────────────────────
        # Runs AFTER the blocklist so a spoofed OAuth lookalike domain
        # (e.g. accounts.g00gle.com) is still caught above before reaching here.
        from urllib.parse import urlparse as _up
        _oauth_host  = _up(url).netloc.lower().split(':')[0]
        _oauth_clean = _oauth_host[4:] if _oauth_host.startswith('www.') else _oauth_host
        _is_trusted_oauth = any(
            _oauth_clean == d or _oauth_clean.endswith('.' + d)
            for d in self.TRUSTED_OAUTH_DOMAINS
        )
        if _is_trusted_oauth and not blocklist_result['is_blocked']:
            return {
                'success':         True,
                'error':           '',
                'url':             url,
                'verdict':         'safe',
                'verdict_label':   LABEL_MAP['safe'],
                'triggered_rules': [],
                'rule_risk_score': 0,
                'ml_result':       {'label': 'safe', 'probability': 0.01},
                'features':        self._extract_features(url) or None,
                'explanation': (
                    f"Domain '{_oauth_host}' is a trusted OAuth/SSO identity "
                    f"provider. Long redirect URLs with percent-encoded parameters "
                    f"are expected and safe on this endpoint."
                ),
                'whitelist':    {'whitelisted': True, 'domain': _oauth_host,
                                 'source': 'trusted_oauth'},
                'homoglyph':    {'is_suspicious': False, 'technique': 'none', 'detail': ''},
                'link_masking': self._check_link_masking(url, visible_text),
                'xai':          None,
                'combined_score': 0.1,
                'blocklist':    blocklist_result,
                'zero_trust': {
                    'passed':       True,
                    'ssl_valid':    True,
                    'dns_resolved': True,
                    'checks': [{'check': 'skipped_trusted_oauth', 'passed': True,
                                'detail': 'Domain is a trusted OAuth/SSO provider.'}],
                },
                'zero_day': {
                    'is_zero_day':    False,
                    'zero_day_score': 0,
                    'indicators':     [],
                },
            }

        # ── Stage 3.5: Zero Trust Validation (SSL/TLS + DNS) ─────────────────
        # Under the Zero Trust security paradigm every URL is untrusted until
        # it passes both a live DNS resolution check and an SSL/TLS certificate
        # verification.  Confirmed blocklist hits are already condemned — their
        # Zero Trust result is forced to failed to avoid unnecessary I/O.
        #
        # ⚠ LATENCY NOTE: _zero_trust_validate() makes two network calls
        # (DNS lookup + TLS handshake, max ~5 s each).  If you need the Fast
        # Path to remain sub-second, move this call to the Deep Path in
        # deep_analyzer.py and remove it here.
        if not blocklist_result['is_blocked']:
            zero_trust_result = self._zero_trust_validate(url)
        else:
            zero_trust_result = {
                'passed':       False,
                'ssl_valid':    False,
                'dns_resolved': False,
                'checks': [{
                    'check':  'skipped_blocklisted',
                    'passed': False,
                    'detail': (
                        'Zero Trust validation skipped — URL is confirmed '
                        'blocklisted by Google Safe Browsing.'
                    ),
                }],
            }

        # ── Stage 4: Feature Extraction ───────────────────────────────────────
        # Decode percent-encoded query params before ML feature extraction so
        # that `continue=https%3A%2F%2F...` does not inflate num_slashes,
        # num_special_chars, and url_entropy. Only the query string and fragment
        # are decoded — scheme, host, and path are left intact so all hostname
        # and structural features remain accurate.
        from urllib.parse import urlparse, unquote, urlunparse
        _parsed_for_ml = urlparse(url)
        _ml_url = urlunparse(_parsed_for_ml._replace(
            query=unquote(_parsed_for_ml.query),
            fragment=unquote(_parsed_for_ml.fragment or ''),
        ))
        features = self._extract_features(_ml_url)
        hostname  = _parsed_for_ml.netloc.lower().split(':')[0]

        # ── Stage 5: Homoglyph & Link Masking ─────────────────────────────────
        homoglyph_result    = self.homoglyph.check(hostname)
        link_masking_result = self._check_link_masking(url, visible_text)

        # ── Stage 6: Heuristic Rule Engine ────────────────────────────────────
        rule_result     = self.rule_engine.analyze(url)
        rule_score      = rule_result['risk_score']
        triggered_rules = rule_result['triggered_rules']

        if domain in self.SHORTENER_DOMAINS:
            triggered_rules.append({
                'name': 'URL Shortener (Analysis Required)',
                'description': 'Known URL shortener detected. Forcing deeper inspection.',
                'severity': 'medium',
            })
            rule_score += 2

        if homoglyph_result['is_suspicious']:
            triggered_rules.append({
                'name': 'Homoglyph / Typosquatting Attack',
                'description': homoglyph_result['detail'],
                'severity': 'high',
            })
            rule_score += 5

        if link_masking_result['is_masked']:
            triggered_rules.append({
                'name': 'Link Masking Detected',
                'description': link_masking_result['detail'],
                'severity': 'high',
            })
            rule_score += 3

        # ── Blocklist hit: inject rule + escalate score ────────────────────────
        if blocklist_result['is_blocked']:
            threat = blocklist_result.get('threat_type', 'UNKNOWN')
            triggered_rules.insert(0, {
                'name': 'Confirmed Threat (Google Safe Browsing)',
                'description': (
                    f"This URL is listed in Google Safe Browsing as a confirmed "
                    f"threat ({threat}). Do not open this link."
                ),
                'severity': 'high',
            })
            # Force score above phishing threshold regardless of rule engine
            rule_score = max(rule_score + 8, 8)

        # ── Stage 6.5: Zero-Day Threat Check ──────────────────────────────────
        # Pure heuristic scan — no I/O.  Detects newly minted phishing
        # infrastructure via DGA-like hostnames, stacked obfuscation, and
        # entropy anomalies that escape standard reputation-based filters.
        zero_day_result = self.rule_engine.check_zero_day(url)

        if zero_day_result['is_zero_day']:
            # Surface indicators as a triggered rule so they appear in the
            # XAI breakdown and the Flutter rule-cards section.
            indicator_summary = '; '.join(
                i['detail'] for i in zero_day_result['indicators'][:2]
            )
            triggered_rules.append({
                'name': 'Zero-Day Threat Indicators Detected',
                'description': (
                    f"{len(zero_day_result['indicators'])} zero-day signal(s): "
                    f"{indicator_summary}"
                ),
                'severity': 'high',
            })
            rule_score += zero_day_result['zero_day_score']

        # ── Stage 7: ML Prediction ────────────────────────────────────────────
        ml_result = self._predict(features)

        # ── Stage 8: Combined Verdict ─────────────────────────────────────────
        if blocklist_result['is_blocked']:
            verdict = 'likely_phishing'
        elif rule_score >= 8 or ml_result['probability'] >= 0.7:
            # If ONLY the ML is firing (zero rule hits, no blocklist, no zero-day),
            # downgrade to suspicious — prevents ML-only false positives on
            # legitimate sites with unusual but clean domain names.
            if rule_score == 0 and not blocklist_result['is_blocked']:
                verdict = 'suspicious'
            else:
                verdict = 'likely_phishing'
        elif rule_score >= 4 or ml_result['probability'] >= 0.4:
            verdict = 'suspicious'
        else:
            verdict = 'safe'

        combined_score = round((ml_result['probability'] * 10) + (rule_score * 0.5), 2)

        return {
            'success':         True,
            'error':           '',
            'url':             url,
            'verdict':         verdict,
            'verdict_label':   LABEL_MAP[verdict],
            'triggered_rules': triggered_rules,
            'rule_risk_score': rule_score,
            'ml_result':       ml_result,
            'features':        features if features else None,
            'explanation':     self._build_explanation(
                                   verdict, rule_score, ml_result,
                                   homoglyph_result, link_masking_result,
                                   whitelist_result, blocklist_result,
                               ),
            'whitelist':       whitelist_result,
            'homoglyph':       homoglyph_result,
            'link_masking':    link_masking_result,
            'xai':             self._build_xai(features, ml_result, triggered_rules, verdict),
            'combined_score':  combined_score,
            'blocklist':       blocklist_result,
            'zero_trust':      zero_trust_result,
            'zero_day':        zero_day_result,
        }

    def get_feature_importances(self) -> list[dict]:
        """Return sorted feature importances for all 19 ML features."""
        feature_order = [
            'url_length', 'hostname_length', 'path_length', 'num_dots',
            'num_hyphens', 'num_underscores', 'num_slashes', 'num_query_params',
            'num_special_chars', 'has_ip_host', 'has_https', 'has_at_sign',
            'subdomain_count', 'url_entropy',
            'has_suspicious_tld', 'hostname_digit_ratio', 'vowel_ratio',
            'has_non_standard_port', 'http_count_in_url',
        ]

        if self.ml_engine is None:
            return sorted(
                [
                    {
                        'feature':     n,
                        'importance':  _FEATURE_IMPORTANCE_APPROX.get(n, 0.0),
                        'description': _FEATURE_DESCRIPTIONS.get(n, ''),
                    }
                    for n in feature_order
                ],
                key=lambda x: x['importance'], reverse=True,
            )

        try:
            importances = self.ml_engine.model.feature_importances_
            result = [
                {
                    'feature':     n,
                    'importance':  round(float(imp), 6),
                    'description': _FEATURE_DESCRIPTIONS.get(n, ''),
                }
                for n, imp in zip(feature_order, importances)
            ]
            return sorted(result, key=lambda x: x['importance'], reverse=True)
        except Exception:
            return sorted(
                [
                    {
                        'feature':     n,
                        'importance':  _FEATURE_IMPORTANCE_APPROX.get(n, 0.0),
                        'description': _FEATURE_DESCRIPTIONS.get(n, ''),
                    }
                    for n in feature_order
                ],
                key=lambda x: x['importance'], reverse=True,
            )

    # ── Static helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _check_link_masking(url: str, visible_text: str) -> dict:
        if not visible_text or not visible_text.strip():
            return {'checked': False, 'is_masked': False, 'detail': 'No visible text provided.'}

        from urllib.parse import urlparse
        import re

        visible     = visible_text.strip().lower()
        href_domain = urlparse(url).netloc.lower().split(':')[0]
        pattern     = re.compile(r'([a-z0-9\-]+\.[a-z]{2,})', re.IGNORECASE)
        visible_domains = pattern.findall(visible)

        if not visible_domains:
            return {'checked': True, 'is_masked': False, 'detail': 'No domain in visible text.'}

        for vd in visible_domains:
            vd_lower = vd.lower()
            vd_clean = vd_lower[4:] if vd_lower.startswith('www.') else vd_lower
            hd_clean = href_domain[4:] if href_domain.startswith('www.') else href_domain
            if vd_clean not in hd_clean and hd_clean not in vd_clean:
                return {
                    'checked':        True,
                    'is_masked':      True,
                    'visible_domain': vd,
                    'actual_domain':  href_domain,
                    'detail':         f"Link masking: {vd} vs {href_domain}",
                }
        return {'checked': True, 'is_masked': False, 'detail': 'Domains match.'}

    @staticmethod
    def _zero_trust_validate(url: str) -> dict:
        """
        Zero Trust pre-flight validation.

        Enforces two hard checks on every non-whitelisted, non-blocklisted URL:

          ZT-1  DNS Resolution  — the hostname must resolve to a valid IP.
                A URL whose domain does not exist in DNS is immediately
                suspicious; legitimate sites have stable DNS records.

          ZT-2  SSL/TLS Validity — for HTTPS URLs, the certificate chain must
                be valid and trusted by the system's CA bundle.  A self-signed,
                expired, or mismatched certificate is a strong phishing signal.

        For HTTP URLs, ZT-2 is automatically failed (no TLS present).

        Returns:
            {
              'passed':       bool,   # True only if DNS ✓ AND TLS ✓
              'ssl_valid':    bool,
              'dns_resolved': bool,
              'checks':       list[dict]   # granular per-check results
            }
        """
        import ssl
        import socket
        from urllib.parse import urlparse as _urlparse

        parsed   = _urlparse(url)
        hostname = parsed.netloc.split(':')[0]
        checks: list[dict] = []

        # ── ZT-1: DNS Resolution ──────────────────────────────────────────────
        try:
            socket.getaddrinfo(
                hostname, None,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )
            dns_resolved = True
            checks.append({
                'check':  'dns_resolution',
                'passed': True,
                'detail': f"'{hostname}' resolves to a valid IP address.",
            })
        except socket.gaierror as exc:
            dns_resolved = False
            checks.append({
                'check':  'dns_resolution',
                'passed': False,
                'detail': f"DNS resolution failed for '{hostname}': {exc}",
            })

        # ── ZT-2: SSL/TLS Certificate Validity ───────────────────────────────
        if parsed.scheme == 'https':
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((hostname, 443), timeout=5) as raw_sock:
                    with ctx.wrap_socket(raw_sock, server_hostname=hostname) as tls_sock:
                        cert = tls_sock.getpeercert()
                ssl_valid = bool(cert)
                checks.append({
                    'check':  'ssl_tls_cert',
                    'passed': True,
                    'detail': 'SSL/TLS certificate is valid and trusted by system CA bundle.',
                })
            except ssl.SSLCertVerificationError as exc:
                ssl_valid = False
                checks.append({
                    'check':  'ssl_tls_cert',
                    'passed': False,
                    'detail': f"Certificate verification failed: {exc}",
                })
            except ssl.SSLError as exc:
                ssl_valid = False
                checks.append({
                    'check':  'ssl_tls_cert',
                    'passed': False,
                    'detail': f"SSL/TLS negotiation error: {exc}",
                })
            except OSError as exc:
                ssl_valid = False
                checks.append({
                    'check':  'ssl_tls_cert',
                    'passed': False,
                    'detail': f"Could not open TLS connection: {exc}",
                })
        else:
            ssl_valid = False
            checks.append({
                'check':  'ssl_tls_cert',
                'passed': False,
                'detail': 'URL uses HTTP — no SSL/TLS certificate present.',
            })

        return {
            'passed':       dns_resolved and ssl_valid,
            'ssl_valid':    ssl_valid,
            'dns_resolved': dns_resolved,
            'checks':       checks,
        }

    @staticmethod
    def _build_xai(features: dict, ml_result: dict, triggered_rules: list, verdict: str) -> dict:
        """Build XAI breakdown. Returns all keys expected by XaiResult.fromJson()."""
        FEATURE_RANGES = {
            'url_length':           (10, 200),
            'hostname_length':      (3, 80),
            'path_length':          (0, 120),
            'num_dots':             (1, 15),
            'num_hyphens':          (0, 10),
            'num_underscores':      (0, 6),
            'num_slashes':          (1, 20),
            'num_query_params':     (0, 12),
            'num_special_chars':    (0, 15),
            'has_ip_host':          (0, 1),
            'has_https':            (0, 1),
            'has_at_sign':          (0, 1),
            'subdomain_count':      (0, 8),
            'url_entropy':          (2, 6),
            'is_punycode':          (0, 1),
            # New v2 features
            'has_suspicious_tld':   (0, 1),
            'hostname_digit_ratio': (0.0, 0.6),
            'vowel_ratio':          (0.0, 0.6),
            'has_non_standard_port': (0, 1),
            'http_count_in_url':    (0, 4),
        }

        feature_contributions = []
        for fname, fval in features.items():
            lo, hi = FEATURE_RANGES.get(fname, (0, 10))
            span   = hi - lo if hi != lo else 1
            normalised = (
                1.0 - (fval - lo) / span
                if fname == 'has_https'
                else min(1.0, max(0.0, (fval - lo) / span))
            )
            importance = _FEATURE_IMPORTANCE_APPROX.get(fname, 0.001)
            feature_contributions.append({
                'feature':      fname,
                'value':        fval,
                'normalised':   round(normalised, 3),
                'importance':   importance,
                'contribution': round(normalised * importance, 6),
                'description':  _FEATURE_DESCRIPTIONS.get(fname, ''),
                'risk_level':   'high' if normalised > 0.7 else ('medium' if normalised > 0.4 else 'low'),
            })
        feature_contributions.sort(key=lambda x: x['contribution'], reverse=True)

        high_severity_rules: int = sum(
            1 for r in triggered_rules if r.get('severity') == 'high'
        )
        top_risk_features: list[str] = [
            f['feature'] for f in feature_contributions if f['normalised'] > 0.5
        ][:3]

        return {
            'why_summary': (
                f"Top indicators: {', '.join(f['feature'] for f in feature_contributions[:2])}"
                if feature_contributions
                else f"Heuristic-only mode — {len(triggered_rules)} rule(s) fired."
            ),
            'feature_contributions': feature_contributions,
            'ml_probability_pct':    round(ml_result['probability'] * 100, 1),
            'rule_count':            len(triggered_rules),
            'high_severity_rules':   high_severity_rules,
            'top_risk_features':     top_risk_features,
        }

    @staticmethod
    def _build_explanation(
        verdict: str, rule_score: int, ml_result: dict,
        homoglyph: dict, link_masking: dict,
        whitelist: dict, blocklist: dict,
    ) -> str:
        parts = [f"Hybrid scan complete. Verdict: {verdict.replace('_', ' ').title()}."]

        if blocklist.get('is_blocked'):
            parts.append(
                f"⛔ Confirmed threat via Google Safe Browsing "
                f"({blocklist.get('threat_type', 'unknown')})."
            )

        prob = ml_result.get('probability', 0.0)
        if prob > 0.0:
            parts.append(
                f"ML engine: {prob*100:.1f}% phishing probability. "
                f"Rule engine: {rule_score} points."
            )
        else:
            parts.append(f"Rule engine: {rule_score} points (ML running in heuristic-only mode).")

        if homoglyph.get('is_suspicious'):
            parts.append(f"⚠️ Homoglyph attack: impersonating '{homoglyph.get('matched_brand', '?')}'.")

        if link_masking.get('is_masked'):
            parts.append(f"⚠️ Link masking: displayed as '{link_masking.get('visible_domain', '?')}'.")

        if not whitelist.get('whitelisted'):
            parts.append("Domain is NOT in the global Tranco whitelist.")

        return ' '.join(parts)
