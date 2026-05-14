# =============================================================================
# modules/rule_engine.py  —  RuleEngine (Deterministic Heuristics)
# =============================================================================
# IMPROVEMENTS IN THIS VERSION:
#
#   NEW RULE A — Brand Name in Path (Impersonation):
#     Detects well-known brand names in the URL path when that brand does NOT
#     appear in the actual hostname.  e.g. http://evil.com/paypal/verify
#     fires; http://paypal.com/verify does NOT fire.
#
#   NEW RULE B — Multiple Phishing Keywords:
#     Fires when 2+ high-signal phishing words appear in the same URL.
#     Single-keyword hits are too noisy; two or more is a strong combined signal.
#
#   NEW RULE C — Free Hosting Subdomain:
#     Detects phishing pages hosted on legitimate free-hosting platforms
#     (Weebly, Netlify, Vercel, Firebase, etc.) via a subdomain.
#     e.g. paypal-login.weebly.com fires; weebly.com itself does NOT.
#
#   FALSE POSITIVE REDUCTION (_RE_SAFE_LONG):
#     Suppresses the URL-length rules for URLs that match reputable long-URL
#     patterns (Amazon product pages, YouTube, Google Maps, LinkedIn, GitHub).
#
#   BUG-03 FIX (retained): Thresholds >= 8 (phishing), >= 4 (suspicious).
#
#   ADDED — check_zero_day():
#     New public method called by URLAnalyzer as Stage 6.5.  Detects zero-day
#     phishing infrastructure via four pure-heuristic lenses (no I/O):
#       ZD-1  High URL entropy + suspicious TLD
#       ZD-2  DGA-like second-level domain
#       ZD-3  Extreme URL length on an unrecognised domain
#       ZD-4  Stacked obfuscation (percent-encoding + double-slash redirect)
#     WHOIS-based newly-registered domain checks are NOT duplicated here —
#     they already live in DeepAnalyzer._check_domain_age() (Deep Path only).
# =============================================================================

import re
from urllib.parse import urlparse


class RuleEngine:
    """Applies deterministic heuristic rules to a URL."""

    # ── Constants ──────────────────────────────────────────────────────────────
    LENGTH_MEDIUM_THRESHOLD = 54
    LENGTH_HIGH_THRESHOLD   = 75
    SUBDOMAIN_THRESHOLD     = 3

    SUSPICIOUS_TLDS = {
        ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz",
        ".top", ".click", ".link", ".win", ".download",
    }

    SHORTENER_DOMAINS = {
        "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co",
        "is.gd", "buff.ly", "adf.ly", "shorte.st",
    }

    # NEW RULE A — brand names checked against the URL path.
    _BRANDS = {
        'paypal', 'amazon', 'apple', 'microsoft', 'google',
        'facebook', 'instagram', 'netflix', 'dropbox', 'linkedin',
        'twitter', 'chase', 'wellsfargo', 'bankofamerica', 'citibank',
        'ebay', 'spotify', 'adobe', 'yahoo', 'github',
    }

    # NEW RULE B — phishing-associated keywords; 2+ hits required.
    _PHISHING_KEYWORDS = {
        'verify', 'confirm', 'update', 'secure', 'login',
        'signin', 'account', 'banking', 'password', 'credential',
        'suspend', 'limited', 'urgent', 'alert', 'validate',
        'authenticate', 'recover', 'unlock', 'unusual',
    }

    # RULE D — open-redirect query parameter names.
    # These parameter names are used by legitimate sites for navigation, but
    # phishers abuse them to bounce victims through trusted domains to evil ones.
    # e.g. https://trusted.com/logout?next=https://evil.com/steal
    _OPEN_REDIRECT_PARAMS = {
        'url', 'redirect', 'redirect_url', 'redirect_uri',
        'next', 'return', 'return_url', 'returnurl',
        'goto', 'target', 'destination', 'dest',
        'continue', 'forward', 'location', 'link',
    }

    # NEW RULE C — free hosting providers abused for phishing subdomains.
    _FREE_HOSTING = {
        'weebly.com', 'wix.com', 'web.app', 'firebaseapp.com',
        'ngrok.io', 'netlify.app', 'vercel.app', 'glitch.me',
        'pages.dev', 'github.io', 'repl.co', '000webhostapp.com',
        'myfreesites.net', 'hostfree.pw', 'byet.host',
    }

    # FALSE POSITIVE REDUCTION — reputable sites that produce long URLs.
    # When matched, Rules 2a/2b (URL length) are suppressed.
    _RE_SAFE_LONG = re.compile(
        r'('
        r'amazon\.[a-z]{2,6}/(?:dp|gp|s|product)/|'
        r'ebay\.[a-z]{2,6}/itm/|'
        r'google\.[a-z]{2,6}/maps|'
        r'youtube\.com/watch\?|'
        r'linkedin\.com/in/|'
        r'linkedin\.com/posts/|'
        r'github\.com/[^/]+/[^/]+|'
        r'twitter\.com/[^/]+/status/|'
        r'x\.com/[^/]+/status/|'
        r'accounts\.google\.com/|'
        r'login\.microsoftonline\.com/|'
        r'login\.live\.com/|'
        r'appleid\.apple\.com/|'
        r'auth\.amazon\.com/'
        r')',
        re.IGNORECASE,
    )

    # ── Compiled Regular Expressions ──────────────────────────────────────────
    _RE_IP_HOST      = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$")
    _RE_AT_SIGN      = re.compile(r"@")
    _RE_DOUBLE_SLASH = re.compile(r"(?<!:)//")
    _RE_MULTI_HYPHEN = re.compile(r"-{2,}")
    _RE_PERCENT_ENC  = re.compile(r"%[0-9a-fA-F]{2}")
    _RE_PUNYCODE     = re.compile(r"^xn--")

    def analyze(self, url: str) -> dict:
        triggered = []
        parsed    = urlparse(url)
        netloc    = parsed.netloc.lower()
        hostname  = netloc.split(":")[0]
        path      = parsed.path.lower()
        full_url  = url.lower()

        clean_host = hostname[4:] if hostname.startswith("www.") else hostname

        # ── Rule 0: Punycode / Homograph Detection ────────────────────────────
        if self._RE_PUNYCODE.match(clean_host):
            triggered.append({
                "name": "Punycode (Homograph Attack) Detected",
                "description": (
                    f"The domain '{hostname}' uses Punycode (starts with 'xn--'). "
                    "This is a common technique for homograph attacks where "
                    "international characters are used to visually mimic trusted brands."
                ),
                "severity": "high",
            })

        # ── Rule 1: IP address used as host ───────────────────────────────────
        if self._RE_IP_HOST.match(netloc):
            triggered.append({
                "name": "IP Address as Host",
                "description": f"The URL uses a raw IP address ({netloc}) instead of a domain.",
                "severity": "high",
            })

        # ── Rule 2: URL length (with false-positive suppression) ──────────────
        url_len      = len(url)
        is_safe_long = bool(self._RE_SAFE_LONG.search(url))

        if url_len > self.LENGTH_HIGH_THRESHOLD and not is_safe_long:
            triggered.append({
                "name": "Excessively Long URL",
                "description": f"URL length is {url_len} characters. Used to hide malicious domains.",
                "severity": "high",
            })
        elif url_len > self.LENGTH_MEDIUM_THRESHOLD and not is_safe_long:
            triggered.append({
                "name": "Unusually Long URL",
                "description": f"URL length is {url_len} characters. Slightly above normal.",
                "severity": "medium",
            })

        # ── Rule 3: Excessive subdomains ──────────────────────────────────────
        parts = clean_host.split(".")
        if len(parts) > self.SUBDOMAIN_THRESHOLD:
            triggered.append({
                "name": "Excessive Subdomains",
                "description": (
                    f"Hostname has {len(parts)} labels. "
                    "Brand names may be embedded as subdomains."
                ),
                "severity": "high",
            })

        # ── Rule 4: @ symbol ──────────────────────────────────────────────────
        if self._RE_AT_SIGN.search(url):
            triggered.append({
                "name": "@ Symbol in URL",
                "description": "Browsers discard everything BEFORE '@', redirecting to the host after it.",
                "severity": "high",
            })

        # ── Rule 5: Double slash in path ──────────────────────────────────────
        url_after_scheme = url.split("://", 1)[-1]
        if self._RE_DOUBLE_SLASH.search(url_after_scheme):
            triggered.append({
                "name": "Double Slash Redirection",
                "description": "Found '//' outside the scheme. Can enable open redirect attacks.",
                "severity": "high",
            })

        # ── Rule 6: Multiple hyphens in hostname ──────────────────────────────
        if self._RE_MULTI_HYPHEN.search(hostname):
            triggered.append({
                "name": "Multiple Hyphens in Domain",
                "description": (
                    f"Domain '{hostname}' contains consecutive hyphens "
                    "(common in typosquatting)."
                ),
                "severity": "medium",
            })

        # ── Rule 7: HTTP (no TLS) ─────────────────────────────────────────────
        if parsed.scheme == "http":
            triggered.append({
                "name": "No HTTPS (Unencrypted)",
                "description": "Connection is unencrypted; site lacks an SSL certificate.",
                "severity": "medium",
            })

        # ── Rule 8: Suspicious TLD ────────────────────────────────────────────
        for tld in self.SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                triggered.append({
                    "name": "Suspicious Top-Level Domain",
                    "description": f"Domain ends with '{tld}', a TLD frequently used in phishing.",
                    "severity": "high",
                })
                break

        # ── Rule 9: URL shortener ─────────────────────────────────────────────
        for shortener in self.SHORTENER_DOMAINS:
            if clean_host == shortener or clean_host.endswith("." + shortener):
                triggered.append({
                    "name": "URL Shortener Detected",
                    "description": f"Service '{shortener}' masks the true destination.",
                    "severity": "medium",
                })
                break

        # ── Rule 10: Percent-encoded obfuscation ──────────────────────────────
        encoded_count = len(self._RE_PERCENT_ENC.findall(url))
        if encoded_count >= 3:
            triggered.append({
                "name": "Excessive Percent-Encoding",
                "description": (
                    f"Found {encoded_count} percent-encoded characters used for obfuscation."
                ),
                "severity": "medium",
            })

        # ── NEW RULE A: Brand Name in Path (Impersonation) ────────────────────
        for brand in self._BRANDS:
            if brand in path and brand not in clean_host:
                triggered.append({
                    "name": "Brand Name in Path (Impersonation)",
                    "description": (
                        f"Brand '{brand}' appears in the URL path but not in the domain. "
                        "This is a classic technique to make phishing pages look legitimate."
                    ),
                    "severity": "high",
                })
                break

        # ── NEW RULE B: Multiple Phishing Keywords ────────────────────────────
        kw_hits = [k for k in self._PHISHING_KEYWORDS if k in full_url]
        if len(kw_hits) >= 2:
            triggered.append({
                "name": "Multiple Phishing Keywords",
                "description": (
                    f"URL contains {len(kw_hits)} phishing-associated terms: "
                    f"{', '.join(kw_hits[:5])}. "
                    "Legitimate sites rarely combine this many credential-related words."
                ),
                "severity": "medium",
            })

        # ── NEW RULE C: Free Hosting Subdomain ────────────────────────────────
        # clean_host strips www. so weebly.com and www.weebly.com are safe;
        # only attacker.weebly.com (endswith '.weebly.com') is flagged.
        for free_host in self._FREE_HOSTING:
            if clean_host.endswith("." + free_host):
                triggered.append({
                    "name": "Phishing on Free Hosting Platform",
                    "description": (
                        f"This URL is hosted as a subdomain on '{free_host}', "
                        "a free platform commonly abused to host phishing pages "
                        "with no domain registration or identity verification."
                    ),
                    "severity": "high",
                })
                break

        # ── RULE D: Brand Name Embedded in Hostname (Hyphen-Based Spoofing) ────
        # Catches attacks like paypal-secure.com, amazon-login.net, and
        # microsoft-verify.xyz.  The brand-in-path rule (Rule A) misses these
        # because it only fires when the brand is NOT in the hostname.
        # The homoglyph Levenshtein check also misses them because it skips
        # comparisons where abs(len(sld) - len(brand)) > 3 — paypal-secure (13)
        # vs paypal (6) = diff 7, so it is skipped.
        # This rule fires only if the domain is NOT an exact brand domain, to
        # avoid flagging 'paypal.com' itself.
        for brand in self._BRANDS:
            # SLD contains the brand as a prefix or suffix separated by hyphen
            if ('-' in clean_host and brand in clean_host.split('-')[0:1] + clean_host.split('-')[-1:]):
                # Make sure the domain is not the real brand (paypal.com passes)
                if not (clean_host == brand or clean_host.startswith(brand + '.')):
                    triggered.append({
                        'name': 'Brand Name in Hostname (Spoofing)',
                        'description': (
                            f"The brand '{brand}' appears inside the domain '{hostname}' "
                            "combined with other words via hyphens — a classic technique "
                            "to make a fake domain look like an official subdomain or service "
                            f"(e.g. {brand}-secure.com, {brand}-login.net)."
                        ),
                        'severity': 'high',
                    })
                    break

        # ── RULE E: Open Redirect Parameter ──────────────────────────────────
        # Detects known open-redirect query parameter names whose value starts
        # with http(s):// — a strong signal that the URL is being used to bounce
        # the user to an attacker-controlled destination through a trusted host.
        # e.g. https://trusted.com/out?url=https://evil.com/steal
        if parsed.query:
            from urllib.parse import parse_qs
            try:
                params = parse_qs(parsed.query, keep_blank_values=False)
                for param_name, values in params.items():
                    if param_name.lower() in self._OPEN_REDIRECT_PARAMS:
                        val = values[0].lower() if values else ''
                        if val.startswith('http://') or val.startswith('https://'):
                            triggered.append({
                                'name': 'Open Redirect Parameter',
                                'description': (
                                    f"Query parameter '{param_name}' contains an external URL "
                                    f"as its value ('{values[0][:60]}...' if len > 60 else '{values[0]}'). "
                                    "Open redirects are used to lend legitimacy to phishing links by "
                                    "routing victims through a trusted domain before landing on a "
                                    "malicious page."
                                ),
                                'severity': 'high',
                            })
                            break
            except Exception:
                pass  # Malformed query string — skip silently

        # ── Compute risk score ────────────────────────────────────────────────
        risk_score = sum(
            5 if r["name"] == "Punycode (Homograph Attack) Detected" else
            (3 if r["severity"] == "high" else 1)
            for r in triggered
        )

        # ── BUG-03 FIX: 8/4 standard ─────────────────────────────────────────
        if risk_score >= 8:
            verdict = "likely_phishing"
        elif risk_score >= 4:
            verdict = "suspicious"
        else:
            verdict = "safe"

        return {
            "triggered_rules": triggered,
            "risk_score":      risk_score,
            "verdict":         verdict,
        }

    # ── Zero-Day Threat Indicators ─────────────────────────────────────────────
    # Called from URLAnalyzer.analyze() as Stage 6.5 — after the rule engine
    # and before ML prediction.  All checks are pure heuristics (no I/O).
    # WHOIS-based newly-registered domain checks live in DeepAnalyzer
    # (_check_domain_age) and are NOT duplicated here.

    def check_zero_day(self, url: str) -> dict:
        """
        Detect zero-day phishing signals through four heuristic lenses:
          ZD-1  High URL entropy + suspicious TLD  (auto-generated domains)
          ZD-2  DGA-like SLD  (digit-heavy or consonant-only hostnames)
          ZD-3  Extreme URL length on an unrecognised domain
          ZD-4  Stacked obfuscation (percent-encoding AND double-slash redirect)

        Returns:
            {
              'is_zero_day':    bool,
              'zero_day_score': int,
              'indicators':     list[dict]
            }
        """
        import math
        from urllib.parse import urlparse

        parsed     = urlparse(url)
        netloc     = parsed.netloc.lower()
        hostname   = netloc.split(':')[0]
        clean_host = hostname[4:] if hostname.startswith('www.') else hostname
        host_sld   = clean_host.split('.')[0]  # second-level domain label only

        indicators: list[dict] = []
        score = 0

        # ── ZD-1: High URL entropy + suspicious TLD ───────────────────────────
        # Legitimate URLs have lower Shannon entropy; auto-generated phishing
        # domains on free/abused TLDs produce highly random character sequences.
        url_body = url.replace('https://', '').replace('http://', '')
        if url_body:
            freq: dict[str, int] = {}
            for ch in url_body:
                freq[ch] = freq.get(ch, 0) + 1
            entropy = -sum(
                (v / len(url_body)) * math.log2(v / len(url_body))
                for v in freq.values()
            )
        else:
            entropy = 0.0

        has_susp_tld = any(clean_host.endswith(t) for t in self.SUSPICIOUS_TLDS)
        if entropy > 4.5 and has_susp_tld:
            indicators.append({
                'indicator': 'high_entropy_suspicious_tld',
                'detail': (
                    f'URL Shannon entropy is {entropy:.2f} on a suspicious TLD — '
                    'consistent with an auto-generated zero-day phishing domain.'
                ),
                'severity': 'high',
            })
            score += 3

        # ── ZD-2: DGA-like SLD (digit-heavy or near-zero vowel ratio) ─────────
        # Domain Generation Algorithms produce hostnames with high digit ratios
        # or unnatural consonant clusters that human-chosen names never exhibit.
        digits_in_sld = sum(c.isdigit() for c in host_sld)
        digit_ratio   = digits_in_sld / max(len(host_sld), 1)
        vowels_in_sld = sum(c in 'aeiou' for c in host_sld)
        vowel_ratio   = vowels_in_sld / max(len(host_sld), 1)

        if digit_ratio > 0.4 or (vowel_ratio < 0.15 and len(host_sld) > 5):
            indicators.append({
                'indicator': 'dga_like_hostname',
                'detail': (
                    f"SLD '{host_sld}' shows DGA-like characteristics "
                    f"(digit ratio: {digit_ratio:.2f}, vowel ratio: {vowel_ratio:.2f}). "
                    'Machine-generated hostnames are a hallmark of zero-day '
                    'phishing infrastructure.'
                ),
                'severity': 'high',
            })
            score += 3

        # ── ZD-3: Extreme URL length on an unrecognised domain ────────────────
        # Newly deployed phishing pages frequently use long, obfuscated paths
        # to evade static pattern matching while the domain itself is unknown.
        known_brand_in_host = any(b in clean_host for b in self._BRANDS)
        if len(url) > 100 and not known_brand_in_host:
            indicators.append({
                'indicator': 'extreme_length_unknown_domain',
                'detail': (
                    f'URL is {len(url)} characters on an unrecognised domain — '
                    'heavy path obfuscation on a novel domain is a zero-day evasion pattern.'
                ),
                'severity': 'medium',
            })
            score += 2

        # ── ZD-4: Stacked obfuscation (percent-encoding + double-slash) ────────
        # Layering multiple evasion techniques simultaneously is rare in
        # legitimate traffic and strongly correlates with brand-new malicious URLs
        # that have not yet been indexed by reputation services.
        encoded_count = len(re.findall(r'%[0-9a-fA-F]{2}', url))
        after_scheme  = url.split('://', 1)[-1]
        has_dbl_slash = '//' in after_scheme

        if encoded_count >= 2 and has_dbl_slash:
            indicators.append({
                'indicator': 'stacked_obfuscation',
                'detail': (
                    f'{encoded_count} percent-encoded segments combined with a '
                    'double-slash redirect — layered evasion targets static filters '
                    'and reputation engines that cannot yet classify the URL.'
                ),
                'severity': 'high',
            })
            score += 3

        return {
            'is_zero_day':    score >= 3,
            'zero_day_score': score,
            'indicators':     indicators,
        }
