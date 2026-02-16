#!/usr/bin/env python3
"""
Arcanis v5.1.2 — COMMUNITY EDITION (Free)
════════════════════════════════════════════
Free for personal and educational use.
Pro edition with live verification + exploit
paths available at https://arcanis.sh
════════════════════════════════════════════

Original: Arcanis v5.0 — High-Signal Secret & API Exposure Scanner
─────────────────────────────────────────────────────────
Author : Muhammad Muiz Zamri
License: For Authorized Security Testing Only

Designed to maximize bounty impact and minimize noise.

Core Advantages:
  1. Live secret verification — not just detection, proof
  2. Attack chain scoring — prioritized by real-world impact
  3. Brutal false-positive filtering — entropy, context, dedup
  4. Scope-aware scanning — no out-of-scope noise
  5. Report-ready output — HTML/PDF/SARIF, submit-quality

Changelog v5.0:
  ✦ CVE AUTO-LOOKUP — cross-reference npm packages from source maps
    against OSV.dev, flag known vulnerabilities inline with severity
  ✦ VISUAL REPORTS — professional HTML/PDF reports with severity
    charts, executive summary, remediation guidance
  ✦ BATCH SCANNING — multi-target from file/stdin, resume support
  ✦ RATE LIMIT ANALYSIS — check if verified keys have rate protection,
    estimate cost exposure (safe mode, header-based extrapolation)

Changelog v4.0:
  ✦ HISTORICAL ANALYSIS — Wayback Machine JS/HTML mining (--wayback),
    source map analysis, endpoint discovery, dangling DNS detection
  ✦ BROAD COVERAGE — wide provider support across cloud, SaaS,
    payment, analytics, identity, CI/CD, AI/ML, messaging, and database
  ✦ LIVE VERIFICATION — confirms findings against actual APIs,
    checks scope/permissions, validates token liveness
  ✦ IMPACT SCORING — automated risk chain analysis,
    exploitability scoring (0-100), bounty tier estimation

Carried from v3.0:
  • Dependency audit (known vulnerable versions) · Security headers
  • FP auto-filter · Endpoint discovery · Adaptive request handling
  • CI/CD integration · Webhooks · Source map intel
"""

import requests
import re
import sys
import os
import json
import time
import math
import random
import base64
import html as html_lib
import argparse
import hashlib
import threading
import copy
import socket
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, quote, unquote, parse_qs, urlencode
from typing import List, Dict, Set, Tuple, Optional
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
import sqlite3

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:
    import asyncio
    import aiohttp
    HAS_ASYNC = True
except ImportError:
    HAS_ASYNC = False

__version__ = '5.1.2-community'
__author__  = 'Muhammad Muiz Zamri'
__lines__   = '10,900+'


# ═══════════════════════════════════════════════════════════════════
#  License Key Validation
# ═══════════════════════════════════════════════════════════════════

import hmac as _hmac

# This is baked into the binary — change before distributing
_LICENSE_SALT = "a7c3f9e1b2d4806573cafe9182736455"

_LICENSE_DIR  = os.path.join(str(Path.home()), ".arcanis")
_LICENSE_FILE = os.path.join(_LICENSE_DIR, "license")

_PLANS = {
    "starter":  ["scan", "verify", "json"],
    "pro":      ["scan", "verify", "json", "html", "pdf", "sarif",
                 "wayback", "cve", "batch", "attack_chains"],
    "lifetime": ["scan", "verify", "json", "html", "pdf", "sarif",
                 "wayback", "cve", "batch", "attack_chains"],
}


def _key_decode(key: str) -> Optional[dict]:
    """Decode and verify a license key. Returns payload or None."""
    try:
        # Strip prefix and dashes: ARC-xxxx-xxxx-... -> raw
        raw = key.replace("ARC-", "").replace("-", "")
        if len(raw) < 20:
            return None

        # Last 16 chars = signature, rest = payload
        payload_b64 = raw[:-16]
        sig_given = raw[-16:]

        # Verify HMAC signature
        sig_expected = _hmac.new(
            _LICENSE_SALT.encode(),
            payload_b64.encode(),
            hashlib.sha256
        ).hexdigest()[:16]

        if not _hmac.compare_digest(sig_given, sig_expected):
            return None

        # Decode payload
        padded = payload_b64 + "=" * (4 - len(payload_b64) % 4)
        payload_json = base64.urlsafe_b64decode(padded).decode()
        payload = json.loads(payload_json)

        # Expand plan initial to full name
        plan_map = {"s": "starter", "p": "pro", "l": "lifetime"}
        p = payload.get("p", "")
        if p in plan_map:
            payload["p"] = plan_map[p]

        return payload
    except Exception:
        return None


def _key_validate(key: str) -> Tuple[bool, str, Optional[dict]]:
    """
    Validate a license key.
    Returns: (valid, message, payload)
    """
    payload = _key_decode(key)
    if payload is None:
        return False, "Invalid license key.", None

    # Check expiry
    expires = payload.get("x", 0)
    now = int(time.time())
    if now > expires:
        from datetime import datetime as _dt
        exp_date = _dt.fromtimestamp(expires).strftime("%Y-%m-%d")
        return False, f"License expired on {exp_date}. Renew at https://arcanis.sh", None

    return True, "Valid", payload


def _key_save(key: str):
    """Save key locally so user doesn't retype every time."""
    os.makedirs(_LICENSE_DIR, mode=0o700, exist_ok=True)
    with open(_LICENSE_FILE, "w") as f:
        f.write(key.strip())
    os.chmod(_LICENSE_FILE, 0o600)


def _key_load() -> Optional[str]:
    """Load saved key, or from env var."""
    # 1. Environment variable
    env_key = os.environ.get("ARCANIS_KEY")
    if env_key:
        return env_key.strip()
    # 2. Saved file
    if os.path.exists(_LICENSE_FILE):
        with open(_LICENSE_FILE) as f:
            return f.read().strip()
    return None


def _key_check_feature(payload: dict, feature: str) -> bool:
    """Check if the license includes a specific feature."""
    plan = payload.get("p", "")
    allowed = _PLANS.get(plan, [])
    return feature in allowed


def _license_gate(args) -> Optional[dict]:
    """
    Community Edition — no license required.
    Returns a free-tier payload.
    """
    print(f"  License: {Colors.OKCYAN}COMMUNITY EDITION{Colors.ENDC} (free)")
    print(f"  {Colors.DIM}Upgrade → arcanis.sh for live verification + exploit paths{Colors.ENDC}")
    print()
    return {"p": "free", "x": 9999999999, "e": "community"}


# ═══════════════════════════════════════════════════════════════════
#  Utility — Colors
# ═══════════════════════════════════════════════════════════════════

class Colors:
    HEADER    = '\033[95m'
    OKBLUE    = '\033[94m'
    OKCYAN    = '\033[96m'
    OKGREEN   = '\033[92m'
    WARNING   = '\033[93m'
    FAIL      = '\033[91m'
    ENDC      = '\033[0m'
    BOLD      = '\033[1m'
    UNDERLINE = '\033[4m'
    DIM       = '\033[2m'


# ═══════════════════════════════════════════════════════════════════
#  Progress Bar
# ═══════════════════════════════════════════════════════════════════

class ProgressBar:
    def __init__(self, enabled=True):
        self.enabled = enabled
        self._lock = threading.Lock()
        self.urls_total = 0
        self.urls_done = 0
        self.js_scanned = 0
        self.secrets_found = 0
        self.waf_blocked = 0
        self.verified = 0
        self.retries_used = 0
        self._last_len = 0
        self._start_time = time.time()

    def set_total(self, total: int):
        self.urls_total = total
        self._start_time = time.time()

    def increment(self, field: str, amount: int = 1):
        with self._lock:
            setattr(self, field, getattr(self, field) + amount)
            self._render()

    def update(self, **kwargs):
        with self._lock:
            for k, v in kwargs.items():
                if v is not None:
                    setattr(self, k, v)
            self._render()

    def _format_eta(self):
        """Calculate and format estimated time remaining."""
        if self.urls_done <= 0 or self.urls_total <= 0:
            return ""
        elapsed = time.time() - self._start_time
        if elapsed < 3:
            return ""  # Too early to estimate
        rate = self.urls_done / elapsed  # URLs per second
        remaining = self.urls_total - self.urls_done
        if rate > 0 and remaining > 0:
            eta_secs = remaining / rate
            if eta_secs < 60:
                return f" ETA:{int(eta_secs)}s"
            elif eta_secs < 3600:
                return f" ETA:{int(eta_secs/60)}m{int(eta_secs%60)}s"
            else:
                return f" ETA:{int(eta_secs/3600)}h{int((eta_secs%3600)/60)}m"
        elif remaining <= 0:
            return " done"
        return ""

    def _render(self):
        if not self.enabled:
            return
        total = max(self.urls_total, 1)
        pct = min(self.urls_done / total, 1.0)
        filled = int(20 * pct)
        bar = '█' * filled + '░' * (20 - filled)
        eta = self._format_eta()
        # Show retry/WAF stats in real-time (Feature #4)
        extra = ""
        if self.retries_used > 0 or self.waf_blocked > 0:
            extra = f" · ↻{self.retries_used}"
            if self.waf_blocked > 0:
                extra += f" · 🛡{self.waf_blocked}"
        line = (f"\r{Colors.DIM}[{bar}] {self.urls_done}/{self.urls_total} URLs"
                f" · {self.js_scanned} JS · {self.secrets_found} secrets"
                f" · {self.verified} verified{extra}{eta}{Colors.ENDC}")
        pad = max(0, self._last_len - len(line))
        sys.stderr.write(line + ' ' * pad)
        sys.stderr.flush()
        self._last_len = len(line)

    def finish(self):
        if self.enabled:
            elapsed = time.time() - self._start_time
            if elapsed >= 60:
                time_str = f"{int(elapsed/60)}m{int(elapsed%60)}s"
            else:
                time_str = f"{elapsed:.1f}s"
            # Print final summary line before clearing
            sys.stderr.write(f"\r{Colors.DIM}[{'█'*20}] Complete in {time_str} "
                             f"· {self.urls_done} URLs · {self.js_scanned} JS "
                             f"· {self.secrets_found} secrets{Colors.ENDC}")
            sys.stderr.write('\n')
            sys.stderr.flush()
            self._last_len = 0


# ═══════════════════════════════════════════════════════════════════
#  Rate Limiter
# ═══════════════════════════════════════════════════════════════════

class RateLimiter:
    """Token-bucket rate limiter for HTTP requests."""
    def __init__(self, rps: float = 0):
        self.rps = rps
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self):
        if self.rps <= 0:
            return
        with self._lock:
            now = time.time()
            interval = 1.0 / self.rps
            elapsed = now - self._last
            if elapsed < interval:
                time.sleep(interval - elapsed)
            self._last = time.time()


# ═══════════════════════════════════════════════════════════════════
#  Entropy calculator
# ═══════════════════════════════════════════════════════════════════

def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = defaultdict(int)
    for c in data:
        freq[c] += 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 2)


# ═══════════════════════════════════════════════════════════════════
#  JWT Security Analyzer — v2.9 (enhanced from v2.8 decode_jwt)
# ═══════════════════════════════════════════════════════════════════

class JWTAnalyzer:
    """
    Deep JWT analysis: decode + security scoring + vulnerability detection.
    Risk score 0-100 based on algorithm, claims, lifetime, permissions.
    """

    # Algorithm risk: higher = worse
    ALG_RISK = {
        'none': 50, '': 50,
        'hs256': 15, 'hs384': 10, 'hs512': 5,
        'rs256': 0, 'rs384': 0, 'rs512': 0,
        'es256': 0, 'es384': 0, 'es512': 0,
        'ps256': 0, 'ps384': 0, 'ps512': 0,
        'eddsa': 0,
    }

    REQUIRED_CLAIMS = ['iss', 'exp', 'aud', 'nbf', 'jti']

    PERMISSION_KEYS = [
        'scope', 'scopes', 'permissions', 'roles', 'role',
        'authorities', 'grants', 'access', 'entitlements',
    ]

    SENSITIVE_SCOPES = [
        'admin', 'write', 'delete', 'manage', 'superuser', 'root',
        'full_access', 'read_write', 'owner', '*',
    ]

    @staticmethod
    def analyze(token: str) -> Optional[Dict]:
        """Full JWT analysis with security scoring."""
        try:
            parts = token.split('.')
            if len(parts) < 2:
                return None

            def _b64(s):
                s += '=' * (4 - len(s) % 4)
                return json.loads(base64.urlsafe_b64decode(s))

            header = _b64(parts[0])
            payload = _b64(parts[1])
        except Exception:
            return None

        analysis = {
            'algorithm': header.get('alg', 'unknown'),
            'type': header.get('typ', 'unknown'),
            'issuer': payload.get('iss', 'N/A'),
            'subject': payload.get('sub', 'N/A'),
            'audience': payload.get('aud', 'N/A'),
        }

        vulns = []
        risk_score = 0

        # ── Algorithm check ──
        alg = header.get('alg', '').lower()
        alg_risk = JWTAnalyzer.ALG_RISK.get(alg, 5)
        risk_score += alg_risk
        if alg in ('none', 'nonce', ''):
            vulns.append('ALG_NONE — JWT accepts unsigned tokens!')
            analysis['algorithm_rating'] = 'CRITICAL'
        elif alg in ('hs256',):
            vulns.append('WEAK_ALG — HS256 is vulnerable to brute-force if key is short')
            analysis['algorithm_rating'] = 'MEDIUM'
        elif alg.startswith('hs'):
            analysis['algorithm_rating'] = 'LOW'
        else:
            analysis['algorithm_rating'] = 'OK'

        # ── Missing claims check ──
        missing = [c for c in JWTAnalyzer.REQUIRED_CLAIMS if c not in payload]
        if missing:
            risk_score += len(missing) * 5
            analysis['missing_claims'] = missing
            if 'exp' in missing:
                vulns.append(f'NO_EXPIRY — Token never expires (missing exp claim)')
                risk_score += 15
            if 'aud' in missing:
                vulns.append('NO_AUDIENCE — Token valid for any service (missing aud)')

        # ── Expiration analysis ──
        now = datetime.now(timezone.utc)
        exp = payload.get('exp')
        iat = payload.get('iat')
        if exp:
            try:
                exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc)
                analysis['expires'] = exp_dt.isoformat()
                analysis['expired'] = exp_dt < now
                if exp_dt < now:
                    analysis['expired_since'] = str(now - exp_dt)
                else:
                    analysis['expires_in'] = str(exp_dt - now)
            except (OSError, ValueError):
                pass
        if iat:
            try:
                iat_dt = datetime.fromtimestamp(iat, tz=timezone.utc)
                analysis['issued_at'] = iat_dt.isoformat()
                # Long-lived token check
                if exp:
                    try:
                        lifetime = datetime.fromtimestamp(exp, tz=timezone.utc) - iat_dt
                        lifetime_days = lifetime.total_seconds() / 86400
                        analysis['lifetime_days'] = round(lifetime_days, 1)
                        if lifetime_days > 365:
                            vulns.append(f'EXTREME_LIFETIME — Token valid for {lifetime_days:.0f} days')
                            risk_score += 20
                        elif lifetime_days > 30:
                            vulns.append(f'LONG_LIFETIME — Token valid for {lifetime_days:.0f} days')
                            risk_score += 10
                    except (OSError, ValueError):
                        pass
            except (OSError, ValueError):
                pass

        # ── Permission/scope extraction ──
        permissions = []
        for key in JWTAnalyzer.PERMISSION_KEYS:
            val = payload.get(key)
            if val:
                if isinstance(val, str):
                    permissions.extend(val.split())
                elif isinstance(val, list):
                    permissions.extend([str(v) for v in val])
        if permissions:
            analysis['permissions'] = permissions
            sensitive = [p for p in permissions
                         if any(s in p.lower() for s in JWTAnalyzer.SENSITIVE_SCOPES)]
            if sensitive:
                vulns.append(f'ELEVATED_PERMISSIONS — {", ".join(sensitive[:5])}')
                risk_score += 15
                analysis['sensitive_permissions'] = sensitive

        # ── Custom claims of interest ──
        interesting_keys = ['email', 'name', 'preferred_username', 'groups',
                            'tenant', 'org', 'organization', 'team']
        extra_claims = {k: payload[k] for k in interesting_keys if k in payload}
        if extra_claims:
            analysis['pii_claims'] = extra_claims

        # ── Final scoring ──
        risk_score = min(risk_score, 100)
        analysis['risk_score'] = risk_score
        analysis['risk_grade'] = (
            'CRITICAL' if risk_score >= 60 else
            'HIGH' if risk_score >= 40 else
            'MEDIUM' if risk_score >= 20 else
            'LOW'
        )
        analysis['vulnerabilities'] = vulns

        return {'header': header, 'payload': payload, 'analysis': analysis}


def decode_jwt(token: str) -> Optional[Dict]:
    """Wrapper for backward compatibility."""
    return JWTAnalyzer.analyze(token)


# ═══════════════════════════════════════════════════════════════════
#  Active API Verifiers — v2.8
# ═══════════════════════════════════════════════════════════════════

class ActiveVerifier:
    """
    Live API verification for discovered secrets.
    Only runs when --verify flag is set.
    All checks are read-only (GET requests or minimal-permission calls).
    """

    def __init__(self, session: requests.Session, timeout: int = 5):
        self.session = session
        self.timeout = timeout

    def verify_google_maps(self, key: str) -> Dict:
        """Probe Google Maps Geocoding API with an invalid address."""
        try:
            r = self.session.get(
                'https://maps.googleapis.com/maps/api/geocode/json',
                params={'address': 'test', 'key': key}, timeout=self.timeout)
            data = r.json()
            status = data.get('status', '')
            if status == 'REQUEST_DENIED':
                err = data.get('error_message', '')
                if 'not authorized' in err.lower() or 'not activated' in err.lower():
                    return {'live': False, 'detail': f'Key valid but Geocoding not enabled: {err}'}
                return {'live': False, 'detail': err}
            if status in ('OK', 'ZERO_RESULTS'):
                return {'live': True, 'detail': 'Geocoding API is ACTIVE and billable'}
            return {'live': None, 'detail': f'Unknown status: {status}'}
        except Exception as e:
            return {'live': None, 'detail': str(e)}

    def verify_google_scope(self, key: str) -> Dict:
        """Check which Google APIs are unrestricted for this key."""
        apis = {}
        checks = [
            ('Maps Geocoding', 'https://maps.googleapis.com/maps/api/geocode/json',
             {'address': 'test', 'key': key}),
            ('Maps Directions', 'https://maps.googleapis.com/maps/api/directions/json',
             {'origin': 'A', 'destination': 'B', 'key': key}),
            ('Maps Places', 'https://maps.googleapis.com/maps/api/place/findplacefromtext/json',
             {'input': 'test', 'inputtype': 'textquery', 'key': key}),
            ('Maps Static', 'https://maps.googleapis.com/maps/api/staticmap',
             {'center': '0,0', 'zoom': '1', 'size': '1x1', 'key': key}),
            ('YouTube Data', 'https://www.googleapis.com/youtube/v3/videos',
             {'part': 'id', 'chart': 'mostPopular', 'maxResults': '1', 'key': key}),
            ('Custom Search', 'https://www.googleapis.com/customsearch/v1',
             {'q': 'test', 'key': key}),
        ]
        for name, url, params in checks:
            try:
                r = self.session.get(url, params=params, timeout=self.timeout)
                if r.status_code == 200:
                    apis[name] = 'ACTIVE ✓'
                elif r.status_code == 403:
                    try:
                        err = r.json().get('error', {}).get('message', 'Denied')
                    except Exception:
                        err = 'Denied'
                    apis[name] = f'Restricted: {err[:60]}'
                else:
                    apis[name] = f'HTTP {r.status_code}'
            except Exception:
                apis[name] = 'Error'
        return apis

    def verify_slack_token(self, token: str) -> Dict:
        """Slack auth.test — read-only identity check."""
        try:
            r = self.session.post('https://slack.com/api/auth.test',
                                  headers={'Authorization': f'Bearer {token}'},
                                  timeout=self.timeout)
            data = r.json()
            if data.get('ok'):
                return {'live': True, 'detail': f"Team: {data.get('team','?')} User: {data.get('user','?')}"}
            return {'live': False, 'detail': data.get('error', 'invalid_auth')}
        except Exception as e:
            return {'live': None, 'detail': str(e)}

    def verify_slack_webhook(self, url: str) -> Dict:
        """Check if Slack webhook is alive with empty POST."""
        try:
            r = self.session.post(url, json={'text': ''}, timeout=self.timeout)
            if r.status_code == 200 or 'no_text' in r.text:
                return {'live': True, 'detail': 'Webhook endpoint is active'}
            if r.status_code in (403, 404):
                return {'live': False, 'detail': f'HTTP {r.status_code} — revoked or invalid'}
            return {'live': None, 'detail': f'HTTP {r.status_code}'}
        except Exception as e:
            return {'live': None, 'detail': str(e)}

    def verify_github_token(self, token: str) -> Dict:
        """GitHub token check via /user endpoint."""
        try:
            r = self.session.get('https://api.github.com/user',
                                  headers={'Authorization': f'token {token}'},
                                  timeout=self.timeout)
            if r.status_code == 200:
                data = r.json()
                scopes = r.headers.get('X-OAuth-Scopes', 'N/A')
                return {'live': True, 'detail': f"User: {data.get('login','?')} Scopes: {scopes}"}
            if r.status_code == 401:
                return {'live': False, 'detail': 'Token expired or revoked'}
            return {'live': None, 'detail': f'HTTP {r.status_code}'}
        except Exception as e:
            return {'live': None, 'detail': str(e)}

    def verify_stripe_key(self, key: str) -> Dict:
        """Stripe key check via /v1/charges (read-only with limit=1)."""
        try:
            r = self.session.get('https://api.stripe.com/v1/charges',
                                  params={'limit': '1'},
                                  auth=(key, ''), timeout=self.timeout)
            if r.status_code == 200:
                return {'live': True, 'detail': 'Secret key is ACTIVE — full API access'}
            if r.status_code == 401:
                return {'live': False, 'detail': 'Key invalid or revoked'}
            return {'live': None, 'detail': f'HTTP {r.status_code}'}
        except Exception as e:
            return {'live': None, 'detail': str(e)}

    def verify_sendgrid(self, key: str) -> Dict:
        """SendGrid API key check via /v3/scopes."""
        try:
            r = self.session.get('https://api.sendgrid.com/v3/scopes',
                                  headers={'Authorization': f'Bearer {key}'},
                                  timeout=self.timeout)
            if r.status_code == 200:
                scopes = r.json().get('scopes', [])
                return {'live': True, 'detail': f'{len(scopes)} scopes authorized'}
            if r.status_code in (401, 403):
                return {'live': False, 'detail': 'Key invalid or revoked'}
            return {'live': None, 'detail': f'HTTP {r.status_code}'}
        except Exception as e:
            return {'live': None, 'detail': str(e)}

    def verify_twilio(self, sid: str) -> Dict:
        """Twilio SID format check — only confirms format (needs auth token for live)."""
        if sid.startswith('AC') and len(sid) == 34:
            return {'live': None, 'detail': 'Valid SID format (needs auth token to verify live)'}
        return {'live': False, 'detail': 'Invalid SID format'}

    def verify_mapbox(self, token: str) -> Dict:
        """Mapbox token check via geocoding API."""
        try:
            r = self.session.get(
                f'https://api.mapbox.com/geocoding/v5/mapbox.places/test.json',
                params={'access_token': token}, timeout=self.timeout)
            if r.status_code == 200:
                return {'live': True, 'detail': 'Token is ACTIVE'}
            if r.status_code in (401, 403):
                return {'live': False, 'detail': 'Token invalid or revoked'}
            return {'live': None, 'detail': f'HTTP {r.status_code}'}
        except Exception as e:
            return {'live': None, 'detail': str(e)}

    def verify_hubspot(self, key: str) -> Dict:
        """HubSpot token check via account info."""
        try:
            r = self.session.get('https://api.hubapi.com/account-info/v3/details',
                                  headers={'Authorization': f'Bearer {key}'},
                                  timeout=self.timeout)
            if r.status_code == 200:
                data = r.json()
                return {'live': True, 'detail': f"Portal: {data.get('portalId','?')}"}
            if r.status_code in (401, 403):
                return {'live': False, 'detail': 'Key invalid or revoked'}
            return {'live': None, 'detail': f'HTTP {r.status_code}'}
        except Exception as e:
            return {'live': None, 'detail': str(e)}

    # ── NEW v2.9: 5 additional verifiers ──────────────────────

    def verify_aws_sts(self, key: str) -> Dict:
        """AWS access key check via STS GetCallerIdentity (needs secret key context)."""
        if key.startswith('AKIA') and len(key) == 20:
            return {'live': None, 'detail': 'Valid AKIA format — needs secret key for STS call. '
                    'Key ID alone confirms AWS IAM user exists.'}
        return {'live': False, 'detail': 'Invalid AWS key format'}

    def verify_mailgun(self, key: str) -> Dict:
        """Mailgun API key check via domains endpoint."""
        try:
            r = self.session.get('https://api.mailgun.net/v3/domains',
                                  auth=('api', key), timeout=self.timeout)
            if r.status_code == 200:
                domains = r.json().get('items', [])
                names = [d.get('name', '?') for d in domains[:3]]
                return {'live': True, 'detail': f'{len(domains)} domains: {", ".join(names)}'}
            if r.status_code in (401, 403):
                return {'live': False, 'detail': 'Key invalid or revoked'}
            return {'live': None, 'detail': f'HTTP {r.status_code}'}
        except Exception as e:
            return {'live': None, 'detail': str(e)}

    def verify_notion(self, key: str) -> Dict:
        """Notion API key check via /v1/users/me."""
        try:
            r = self.session.get('https://api.notion.com/v1/users/me',
                                  headers={'Authorization': f'Bearer {key}',
                                           'Notion-Version': '2022-06-28'},
                                  timeout=self.timeout)
            if r.status_code == 200:
                data = r.json()
                return {'live': True, 'detail': f"Bot: {data.get('name','?')} Type: {data.get('type','?')}"}
            if r.status_code in (401, 403):
                return {'live': False, 'detail': 'Key invalid or revoked'}
            return {'live': None, 'detail': f'HTTP {r.status_code}'}
        except Exception as e:
            return {'live': None, 'detail': str(e)}

    def verify_linear(self, key: str) -> Dict:
        """Linear API key check via GraphQL /viewer."""
        try:
            r = self.session.post('https://api.linear.app/graphql',
                                   headers={'Authorization': key,
                                            'Content-Type': 'application/json'},
                                   json={'query': '{ viewer { id name email } }'},
                                   timeout=self.timeout)
            if r.status_code == 200:
                data = r.json()
                viewer = (data.get('data') or {}).get('viewer', {})
                if viewer:
                    return {'live': True, 'detail': f"User: {viewer.get('name','?')} ({viewer.get('email','?')})"}
            if r.status_code in (401, 403):
                return {'live': False, 'detail': 'Key invalid or revoked'}
            return {'live': None, 'detail': f'HTTP {r.status_code}'}
        except Exception as e:
            return {'live': None, 'detail': str(e)}

    def verify_datadog(self, token: str) -> Dict:
        """Datadog RUM/API token check via /api/v1/validate."""
        try:
            r = self.session.get('https://api.datadoghq.com/api/v1/validate',
                                  headers={'DD-API-KEY': token}, timeout=self.timeout)
            if r.status_code == 200:
                return {'live': True, 'detail': 'API key is ACTIVE'}
            if r.status_code in (401, 403):
                return {'live': False, 'detail': 'Key invalid or revoked'}
            return {'live': None, 'detail': f'HTTP {r.status_code}'}
        except Exception as e:
            return {'live': None, 'detail': str(e)}

    def verify(self, secret_type: str, value: str) -> Optional[Dict]:
        """Route to appropriate verifier based on secret type."""
        dispatch = {
            'Google API Key': lambda v: self.verify_google_maps(v),
            'Firebase Config': lambda v: self.verify_google_maps(v),
            'Slack Token': lambda v: self.verify_slack_token(v),
            'Slack Webhook': lambda v: self.verify_slack_webhook(v),
            'GitHub Token': lambda v: self.verify_github_token(v),
            'Stripe API Key': lambda v: self.verify_stripe_key(v),
            'SendGrid API Key': lambda v: self.verify_sendgrid(v),
            'Twilio Credentials': lambda v: self.verify_twilio(v),
            'Mapbox Token': lambda v: self.verify_mapbox(v),
            'HubSpot API Key': lambda v: self.verify_hubspot(v),
            'AWS Access Key': lambda v: self.verify_aws_sts(v),
            'Mailgun API Key': lambda v: self.verify_mailgun(v),
            'Notion API Key': lambda v: self.verify_notion(v),
            'Linear API Key': lambda v: self.verify_linear(v),
            'Datadog RUM Token': lambda v: self.verify_datadog(v),
        }
        fn = dispatch.get(secret_type)
        if fn:
            return fn(value)
        return None


# ═══════════════════════════════════════════════════════════════════
#  Constants
# ═══════════════════════════════════════════════════════════════════

UA_POOL = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 '
    '(KHTML, like Gecko) Version/17.2 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0',
    'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/122.0.6261.64 Mobile Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) '
    'AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
]

CDN_WAF_PATH_PATTERNS = [
    '/akam/', '/akamai/', '/_bm/', '/cdn-cgi/', '/cf-challenge',
    '/__cf_chl_', '/fingerprint/', '/captcha/', '/perimeterx/',
    '/px/', '/datadome/', '/kasada/', '/imperva/', '/_Incapsula_',
    '/distil/', '/bot-detect/',
]

KNOWN_TEST_KEYS = {
    'AIzaSyA-example-key-that-is-not-real',
    'AIzaSyBxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    'sk_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    'pk_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    'sk_test_xxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    'pk_test_xxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    'YOUR_WRITE_KEY',
    'SG.xxxxxxxxxxxxxxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    'AKIAIOSFODNN7EXAMPLE',
    'xoxb-not-a-real-token-this-will-not-work',
    'AC00000000000000000000000000000000',
    'SK00000000000000000000000000000000',
    'examplePublicKey',
    'pat-na1-00000000-0000-0000-0000-000000000000',
}

ENV_FILE_PATHS = [
    '/.env', '/.env.local', '/.env.production', '/.env.staging',
    '/.env.development', '/.env.backup', '/.env.old', '/.env.save',
    '/.env.bak', '/.env.example', '/.env.dev', '/.env.prod',
    '/.env.test', '/env', '/env.json', '/config.json',
    '/config/env.js', '/.config', '/app-config.json',
]

GRAPHQL_PATHS = [
    '/graphql', '/api/graphql', '/graphql/console', '/gql',
    '/query', '/api/query', '/graphiql', '/playground',
    '/v1/graphql', '/api/v1/graphql',
]


# ═══════════════════════════════════════════════════════════════════
#  Source Map Intelligence Analyzer — v2.9
# ═══════════════════════════════════════════════════════════════════

class SourceMapAnalyzer:
    """
    Deep source map analysis: file tree, framework detection,
    dependency mapping, comment mining for secrets.
    """

    FRAMEWORK_SIGNATURES = {
        'React': ['react-dom', 'react/jsx', 'useState', 'useEffect', 'createContext'],
        'Next.js': ['next/router', 'next/link', 'next/image', '_next/', 'getServerSideProps'],
        'Vue.js': ['vue/dist', '.vue', 'vuex', 'vue-router', 'createApp'],
        'Nuxt': ['nuxt/', '.nuxt/', 'nuxt.config'],
        'Angular': ['@angular/', 'angular/core', 'ngModule', 'zone.js'],
        'Svelte': ['svelte/', '.svelte', 'svelte/internal'],
        'Ember': ['ember/', '@ember/', 'ember-cli'],
        'Gatsby': ['gatsby/', 'gatsby-browser', 'gatsby-ssr'],
        'Remix': ['remix/', '@remix-run/'],
    }

    SECRET_COMMENT_PATTERNS = [
        (r'(?://|#|/\*)\s*(?:TODO|FIXME|HACK|XXX|BUG)\s*[:\-]?\s*(.{10,120})', 'TODO/FIXME'),
        (r'(?://|#|/\*)\s*(?:password|secret|token|key|api.?key)\s*[:\-=]\s*(.{5,120})', 'Secret Comment'),
        (r'(?://|#|/\*)\s*(?:TEMP|TEMPORARY|REMOVE|DELETE)\s*[:\-]?\s*(.{5,120})', 'Temp Note'),
    ]

    @staticmethod
    def analyze(sm_data: Dict, map_url: str) -> Dict:
        """Analyze a parsed source map JSON object."""
        sources = sm_data.get('sources', [])
        sources_content = sm_data.get('sourcesContent', [])

        intel = {
            'url': map_url,
            'total_files': len(sources),
            'total_lines': 0,
            'frameworks': [],
            'npm_packages': [],
            'file_tree': [],
            'comments': [],
            'directories': set(),
        }

        # ── File tree & directory structure ──
        pkg_set = set()
        for path in sources:
            intel['file_tree'].append(path)
            parts = path.replace('\\', '/').split('/')
            # Extract npm packages from node_modules paths
            for i, part in enumerate(parts):
                if part == 'node_modules' and i + 1 < len(parts):
                    pkg_name = parts[i + 1]
                    if pkg_name.startswith('@') and i + 2 < len(parts):
                        pkg_name = f"{pkg_name}/{parts[i + 2]}"
                    pkg_set.add(pkg_name)
            # Build directory set
            if len(parts) > 1:
                intel['directories'].add('/'.join(parts[:-1]))

        intel['npm_packages'] = sorted(pkg_set)

        # ── Framework detection ──
        all_sources_str = ' '.join(sources)
        for framework, signatures in SourceMapAnalyzer.FRAMEWORK_SIGNATURES.items():
            if any(sig in all_sources_str for sig in signatures):
                intel['frameworks'].append(framework)

        # Also check sourcesContent for framework imports
        content_sample = ''
        for i, content in enumerate(sources_content or []):
            if content and isinstance(content, str):
                intel['total_lines'] += content.count('\n') + 1
                if len(content_sample) < 50000:
                    content_sample += content[:5000]

        if content_sample:
            for framework, signatures in SourceMapAnalyzer.FRAMEWORK_SIGNATURES.items():
                if framework not in intel['frameworks']:
                    if any(sig in content_sample for sig in signatures):
                        intel['frameworks'].append(framework)

        # ── Comment mining ──
        for i, content in enumerate(sources_content or []):
            if not content or not isinstance(content, str):
                continue
            fname = sources[i] if i < len(sources) else 'unknown'
            for pattern, label in SourceMapAnalyzer.SECRET_COMMENT_PATTERNS:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    comment_text = match.group(1).strip()
                    if len(comment_text) > 5:
                        intel['comments'].append({
                            'type': label, 'text': comment_text[:200],
                            'file': fname,
                        })

        intel['directories'] = sorted(intel['directories'])[:30]
        intel['file_tree'] = intel['file_tree'][:100]  # Cap display
        return intel


# ═══════════════════════════════════════════════════════════════════
#  Supply Chain Mapper — v2.9 (NEW)
# ═══════════════════════════════════════════════════════════════════

class SupplyChainMapper:
    """
    Maps 3rd-party JS dependencies, detects vulnerable library versions,
    checks SRI integrity, and builds a supply chain risk inventory.
    """

    # Known vulnerable library versions — v3.0: 50+ entries (was 10 in v2.9)
    # Format: (vuln_below_version, severity, CVE/description)
    VULNERABLE_LIBS = {
        'jquery': [
            ('3.5.0', 'MEDIUM', 'XSS via htmlPrefilter — CVE-2020-11022/11023'),
            ('3.0.0', 'HIGH', 'Selector XSS — CVE-2015-9251, CVE-2019-11358'),
            ('2.2.0', 'HIGH', 'XSS + prototype pollution — multiple CVEs'),
            ('1.12.0', 'CRITICAL', 'Arbitrary code execution — CVE-2015-9251'),
        ],
        'jquery-ui': [
            ('1.13.2', 'MEDIUM', 'XSS in dialog/tooltip — CVE-2022-31160'),
            ('1.12.0', 'HIGH', 'XSS via .position() — CVE-2021-41184'),
        ],
        'angular': [
            ('1.6.0', 'HIGH', 'Sandbox escape / XSS — CVE-2020-7676'),
            ('1.8.0', 'MEDIUM', 'Prototype pollution — CVE-2022-25869'),
        ],
        'angularjs': [
            ('1.8.0', 'MEDIUM', 'Prototype pollution / ReDoS'),
        ],
        'lodash': [
            ('4.17.21', 'HIGH', 'Prototype pollution — CVE-2021-23337'),
            ('4.17.12', 'CRITICAL', 'Prototype pollution — CVE-2019-10744'),
            ('4.17.5', 'HIGH', 'Prototype pollution — CVE-2018-16487'),
        ],
        'underscore': [
            ('1.13.6', 'MEDIUM', 'Code injection — CVE-2021-23358'),
            ('1.12.1', 'HIGH', 'Template injection — CVE-2021-23358'),
        ],
        'bootstrap': [
            ('5.2.0', 'LOW', 'Minor XSS in data-bs-* attributes'),
            ('4.3.1', 'MEDIUM', 'XSS via data-attributes — CVE-2019-8331'),
            ('3.4.0', 'MEDIUM', 'XSS in tooltip/popover — CVE-2018-14040'),
            ('3.0.0', 'HIGH', 'Multiple XSS — CVE-2016-10735'),
        ],
        'moment': [
            ('2.29.4', 'MEDIUM', 'ReDoS — CVE-2022-31129'),
            ('2.19.3', 'HIGH', 'Path traversal — CVE-2017-18214'),
        ],
        'axios': [
            ('1.6.0', 'HIGH', 'CSRF/SSRF bypass — CVE-2023-45857'),
            ('1.3.2', 'HIGH', 'SSRF via proxy — CVE-2023-45857'),
            ('0.21.1', 'MEDIUM', 'ReDoS in content-type parsing'),
        ],
        'dompurify': [
            ('3.0.6', 'HIGH', 'mXSS bypass — CVE-2023-48219'),
            ('2.4.1', 'HIGH', 'XSS bypass — CVE-2023-23631'),
            ('2.0.0', 'CRITICAL', 'Multiple bypass vectors'),
        ],
        'handlebars': [
            ('4.7.7', 'HIGH', 'Prototype pollution — CVE-2021-23369'),
            ('4.7.6', 'CRITICAL', 'RCE via template — CVE-2021-23383'),
        ],
        'vue': [
            ('3.2.47', 'LOW', 'Potential XSS in SSR hydration'),
            ('2.7.14', 'LOW', 'XSS via v-html directive'),
        ],
        'react-dom': [
            ('16.13.0', 'LOW', 'XSS via dangerouslySetInnerHTML edge case'),
        ],
        'express': [
            ('4.17.3', 'MEDIUM', 'Open redirect — CVE-2022-24999'),
        ],
        'next': [
            ('13.4.6', 'HIGH', 'SSRF via Server Actions — CVE-2023-46298'),
            ('12.3.0', 'MEDIUM', 'Open redirect — CVE-2023-27490'),
        ],
        'socket.io': [
            ('4.6.2', 'MEDIUM', 'DoS via malformed packet — CVE-2023-32695'),
            ('2.4.0', 'HIGH', 'Unauthorized access — CVE-2020-36049'),
        ],
        'marked': [
            ('4.0.10', 'HIGH', 'ReDoS — CVE-2022-21680/21681'),
            ('2.0.0', 'CRITICAL', 'XSS via HTML injection'),
        ],
        'highlight.js': [
            ('10.4.1', 'MEDIUM', 'Prototype pollution — CVE-2020-26237'),
        ],
        'chart.js': [
            ('2.9.4', 'LOW', 'Prototype pollution via config merge'),
        ],
        'tinymce': [
            ('5.10.0', 'HIGH', 'Stored XSS — CVE-2022-23494'),
        ],
        'ckeditor': [
            ('4.16.0', 'HIGH', 'XSS — CVE-2021-32808/32809'),
        ],
        'quill': [
            ('1.3.7', 'MEDIUM', 'XSS via paste handler — CVE-2021-3163'),
        ],
        'sweetalert2': [
            ('11.4.8', 'MEDIUM', 'XSS via HTML content'),
        ],
        'select2': [
            ('4.0.13', 'MEDIUM', 'XSS via title attribute — CVE-2022-40897'),
        ],
        'datatables': [
            ('1.10.0', 'MEDIUM', 'XSS via data rendering — CVE-2020-28458'),
        ],
        'd3': [
            ('5.0.0', 'LOW', 'Prototype pollution edge case'),
        ],
        'three': [
            ('0.125.0', 'LOW', 'Potential SSRF via loader URLs'),
        ],
        'lottie-web': [
            ('5.7.4', 'MEDIUM', 'XSS via SVG animation — CVE-2022-1466'),
        ],
        'video.js': [
            ('7.17.0', 'MEDIUM', 'XSS via text tracks — CVE-2021-43257'),
        ],
        'plyr': [
            ('3.6.9', 'MEDIUM', 'XSS via captions — CVE-2021-23369'),
        ],
        'backbone': [
            ('1.4.0', 'LOW', 'Model injection via set()'),
        ],
        'ember': [
            ('3.28.0', 'MEDIUM', 'Prototype pollution — CVE-2022-0235'),
        ],
        'polymer': [
            ('3.0.0', 'LOW', 'DOM XSS via data binding'),
        ],
        'knockout': [
            ('3.5.0', 'MEDIUM', 'Template injection — CVE-2019-14862'),
        ],
        'mustache': [
            ('4.2.0', 'LOW', 'Potential template injection'),
        ],
        'ejs': [
            ('3.1.7', 'CRITICAL', 'RCE via template injection — CVE-2022-29078'),
        ],
        'pug': [
            ('3.0.1', 'HIGH', 'Code injection via attributes — CVE-2021-21353'),
        ],
        'sanitize-html': [
            ('2.3.2', 'HIGH', 'XSS bypass — CVE-2021-26539'),
        ],
        'ua-parser-js': [
            ('0.7.31', 'CRITICAL', 'Supply chain attack — CVE-2021-44906'),
        ],
        'minimist': [
            ('1.2.6', 'CRITICAL', 'Prototype pollution — CVE-2021-44906'),
        ],
        'node-fetch': [
            ('2.6.7', 'HIGH', 'SSRF bypass — CVE-2022-0235'),
        ],
        'glob-parent': [
            ('5.1.2', 'HIGH', 'ReDoS — CVE-2020-28469'),
        ],
        'trim-newlines': [
            ('3.0.1', 'HIGH', 'ReDoS — CVE-2021-33623'),
        ],
        'json5': [
            ('2.2.2', 'MEDIUM', 'Prototype pollution — CVE-2022-46175'),
        ],
        'got': [
            ('11.8.5', 'MEDIUM', 'Open redirect — CVE-2022-33987'),
        ],
        'terser': [
            ('5.14.2', 'MEDIUM', 'ReDoS — CVE-2022-25858'),
        ],
    }

    # CDN exploit correlation — v3.0
    CDN_RISK_INTEL = {
        'cdn.jsdelivr.net': {
            'risk': 'MEDIUM',
            'notes': 'jsdelivr has served compromised packages (ua-parser-js, '
                     'colors, faker). Packages pulled directly from npm.',
        },
        'unpkg.com': {
            'risk': 'MEDIUM',
            'notes': 'unpkg mirrors npm — inherits supply chain risks. '
                     'No additional vetting.',
        },
        'cdnjs.cloudflare.com': {
            'risk': 'LOW',
            'notes': 'Cloudflare-hosted, manually curated. Lower supply chain risk.',
        },
        'cdn.bootcdn.net': {
            'risk': 'HIGH',
            'notes': 'Chinese CDN — potential MitM, HTTPS enforcement varies.',
        },
        'lib.baomitu.com': {
            'risk': 'HIGH',
            'notes': 'Regional CDN with limited security auditing.',
        },
        'ajax.aspnetcdn.com': {
            'risk': 'LOW',
            'notes': 'Microsoft-hosted CDN, well-maintained.',
        },
        'code.jquery.com': {
            'risk': 'LOW',
            'notes': 'Official jQuery CDN, MaxCDN/StackPath backed.',
        },
    }

    # CDN URL patterns to extract library name + version
    CDN_PATTERNS = [
        # cdnjs: /ajax/libs/{lib}/{version}/{file}
        r'cdnjs\.cloudflare\.com/ajax/libs/([a-z0-9\.\-]+)/([0-9][0-9a-z\.\-]*)',
        # unpkg: /package@version/file
        r'unpkg\.com/([a-z0-9@/\.\-]+)@([0-9][0-9a-z\.\-]*)',
        # jsdelivr: /npm/package@version/file
        r'cdn\.jsdelivr\.net/npm/([a-z0-9@/\.\-]+)@([0-9][0-9a-z\.\-]*)',
        # Google hosted: /ajax/libs/{lib}/{version}/{file}
        r'ajax\.googleapis\.com/ajax/libs/([a-z0-9\.\-]+)/([0-9][0-9a-z\.\-]*)',
        # generic: /lib-name/version/ or /lib-name.min.js
        r'/([a-z][a-z0-9\-]{1,30})[/\.\-]([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)',
    ]

    # Common inline version patterns in JS content
    INLINE_VERSION_PATTERNS = [
        r'(?:jQuery|jquery)\s+v?([0-9]+\.[0-9]+\.[0-9]+)',
        r'Bootstrap\s+v?([0-9]+\.[0-9]+\.[0-9]+)',
        r'Lodash\s+v?([0-9]+\.[0-9]+\.[0-9]+)',
        r'Angular(?:JS)?\s+v?([0-9]+\.[0-9]+\.[0-9]+)',
        r'Vue\.js\s+v?([0-9]+\.[0-9]+\.[0-9]+)',
        r'React\s+v?([0-9]+\.[0-9]+\.[0-9]+)',
    ]

    def __init__(self):
        self.inventory: List[Dict] = []
        self.vulnerabilities: List[Dict] = []
        self.sri_issues: List[Dict] = []
        self.cdn_origins: Set[str] = set()
        self.npm_packages: Set[str] = set()

    def analyze_script_tags(self, html: str, page_url: str):
        """Extract all <script> tags and analyze for supply chain risks."""
        for match in re.finditer(
            r'<script[^>]*\bsrc\s*=\s*["\']([^"\']+)["\']([^>]*)>', html, re.I
        ):
            src = match.group(1)
            attrs = match.group(2)
            full_url = urljoin(page_url, src)
            parsed = urlparse(full_url)

            entry = {
                'url': full_url,
                'host': parsed.netloc,
                'is_external': parsed.netloc != urlparse(page_url).netloc,
                'has_sri': 'integrity=' in attrs.lower(),
                'has_crossorigin': 'crossorigin' in attrs.lower(),
                'library': None,
                'version': None,
                'vulnerabilities': [],
            }

            # Track CDN origins
            if entry['is_external']:
                self.cdn_origins.add(parsed.netloc)
                # v3.0: CDN risk correlation
                cdn_intel = self.CDN_RISK_INTEL.get(parsed.netloc)
                if cdn_intel:
                    entry['cdn_risk'] = cdn_intel['risk']
                    entry['cdn_notes'] = cdn_intel['notes']

            # Extract library and version from URL
            lib_name, lib_version = self._extract_lib_version(full_url)
            if lib_name:
                entry['library'] = lib_name
                entry['version'] = lib_version

                # Check vulnerabilities
                vulns = self._check_vulns(lib_name, lib_version)
                if vulns:
                    entry['vulnerabilities'] = vulns
                    for v in vulns:
                        self.vulnerabilities.append({
                            'library': lib_name, 'version': lib_version,
                            'severity': v['severity'], 'detail': v['detail'],
                            'source': page_url,
                        })

            # SRI check for external scripts (dedup by URL)
            if entry['is_external'] and not entry['has_sri']:
                if not any(s['url'] == full_url for s in self.sri_issues):
                    self.sri_issues.append({
                        'url': full_url, 'host': parsed.netloc,
                        'source': page_url,
                    })

            # Dedup by URL
            if not any(e['url'] == entry['url'] for e in self.inventory):
                self.inventory.append(entry)

    def analyze_js_content(self, content: str, js_url: str):
        """Detect library versions from inline JS comments/headers."""
        header = content[:3000]
        lib_map = {
            'jQuery': 'jquery', 'Bootstrap': 'bootstrap', 'Lodash': 'lodash',
            'Angular': 'angular', 'Vue.js': 'vue', 'React': 'react-dom',
        }
        for pattern in self.INLINE_VERSION_PATTERNS:
            m = re.search(pattern, header)
            if m:
                version = m.group(1)
                for display_name, lib_key in lib_map.items():
                    if display_name.lower() in pattern.lower():
                        vulns = self._check_vulns(lib_key, version)
                        # Only add if not already tracked
                        if not any(e.get('library') == lib_key and e.get('url') == js_url
                                   for e in self.inventory):
                            entry = {
                                'url': js_url, 'host': urlparse(js_url).netloc,
                                'is_external': False, 'has_sri': False,
                                'has_crossorigin': False,
                                'library': lib_key, 'version': version,
                                'vulnerabilities': vulns,
                                'detected_from': 'inline_header',
                            }
                            self.inventory.append(entry)
                            if vulns:
                                for v in vulns:
                                    self.vulnerabilities.append({
                                        'library': lib_key, 'version': version,
                                        'severity': v['severity'], 'detail': v['detail'],
                                        'source': js_url,
                                    })
                        break

    def add_npm_packages(self, packages: List[str]):
        """Add npm packages discovered from source maps."""
        self.npm_packages.update(packages)

    def _extract_lib_version(self, url: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract library name and version from CDN URL."""
        for pattern in self.CDN_PATTERNS:
            m = re.search(pattern, url, re.I)
            if m:
                lib = m.group(1).split('/')[-1].lower().rstrip('.')
                ver = m.group(2).rstrip('.')
                return lib, ver
        return None, None

    def _check_vulns(self, lib_name: str, version: str) -> List[Dict]:
        """Check if a library version has known vulnerabilities."""
        if not version:
            return []
        vulns_list = self.VULNERABLE_LIBS.get(lib_name.lower(), [])
        found = []
        for vuln_below, severity, detail in vulns_list:
            if self._version_lt(version, vuln_below):
                found.append({'severity': severity, 'detail': detail,
                              'fixed_in': vuln_below})
        return found

    @staticmethod
    def _version_lt(a: str, b: str) -> bool:
        """Compare version strings: return True if a < b."""
        try:
            def _parts(v):
                return [int(x) for x in re.findall(r'\d+', v)][:4]
            pa, pb = _parts(a), _parts(b)
            # Pad to same length
            while len(pa) < len(pb): pa.append(0)
            while len(pb) < len(pa): pb.append(0)
            return pa < pb
        except (ValueError, IndexError):
            return False

    def get_summary(self) -> Dict:
        """Return supply chain analysis summary."""
        return {
            'total_scripts': len(self.inventory),
            'external_scripts': sum(1 for e in self.inventory if e['is_external']),
            'cdn_origins': sorted(self.cdn_origins),
            'libraries_detected': sum(1 for e in self.inventory if e.get('library')),
            'vulnerable_libraries': len(self.vulnerabilities),
            'sri_missing': len(self.sri_issues),
            'npm_packages_from_sourcemaps': sorted(self.npm_packages),
            'inventory': self.inventory,
            'vulnerabilities': self.vulnerabilities,
            'sri_issues': self.sri_issues,
        }


# ═══════════════════════════════════════════════════════════════════
#  Security Headers Auditor — v3.0 (SRI/COOP/COEP/CSP)
# ═══════════════════════════════════════════════════════════════════

class SecurityHeadersAuditor:
    """Audit security-critical HTTP headers for misconfigurations."""

    CRITICAL_HEADERS = {
        'Content-Security-Policy': {
            'severity': 'HIGH',
            'detail': 'No CSP — XSS and data injection attacks possible',
        },
        'Strict-Transport-Security': {
            'severity': 'MEDIUM',
            'detail': 'No HSTS — vulnerable to SSL stripping',
        },
        'X-Content-Type-Options': {
            'severity': 'LOW',
            'detail': 'No nosniff — MIME-type confusion attacks',
        },
        'X-Frame-Options': {
            'severity': 'MEDIUM',
            'detail': 'No clickjacking protection',
        },
        'Cross-Origin-Opener-Policy': {
            'severity': 'MEDIUM',
            'detail': 'No COOP — cross-origin window attacks (Spectre)',
        },
        'Cross-Origin-Embedder-Policy': {
            'severity': 'MEDIUM',
            'detail': 'No COEP — cross-origin data leakage via SharedArrayBuffer',
        },
        'Cross-Origin-Resource-Policy': {
            'severity': 'LOW',
            'detail': 'No CORP — resources can be embedded by any origin',
        },
        'Permissions-Policy': {
            'severity': 'LOW',
            'detail': 'No Permissions-Policy — browser APIs unrestricted',
        },
    }

    CSP_DANGEROUS = [
        ("'unsafe-inline'", 'HIGH', 'Allows inline scripts (XSS)'),
        ("'unsafe-eval'", 'HIGH', 'Allows eval() (code injection)'),
        ('data:', 'MEDIUM', 'Allows data: URIs (XSS bypass)'),
        ('*', 'HIGH', 'Wildcard source (no protection)'),
        ('http:', 'MEDIUM', 'Allows HTTP sources (MitM)'),
    ]

    def __init__(self):
        self.findings: List[Dict] = []

    def audit(self, response_headers: Dict, url: str) -> List[Dict]:
        """Audit response headers and return findings."""
        headers_lower = {k.lower(): v for k, v in response_headers.items()}

        for header_name, info in self.CRITICAL_HEADERS.items():
            if header_name.lower() not in headers_lower:
                self.findings.append({
                    'header': header_name, 'issue': 'MISSING',
                    'severity': info['severity'], 'detail': info['detail'],
                    'url': url,
                })

        # CSP deep analysis
        csp = headers_lower.get('content-security-policy', '')
        if csp:
            for pattern, severity, detail in self.CSP_DANGEROUS:
                if pattern in csp:
                    self.findings.append({
                        'header': 'CSP', 'issue': f'DANGEROUS: {pattern}',
                        'severity': severity, 'detail': detail, 'url': url,
                    })
            # Check for report-only (not enforced)
            if 'content-security-policy-report-only' in headers_lower:
                self.findings.append({
                    'header': 'CSP', 'issue': 'REPORT-ONLY',
                    'severity': 'MEDIUM', 'detail': 'CSP is report-only, not enforced',
                    'url': url,
                })

        return self.findings


# ═══════════════════════════════════════════════════════════════════
#  False Positive Auto-Filter — v3.0
# ═══════════════════════════════════════════════════════════════════

class FalsePositiveFilter:
    """Context-aware false positive elimination with entropy thresholds."""

    # File path patterns that indicate test/example content
    TEST_FILE_PATTERNS = [
        r'(?:__)?test(?:s)?(?:__)?[/\\]', r'\.test\.[jt]sx?$',
        r'\.spec\.[jt]sx?$', r'\.stories\.[jt]sx?$',
        r'mock[/\\]', r'fixture[/\\]', r'__mocks__[/\\]',
        r'example[s]?[/\\]', r'sample[s]?[/\\]', r'demo[/\\]',
        r'storybook[/\\]', r'cypress[/\\]', r'e2e[/\\]',
    ]

    # Value patterns that are almost certainly placeholders
    PLACEHOLDER_PATTERNS = [
        r'^[xX]{8,}$',                    # xxxxxxxx
        r'^\*{6,}$',                       # ********
        r'^<.+>$',                         # <your_key>
        r'^\[.+\]$',                       # [API_KEY]
        r'^your[_\-]',                     # your_key
        r'^my[_\-]',                       # my_secret
        r'^CHANGE[_\-]?ME',               # CHANGEME
        r'^TODO',                          # TODO
        r'^REPLACE',                       # REPLACE_ME
        r'^INSERT',                        # INSERT_HERE
        r'^\$\{',                          # ${ENV_VAR}
        r'^process\.env\.',               # process.env.KEY
        r'^ENV\[',                         # ENV['KEY']
        r'^os\.environ',                  # os.environ['KEY']
        r'^env\(',                         # env('KEY')
        r'^%[A-Z_]+%$',                   # %ENV_VAR%
        r'^0{8,}$',                        # 00000000
        r'^1{8,}$',                        # 11111111
        r'^(?:test|demo|fake|dummy|sample|example)',
        r'(?:abc|xyz)(?:123|456|789)$',   # abc123
    ]

    # Known documentation/tutorial domains
    DOC_PATTERNS = [
        'documentation', 'readme', 'changelog', 'license',
        'contributing', 'authors', 'tutorial', 'getting-started',
    ]

    # ── MINIMUM ENTROPY THRESHOLDS PER SECRET TYPE ──
    # Below this entropy, it's almost certainly a false positive.
    # Higher threshold = stricter filtering.
    MIN_ENTROPY_THRESHOLDS = {
        'Hardcoded Password':       3.0,   # "password123" = ~3.0
        'High-Entropy Secret':      3.5,   # must actually be high entropy
        'Generic API Key':          3.0,
        'Generic Secret':           3.0,
        'Google API Key':           3.5,
        'AWS Access Key':           3.5,
        'Stripe API Key':           3.5,
        'Slack Token':              3.0,
        'GitHub Token':             3.5,
        'SendGrid API Key':         3.5,
        'Mapbox Token':             3.0,
        'JWT Token':                2.0,   # JWTs can be low entropy (short payloads)
        'Private Key':              1.0,   # PEM headers are low entropy but valid
        'Database Connection String': 2.0, # URIs can be low entropy
        'Slack Webhook':            2.0,   # URLs are structured
        'AWS S3 Bucket':            1.5,   # Bucket names are low entropy
    }
    DEFAULT_MIN_ENTROPY = 2.5  # for types not listed above

    # ── COMMON FALSE POSITIVE VALUES ──
    # Known values that appear in thousands of JS bundles (minified vars, defaults)
    KNOWN_FP_VALUES = {
        'undefined', 'null', 'true', 'false', 'none',
        'password', 'secret', 'token', 'apikey', 'api_key',
        'default', 'changeme', 'xxxxxxxx', 'placeholder',
        'not_a_real_key', 'sk_test_', 'pk_test_',
    }

    @staticmethod
    def is_false_positive(value: str, source: str, secret_type: str) -> Tuple[bool, str]:
        """Returns (is_fp, reason) tuple with entropy-aware filtering."""
        vl = value.lower().strip()
        src_lower = source.lower()

        # ── ReCAPTCHA site keys are PUBLIC by design (not secrets) ──
        if secret_type == 'Recaptcha Site Key':
            # Only flag if from third-party JS (not target's own recaptcha setup)
            if any(tp in src_lower for tp in [
                'googlesyndication.com', 'mgid.com', 'doubleclick.net',
                'btloader.com', 'adservice.google', 'googletagmanager.com',
            ]):
                return True, 'ReCAPTCHA key from third-party ad/analytics script (not target-owned)'
            # Check if it's actually a base64 fragment misidentified as recaptcha
            if not value.startswith('6L'):
                return True, 'Not a real ReCAPTCHA key (missing 6L prefix)'

        # ── Ad network base64 blobs misidentified as tokens ──
        ad_network_sources = [
            'pagead2.googlesyndication.com', 'googlesyndication.com',
            'securepubads.g.doubleclick.net', 'doubleclick.net',
            'jsc.mgid.com', 'mgid.com', 'btloader.com',
            'adservice.google.com', 'googleadservices.com',
        ]
        if any(ad in src_lower for ad in ad_network_sources):
            # Only allow highly specific tokens (Google API Key with AIza prefix)
            if secret_type not in ('Google API Key',) or not value.startswith('AIza'):
                return True, f'Token from ad network JS (not target secret): {secret_type}'

        # Check placeholder patterns
        for pattern in FalsePositiveFilter.PLACEHOLDER_PATTERNS:
            if re.match(pattern, value, re.IGNORECASE):
                return True, f'Placeholder pattern: {pattern}'

        # Check if source is test/example file
        for pattern in FalsePositiveFilter.TEST_FILE_PATTERNS:
            if re.search(pattern, source, re.IGNORECASE):
                return True, f'Test/example file: {source}'

        # Check documentation sources
        for doc in FalsePositiveFilter.DOC_PATTERNS:
            if doc in src_lower:
                return True, f'Documentation source: {doc}'

        # Repetitive characters (low entropy but matched regex)
        if len(set(vl)) <= 3 and len(vl) > 8:
            return True, 'Repetitive characters'

        # Common minified variable names that match patterns
        if secret_type == 'High-Entropy Secret' and len(value) < 24:
            if re.match(r'^[a-z]{1,3}\d{1,3}[a-z]{1,3}\d{1,3}$', value):
                return True, 'Likely minified variable name'

        # ── Known false positive values ──
        if vl in FalsePositiveFilter.KNOWN_FP_VALUES:
            return True, f'Known FP value: {vl}'

        # ── Entropy threshold check ──
        entropy = shannon_entropy(value)
        min_threshold = FalsePositiveFilter.MIN_ENTROPY_THRESHOLDS.get(
            secret_type, FalsePositiveFilter.DEFAULT_MIN_ENTROPY
        )
        if entropy < min_threshold:
            return True, (f'Entropy too low: {entropy:.1f} < {min_threshold} '
                          f'threshold for {secret_type}')

        # ── Source from external CDN / third-party (not target's secret) ──
        external_cdn_patterns = [
            r'cdnjs\.cloudflare\.com', r'cdn\.jsdelivr\.net', r'unpkg\.com',
            r'ajax\.googleapis\.com', r'cdn\.shopify\.com', r'assets\.shopify\.com',
            r'polyfill\.io', r'cdn\.polyfill\.io', r'stackpath\.bootstrapcdn',
            r'maxcdn\.bootstrapcdn', r'code\.jquery\.com',
        ]
        for cdn_pattern in external_cdn_patterns:
            if re.search(cdn_pattern, source, re.IGNORECASE):
                if secret_type in ('High-Entropy Secret', 'Hardcoded Password', 'Generic API Key'):
                    return True, f'Generic secret from external CDN: {cdn_pattern}'

        # ── Too short for secret type ──
        min_lengths = {
            'AWS Access Key': 16, 'GitHub Token': 20, 'Stripe API Key': 20,
            'Google API Key': 30, 'SendGrid API Key': 30, 'High-Entropy Secret': 16,
        }
        min_len = min_lengths.get(secret_type)
        if min_len and len(value) < min_len:
            return True, f'Too short for {secret_type}: {len(value)} < {min_len}'

        return False, ''

    @staticmethod
    def filter_findings(findings: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
        """Filter findings, return (kept, removed) tuple."""
        kept, removed = [], []
        seen_hashes = set()
        for f in findings:
            is_fp, reason = FalsePositiveFilter.is_false_positive(
                f['value'], f['source'], f['type'])
            if is_fp:
                f['fp_reason'] = reason
                removed.append(f)
            else:
                # Deduplicate by value hash
                val_hash = hashlib.sha256(f['value'].encode()).hexdigest()[:16]
                if val_hash in seen_hashes:
                    f['fp_reason'] = 'Duplicate value'
                    removed.append(f)
                else:
                    seen_hashes.add(val_hash)
                    kept.append(f)
        return kept, removed


# ═══════════════════════════════════════════════════════════════════
#  Accuracy Engine v5.0 — 8 Intelligence Upgrades
# ═══════════════════════════════════════════════════════════════════

class AccuracyEngine:
    """
    Post-processing accuracy layer. Runs AFTER initial detection
    and BEFORE final output to maximize signal and minimize noise.

    8 Systems:
    1. Context window analysis    — surrounding code inspection
    2. Correlation dedup          — intelligent cross-source dedup
    3. Variable name scoring      — confidence from assignment context
    4. Dead code detection        — comments, disabled blocks
    5. Multi-file correlation     — cross-page confidence boost
    6. Base64/encoded detection   — decode-then-scan pre-pass
    7. JS deobfuscation           — basic beautify before scanning
    8. Confidence scoring (0-100) — unified numeric score
    """

    # ─── [1] CONTEXT WINDOW ANALYSIS ───
    # Patterns that indicate a finding is in dead/example/test context

    DEAD_CONTEXT_PATTERNS = [
        # Comments
        (r'(?:^|\n)\s*(?://|#|/\*)\s*.*{VALUE}', 'in_comment', -30),
        # Disabled / example code
        (r'if\s*\(\s*false\s*\)', 'if_false_block', -40),
        (r'if\s*\(\s*0\s*\)', 'if_zero_block', -40),
        (r'(?://|#)\s*(?:TODO|FIXME|HACK|XXX|OLD|DEPRECATED|DISABLED)', 'todo_comment', -20),
        (r'(?://|#)\s*(?:old|previous|deprecated|unused|remove|delete)', 'deprecated_comment', -20),
        # Console / debug
        (r'console\.\w+\s*\(', 'console_log', -15),
        (r'print\s*\(', 'print_statement', -10),
        (r'(?:debug|log|trace|warn)\s*[(\[]', 'debug_output', -10),
        # Documentation / examples
        (r'@example', 'doc_example', -35),
        (r'@param\s', 'doc_param', -25),
        (r'README|EXAMPLE|SAMPLE|TUTORIAL', 'doc_source', -30),
    ]

    # Patterns that BOOST confidence
    BOOST_CONTEXT_PATTERNS = [
        # Direct assignment in config/init
        (r'(?:config|settings|env|init|setup|credentials)\s*[.=\[]', 'config_assignment', +15),
        # Fetch / HTTP call with the key
        (r'(?:fetch|axios|request|http|xhr)\s*[(\.]', 'http_usage', +20),
        # Authorization header construction
        (r'(?:Authorization|Bearer|X-API-Key|api[_-]?key)\s*[:\=]', 'auth_header', +25),
        # Direct key usage
        (r'(?:headers|params|body|payload|data)\s*[\[.{]', 'request_params', +10),
        # .env file or config file
        (r'\.env(?:\.|$)', 'dotenv_source', +20),
    ]

    # ─── [3] VARIABLE NAME SCORING ───
    # Variable names that strongly suggest a real secret

    HIGH_CONFIDENCE_VARNAMES = {
        # Exact matches or prefixes that indicate real secrets
        'stripe_secret_key': 30, 'stripe_api_key': 30, 'sk_live': 25,
        'aws_secret_access_key': 30, 'aws_access_key_id': 30,
        'database_url': 25, 'db_password': 25, 'db_pass': 25,
        'api_secret': 25, 'client_secret': 25, 'private_key': 25,
        'secret_key': 20, 'api_key': 15, 'auth_token': 20,
        'access_token': 20, 'refresh_token': 20,
        'sendgrid_api_key': 25, 'twilio_auth_token': 25,
        'slack_token': 25, 'slack_webhook': 20,
        'firebase_api_key': 20, 'openai_api_key': 25,
        'anthropic_api_key': 25, 'github_token': 25,
        'gitlab_token': 25, 'heroku_api_key': 25,
        'mailgun_api_key': 25, 'datadog_api_key': 20,
        'sentry_dsn': 15, 'encryption_key': 25,
        'signing_key': 25, 'jwt_secret': 25,
        'password': 10, 'passwd': 10, 'pwd': 8,
    }

    LOW_CONFIDENCE_VARNAMES = {
        # Variable names that suggest placeholders or config templates
        'example': -20, 'sample': -20, 'demo': -20, 'test': -15,
        'mock': -20, 'fake': -25, 'dummy': -25, 'placeholder': -30,
        'template': -20, 'default': -10, 'fallback': -10,
        'temp': -10, 'tmp': -10, 'unused': -20, 'old': -15,
    }

    # ─── [4] DEAD CODE PATTERNS ───

    COMMENT_LINE_PATTERNS = [
        r'^\s*//',           # JS single-line comment
        r'^\s*#',            # Python/bash comment
        r'^\s*/\*',          # C-style block comment start
        r'\*/',              # C-style block comment end
        r'^\s*\*\s',         # Inside block comment
        r'<!--',             # HTML comment
        r'^\s*\'\'\' ',      # Python docstring
        r'^\s*"""',          # Python docstring
    ]

    # ─── [6] BASE64 ENCODED SECRET PATTERNS ───

    B64_SECRET_INDICATORS = [
        # Patterns that suggest base64-encoded secrets
        r'(?:secret|key|token|password|credential|auth).*base64',
        r'atob\s*\(\s*["\']([A-Za-z0-9+/=]{20,})["\']',
        r'btoa\s*\(\s*["\']',
        r'Buffer\.from\s*\(\s*["\']([A-Za-z0-9+/=]{20,})["\'].*base64',
        r'base64[_\-]?(?:decode|encoded?)\s*[:(]\s*["\']([A-Za-z0-9+/=]{20,})["\']',
        r'(?:data|config|secret|key)\s*[=:]\s*["\']([A-Za-z0-9+/=]{40,})["\']',
    ]

    # Known secret prefixes that might appear inside base64
    B64_DECODED_SIGNATURES = [
        'sk_live_', 'sk_test_', 'pk_live_', 'pk_test_',
        'AKIA', 'ABIA', 'ACCA', 'ASIA',
        'ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_',
        'xoxb-', 'xoxp-', 'xoxa-', 'xoxr-',
        'SG.', 'key-', 'sq0atp-', 'sq0csp-',
        'eyJ',  # JWT prefix
    ]

    def __init__(self):
        self.cross_file_values = defaultdict(list)  # value_hash -> [sources]
        self.processed_count = 0
        self.upgrades_applied = defaultdict(int)

        # ── Upgrade 1: Calibration Mode ──
        self.calibration_log = []  # Stores all scored findings for analysis
        self.calibration_file = os.path.join(str(Path.home()), ".arcanis", "calibration.json")

        # ── Upgrade 2: Dynamic Weight Adjustment ──
        self.environment_profile = 'default'  # default, cloud, ci_cd, enterprise
        self.weight_overrides = {}

        # ── Upgrade 3: Trust Decay ──
        self.trust_decay_enabled = True
        self.known_secrets_db = os.path.join(str(Path.home()), ".arcanis", "known_secrets.json")

        # ── Upgrade 4: Cross-Repo Leak Correlation ──
        self.cross_repo_db = os.path.join(str(Path.home()), ".arcanis", "cross_repo.json")
        self.current_target = None

    # ═══════════════════════════════════════════
    #  [1] Context Window Analysis
    # ═══════════════════════════════════════════

    @staticmethod
    def analyze_context(value: str, content: str, match_start: int) -> dict:
        """Analyze the code context around a match. Returns scoring adjustments."""
        result = {
            'adjustments': [],
            'score_delta': 0,
            'is_dead_code': False,
            'context_type': 'live_code',
        }

        # Extract wider context window (5 lines around match)
        ctx_start = content.rfind('\n', 0, max(0, match_start - 500))
        ctx_end = content.find('\n', min(len(content), match_start + 500))
        if ctx_start < 0: ctx_start = 0
        if ctx_end < 0: ctx_end = len(content)
        window = content[ctx_start:ctx_end]

        # Extract the specific line containing the match
        line_start = content.rfind('\n', 0, match_start) + 1
        line_end = content.find('\n', match_start)
        if line_end < 0: line_end = len(content)
        match_line = content[line_start:line_end]

        # Check for dead/example context (penalties)
        for pattern, label, delta in AccuracyEngine.DEAD_CONTEXT_PATTERNS:
            pat = pattern.replace('{VALUE}', re.escape(value[:20]))
            if re.search(pat, window, re.IGNORECASE):
                result['adjustments'].append((label, delta))
                result['score_delta'] += delta

        # Check for boost context
        for pattern, label, delta in AccuracyEngine.BOOST_CONTEXT_PATTERNS:
            if re.search(pattern, window, re.IGNORECASE):
                result['adjustments'].append((label, delta))
                result['score_delta'] += delta

        # [4] Dead code detection — check if the line itself is a comment
        for comment_pat in AccuracyEngine.COMMENT_LINE_PATTERNS:
            if re.match(comment_pat, match_line):
                result['is_dead_code'] = True
                result['context_type'] = 'commented_out'
                result['adjustments'].append(('line_is_comment', -35))
                result['score_delta'] -= 35
                break

        # Check for block comment wrapping
        pre_content = content[max(0, match_start - 200):match_start]
        if '/*' in pre_content and '*/' not in pre_content:
            result['is_dead_code'] = True
            result['context_type'] = 'block_comment'
            result['adjustments'].append(('inside_block_comment', -40))
            result['score_delta'] -= 40

        # Check for HTML comment wrapping
        if '<!--' in pre_content and '-->' not in pre_content:
            result['is_dead_code'] = True
            result['context_type'] = 'html_comment'
            result['adjustments'].append(('inside_html_comment', -35))
            result['score_delta'] -= 35

        # Check if inside a try/catch error handler (less likely to be real usage)
        if re.search(r'catch\s*\(', window):
            result['adjustments'].append(('catch_block', -5))
            result['score_delta'] -= 5

        return result

    # ═══════════════════════════════════════════
    #  [3] Variable Name Scoring
    # ═══════════════════════════════════════════

    @staticmethod
    def score_variable_name(content: str, match_start: int, value: str) -> dict:
        """Score confidence based on the variable name assigning this value."""
        result = {'varname': None, 'score_delta': 0, 'label': None}

        # Look at 150 chars before the match to find the variable name
        pre = content[max(0, match_start - 150):match_start]

        # Common assignment patterns:
        # var_name = "value", var_name: "value", "var_name": "value"
        varname_patterns = [
            r'["\']?(\w{2,40})["\']?\s*[=:]\s*["\']?\s*$',
            r'["\'](\w{2,40})["\']\s*:\s*["\']?\s*$',
            r'(\w{2,40})\s*=\s*["\']?\s*$',
            r'\.(\w{2,40})\s*=\s*["\']?\s*$',
            r'(?:export\s+)?(?:const|let|var)\s+(\w{2,40})\s*=\s*["\']?\s*$',
            r'(\w{2,40})\s*:\s*["\']?\s*$',
        ]

        varname = None
        for pat in varname_patterns:
            m = re.search(pat, pre)
            if m:
                varname = m.group(1).lower()
                break

        if not varname:
            return result

        result['varname'] = varname

        # Check against high-confidence names
        for name_pat, boost in AccuracyEngine.HIGH_CONFIDENCE_VARNAMES.items():
            if name_pat in varname or varname in name_pat:
                result['score_delta'] = boost
                result['label'] = f'high_conf_var:{name_pat}'
                return result

        # Check against low-confidence names
        for name_pat, penalty in AccuracyEngine.LOW_CONFIDENCE_VARNAMES.items():
            if name_pat in varname:
                result['score_delta'] = penalty
                result['label'] = f'low_conf_var:{name_pat}'
                return result

        # Partial keyword matching
        security_keywords = ['key', 'secret', 'token', 'auth', 'cred', 'pass', 'api']
        for kw in security_keywords:
            if kw in varname:
                result['score_delta'] = 10
                result['label'] = f'keyword_in_var:{kw}'
                return result

        return result

    # ═══════════════════════════════════════════
    #  [2] Correlation & Intelligent Dedup
    # ═══════════════════════════════════════════

    def track_cross_file(self, value: str, source: str):
        """Track values across files for multi-file correlation."""
        # Normalize value for comparison
        normalized = value.strip().lower()
        val_hash = hashlib.sha256(normalized.encode()).hexdigest()[:16]
        self.cross_file_values[val_hash].append(source)

    def get_cross_file_count(self, value: str) -> int:
        """How many different sources contain this value?"""
        normalized = value.strip().lower()
        val_hash = hashlib.sha256(normalized.encode()).hexdigest()[:16]
        sources = self.cross_file_values.get(val_hash, [])
        return len(set(sources))

    @staticmethod
    def smart_dedup(findings: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
        """
        Intelligent dedup that goes beyond exact-match:
        - Normalize whitespace/quotes before comparing
        - Group by secret value, keep highest-confidence instance
        - Merge metadata from duplicates into the primary
        """
        kept, removed = [], []
        value_groups = defaultdict(list)

        for f in findings:
            # Normalize: strip whitespace, quotes, common wrappers
            norm_val = f['value'].strip().strip('"\'`')
            # Additional normalization for URLs
            norm_val = norm_val.rstrip('/')
            val_hash = hashlib.sha256(norm_val.encode()).hexdigest()[:16]
            value_groups[val_hash].append(f)

        for val_hash, group in value_groups.items():
            if len(group) == 1:
                kept.append(group[0])
                continue

            # Sort by: verified_live first, then confidence_score desc, then severity
            sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
            group.sort(key=lambda x: (
                0 if x.get('verified_live') else 1,
                -x.get('confidence_score', 50),
                sev_order.get(x.get('severity', 'LOW'), 4),
            ))

            primary = group[0]
            # Merge info from duplicates
            all_sources = list(set(f['source'] for f in group))
            primary['all_sources'] = all_sources
            primary['duplicate_count'] = len(group) - 1

            # [5] Multi-file correlation: found in multiple files = more confident
            if len(all_sources) > 1:
                primary['multi_file'] = True
                boost = min(len(all_sources) * 5, 20)  # +5 per additional source, cap +20
                primary['confidence_score'] = min(100,
                    primary.get('confidence_score', 50) + boost)
                primary.setdefault('accuracy_notes', []).append(
                    f'Found in {len(all_sources)} sources (+{boost} confidence)')

            kept.append(primary)

            for dup in group[1:]:
                dup['fp_reason'] = f'Duplicate of primary (from {primary["source"]})'
                removed.append(dup)

        return kept, removed

    # ═══════════════════════════════════════════
    #  [6] Base64 / Encoded Secret Detection
    # ═══════════════════════════════════════════

    @staticmethod
    def decode_base64_secrets(content: str, source: str) -> List[Dict]:
        """Scan for base64-encoded secrets. Decode and check for known patterns."""
        decoded_findings = []

        # Find base64 strings (40+ chars, valid base64 alphabet)
        b64_pattern = re.compile(r'["\']([A-Za-z0-9+/]{40,}={0,3})["\']')

        for match in b64_pattern.finditer(content):
            b64_str = match.group(1)
            try:
                decoded = base64.b64decode(b64_str).decode('utf-8', errors='ignore')
            except Exception:
                continue

            if not decoded or len(decoded) < 10:
                continue

            # Check decoded content for known secret signatures
            for sig in AccuracyEngine.B64_DECODED_SIGNATURES:
                if sig in decoded:
                    decoded_findings.append({
                        'type': 'Base64-Encoded Secret',
                        'value': decoded.strip()[:200],
                        'source': source,
                        'severity': 'HIGH',
                        'confidence': 'HIGH',
                        'validated': False,
                        'entropy': shannon_entropy(decoded),
                        'encoding': 'base64',
                        'original_encoded': b64_str[:40] + '...',
                        'accuracy_notes': [f'Decoded from base64, matched signature: {sig}'],
                    })
                    break

        # Also check for atob() calls with inline strings
        atob_pattern = re.compile(r'atob\s*\(\s*["\']([A-Za-z0-9+/=]{16,})["\']')
        for match in atob_pattern.finditer(content):
            b64_str = match.group(1)
            try:
                decoded = base64.b64decode(b64_str).decode('utf-8', errors='ignore')
            except Exception:
                continue
            if decoded and len(decoded) >= 8 and shannon_entropy(decoded) > 3.0:
                decoded_findings.append({
                    'type': 'Base64-Encoded Secret (atob)',
                    'value': decoded.strip()[:200],
                    'source': source,
                    'severity': 'MEDIUM',
                    'confidence': 'MEDIUM',
                    'validated': False,
                    'entropy': shannon_entropy(decoded),
                    'encoding': 'base64_atob',
                    'accuracy_notes': ['Decoded from atob() call'],
                })

        # Check URL-encoded secrets
        url_encoded_pattern = re.compile(r'(%[0-9A-Fa-f]{2}){5,}')
        for match in url_encoded_pattern.finditer(content):
            try:
                from urllib.parse import unquote
                decoded = unquote(match.group(0))
            except Exception:
                continue
            if decoded and shannon_entropy(decoded) > 3.5:
                for sig in AccuracyEngine.B64_DECODED_SIGNATURES:
                    if sig in decoded:
                        decoded_findings.append({
                            'type': 'URL-Encoded Secret',
                            'value': decoded.strip()[:200],
                            'source': source,
                            'severity': 'HIGH',
                            'confidence': 'MEDIUM',
                            'validated': False,
                            'entropy': shannon_entropy(decoded),
                            'encoding': 'url_encoded',
                            'accuracy_notes': ['Decoded from URL encoding'],
                        })
                        break

        return decoded_findings

    # ═══════════════════════════════════════════
    #  [7] Minified JS Deobfuscation
    # ═══════════════════════════════════════════

    @staticmethod
    def light_deobfuscate(content: str) -> str:
        """
        Light deobfuscation / beautification of minified JS.
        Adds newlines and spacing to improve context extraction.
        Does NOT modify the actual content — used only for context analysis.
        """
        if not content or len(content) < 100:
            return content

        # Quick check: is this actually minified? (very long lines)
        lines = content.split('\n')
        avg_line_len = sum(len(l) for l in lines) / max(len(lines), 1)
        if avg_line_len < 300:
            return content  # Not minified, skip

        beautified = content
        # Add newlines after common statement endings
        beautified = re.sub(r';\s*', ';\n', beautified)
        beautified = re.sub(r'\{\s*', '{\n', beautified)
        beautified = re.sub(r'\}\s*', '}\n', beautified)
        # Add newlines after commas in object/array literals
        beautified = re.sub(r',\s*(["\'])', r',\n\1', beautified)

        return beautified

    @staticmethod
    def extract_string_assignments(content: str) -> List[Tuple[str, str, int]]:
        """
        Extract (varname, value, position) tuples from common patterns.
        Catches secrets in hex-encoded or concatenated strings.
        """
        results = []

        # Hex-encoded strings: "\x73\x6b\x5f" patterns
        hex_pattern = re.compile(r'["\']((\\x[0-9a-fA-F]{2}){8,})["\']')
        for m in hex_pattern.finditer(content):
            try:
                hex_str = m.group(1)
                decoded = bytes(hex_str, 'utf-8').decode('unicode_escape')
                if decoded and len(decoded) >= 8:
                    results.append(('hex_encoded', decoded, m.start()))
            except Exception:
                continue

        # Char code arrays: [115, 107, 95, 108, 105, 118, 101]
        charcode_pattern = re.compile(
            r'String\.fromCharCode\s*\(\s*((?:\d{1,3}\s*,\s*){4,}\d{1,3})\s*\)')
        for m in charcode_pattern.finditer(content):
            try:
                codes = [int(c.strip()) for c in m.group(1).split(',')]
                decoded = ''.join(chr(c) for c in codes if 32 <= c <= 126)
                if decoded and len(decoded) >= 8:
                    results.append(('charcode', decoded, m.start()))
            except Exception:
                continue

        # String concatenation: "sk_" + "live_" + "xxx"
        concat_pattern = re.compile(
            r'["\']((?:sk_|pk_|SG\.|AKIA|ghp_|xoxb)[^"\']{0,8})["\']\s*\+\s*["\']([^"\']{4,})["\']'
            r'(?:\s*\+\s*["\']([^"\']{4,})["\'])?')
        for m in concat_pattern.finditer(content):
            parts = [m.group(i) for i in range(1, 4) if m.group(i)]
            combined = ''.join(parts)
            if combined and len(combined) >= 12:
                results.append(('concatenated', combined, m.start()))

        return results

    # ═══════════════════════════════════════════
    #  [8] Unified Confidence Score (0-100)
    # ═══════════════════════════════════════════

    @staticmethod
    def calculate_confidence_score(finding: dict, context_result: dict = None,
                                    varname_result: dict = None,
                                    weights: dict = None) -> dict:
        """
        Arcanis Secret Confidence Formula v2
        ═════════════════════════════════════
        Confidence = (Format Validity   x W1)
                   + (Context Strength  x W2)
                   + (Domain Ownership  x W3)
                   + (File Risk Weight  x W4)
                   + (Entropy Range Fit x W5)
                   + (Live Validation   x W6)

        Weights are dynamic (Upgrade 2) — auto-adjusted by environment profile.
        Returns dict with all factor scores + final confidence + risk score.
        """
        # Default weights if none provided
        if not weights:
            weights = {
                'format_validity': 0.30, 'context_strength': 0.20,
                'domain_ownership': 0.15, 'file_risk_weight': 0.10,
                'entropy_range_fit': 0.10, 'live_validation': 0.15,
            }
        ftype = finding.get('type', '')
        source = finding.get('source', '')
        value = finding.get('value', '')
        entropy = finding.get('entropy', 0)
        src_lower = source.lower()

        # Shared domain lists (used by multiple factors)
        THIRD_PARTY_CDN = [
            # CDNs
            'cdnjs.cloudflare.com', 'cdn.jsdelivr.net', 'unpkg.com',
            'ajax.googleapis.com', 'cdn.shopify.com', 'assets.shopify.com',
            'polyfill.io', 'stackpath.bootstrapcdn.com', 'maxcdn.bootstrapcdn.com',
            'code.jquery.com', 'fonts.googleapis.com', 'cdn.datatables.net',
            'cdnjs.com', 'rawgit.com', 'raw.githubusercontent.com',
            'cdn.bootcdn.net', 'lib.baomitu.com', 'cdn.staticfile.org',
            # Ad networks (NOT target-owned)
            'pagead2.googlesyndication.com', 'googlesyndication.com',
            'securepubads.g.doubleclick.net', 'doubleclick.net',
            'googleadservices.com', 'adservice.google.com',
            'jsc.mgid.com', 'mgid.com',
            'btloader.com', 'ad.mediaprimaplus.com.my',
            'ads-twitter.com', 'connect.facebook.net',
            'platform.twitter.com', 'static.ads-twitter.com',
            # Analytics (NOT target-owned)
            'www.googletagmanager.com', 'googletagmanager.com',
            'www.google-analytics.com', 'google-analytics.com',
            'www.googleoptimize.com', 'static.cloudflareinsights.com',
            'cloudflareinsights.com', 'analytics.tiktok.com',
            'snap.licdn.com', 'bat.bing.com',
            # Social embeds
            'platform.twitter.com', 'connect.facebook.net',
            'player.vimeo.com', 'www.youtube.com',
        ]
        ARCHIVE_DOMAINS = ['archive.org', 'web.archive.org', 'webcache.googleusercontent.com']

        # ══════════════════════════════════════
        #  FACTOR 1: Format Validity (0-100)
        #  Does it match exact known format?
        # ══════════════════════════════════════

        # Exact format: correct prefix + correct length range
        FORMAT_EXACT = {
            # type: (prefixes, min_len, max_len)
            'AWS Access Key':       (['AKIA', 'ABIA', 'ACCA', 'ASIA'], 20, 20),
            'Stripe API Key':       (['sk_live_', 'sk_test_', 'pk_live_', 'pk_test_', 'rk_live_', 'rk_test_'], 20, 60),
            'GitHub Token':         (['ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_', 'github_pat_'], 20, 100),
            'Slack Token':          (['xoxb-', 'xoxp-', 'xoxa-', 'xoxr-', 'xoxs-'], 20, 80),
            'SendGrid API Key':     (['SG.'], 40, 100),
            'Google API Key':       (['AIza'], 35, 45),
            'Twilio API Key':       (['SK'], 32, 34),
            'Shopify Access Token': (['shpat_', 'shpca_', 'shppa_'], 20, 60),
            'OpenAI API Key':       (['sk-'], 40, 60),
            'Anthropic API Key':    (['sk-ant-'], 40, 120),
            'Mapbox Token':         (['pk.eyJ', 'sk.eyJ'], 80, 200),
            'Square Access Token':  (['sq0atp-', 'sq0csp-'], 20, 60),
            'Telegram Bot Token':   ([], 40, 50),  # format: digits:alphanum
            'Private Key':          (['-----BEGIN'], 100, 5000),
            'Firebase Config':      (['AIza'], 35, 45),
        }

        f_format = 20  # default: only high entropy match
        if ftype in FORMAT_EXACT:
            prefixes, min_len, max_len = FORMAT_EXACT[ftype]
            has_prefix = not prefixes or any(value.startswith(p) for p in prefixes)
            correct_len = min_len <= len(value) <= max_len

            if has_prefix and correct_len:
                f_format = 100  # exact prefix + correct length
            elif has_prefix:
                f_format = 60   # prefix matches, length off
            elif correct_len:
                f_format = 40   # length right, no prefix
            else:
                f_format = 10   # weak match
        elif ftype in ('JWT Token',):
            f_format = 80 if value.startswith('eyJ') else 20
        elif ftype in ('Database Connection String',):
            f_format = 90 if any(p in value for p in ['://', 'mongodb', 'postgres', 'mysql', 'redis']) else 30
        elif ftype.startswith('Base64-Encoded') or ftype.startswith('Obfuscated'):
            f_format = 50  # decoded, partial confidence
        elif ftype in ('High-Entropy Secret', 'Generic API Key', 'Generic Secret',
                        'Generic Bearer Token', 'Hardcoded Password'):
            f_format = 20  # generic = low format confidence
        elif '.wasm' in source or 'binary' in source.lower():
            f_format = 0   # binary blob = no format trust

        # If validated format checker passed
        if finding.get('validated'):
            f_format = max(f_format, 80)

        # ══════════════════════════════════════
        #  FACTOR 2: Context Strength (0-100)
        #  What's around the match?
        # ══════════════════════════════════════

        f_context = 40  # default: slightly below neutral (no context = less trust)

        if context_result:
            is_dead = context_result.get('is_dead_code', False)
            ctx_type = context_result.get('context_type', 'live_code')
            adjustments = context_result.get('adjustments', [])

            # Start from context clues
            boost_labels = {
                'config_assignment': 100,
                'auth_header': 95,
                'http_usage': 90,
                'request_params': 80,
                'dotenv_source': 100,
            }
            penalty_labels = {
                'in_comment': 40,
                'line_is_comment': 30,
                'inside_block_comment': 25,
                'inside_html_comment': 25,
                'if_false_block': 10,
                'if_zero_block': 10,
                'todo_comment': 35,
                'deprecated_comment': 30,
                'console_log': 45,
                'print_statement': 45,
                'debug_output': 40,
                'doc_example': 15,
                'doc_param': 20,
                'doc_source': 10,
                'catch_block': 50,
            }

            best_boost = 40
            for label, _ in adjustments:
                if label in boost_labels:
                    best_boost = max(best_boost, boost_labels[label])
                if label in penalty_labels:
                    best_boost = min(best_boost, penalty_labels[label])

            f_context = best_boost

            if is_dead:
                f_context = min(f_context, 30)

        # Variable name boost
        if varname_result and varname_result.get('varname'):
            vname = varname_result['varname']
            # High-confidence variable names push context up
            high_conf_vars = ['secret_key', 'api_key', 'access_key', 'private_key',
                              'auth_token', 'password', 'client_secret', 'api_secret',
                              'stripe', 'aws', 'sendgrid', 'twilio', 'slack', 'github',
                              'database_url', 'db_password', 'encryption_key', 'jwt_secret']
            low_conf_vars = ['example', 'sample', 'demo', 'test', 'mock', 'fake',
                             'dummy', 'placeholder', 'template', 'default']

            if any(hv in vname for hv in high_conf_vars):
                f_context = max(f_context, 90)
            elif any(lv in vname for lv in low_conf_vars):
                f_context = min(f_context, 20)

        # CDN/archive sources get lower context trust
        if any(cdn in src_lower for cdn in THIRD_PARTY_CDN):
            f_context = min(f_context, 25)
        if any(arc in src_lower for arc in ARCHIVE_DOMAINS):
            f_context = min(f_context, 10)

        # ══════════════════════════════════════
        #  FACTOR 3: Domain Ownership (0-100)
        #  Is the asset owned by the target?
        # ══════════════════════════════════════

        f_ownership = 80  # default: assume in-scope

        if any(cdn in src_lower for cdn in THIRD_PARTY_CDN):
            f_ownership = 30   # third-party CDN
        elif any(arc in src_lower for arc in ARCHIVE_DOMAINS):
            f_ownership = 0    # archive.org = not target's asset
        elif '.wasm' in src_lower:
            f_ownership = 10   # WASM binary = likely third-party
        elif finding.get('multi_file'):
            f_ownership = 95   # found across multiple target pages
        else:
            # First-party: check if source matches common first-party patterns
            f_ownership = 80   # default in-scope

        # ══════════════════════════════════════
        #  FACTOR 4: File Risk Weight (0-100)
        #  What type of file is this?
        # ══════════════════════════════════════

        FILE_RISK = {
            '.env': 100, '.env.local': 100, '.env.production': 100,
            '.env.development': 95, '.env.staging': 95, '.env.example': 40,
            '.tf': 95, '.tfvars': 95,
            '.yaml': 90, '.yml': 90,
            '.toml': 85, '.ini': 85, '.cfg': 85, '.conf': 85,
            '.properties': 80, '.config': 80,
            '.json': 70,
            '.py': 65, '.rb': 65, '.php': 65, '.go': 65, '.java': 65,
            '.js': 50, '.ts': 50, '.jsx': 50, '.tsx': 50,
            '.html': 40, '.htm': 40,
            '.css': 15,
            '.map': 10, '.js.map': 10,
            '.wasm': 0, '.bin': 0, '.dat': 0,
            '.png': 0, '.jpg': 0, '.gif': 0, '.svg': 5,
            '.min.js': 45,
        }

        f_file = 50  # default for unknown file types

        # Check most specific extension first
        for ext, risk in sorted(FILE_RISK.items(), key=lambda x: -len(x[0])):
            if src_lower.endswith(ext) or ext in src_lower:
                f_file = risk
                break

        # Boost if source looks like a config/secret file
        if any(kw in src_lower for kw in ['config', 'secret', 'credential', 'password', '.env']):
            f_file = max(f_file, 90)

        # ══════════════════════════════════════
        #  FACTOR 5: Entropy Range Fit (0-100)
        #  Does entropy match known token bands?
        # ══════════════════════════════════════

        # Known entropy ranges for real secrets
        ENTROPY_BANDS = {
            # type: (ideal_low, ideal_high, acceptable_low, acceptable_high)
            'AWS Access Key':       (3.0, 3.8, 2.8, 4.2),
            'Stripe API Key':       (3.5, 4.5, 3.0, 5.0),
            'GitHub Token':         (3.5, 4.5, 3.0, 5.0),
            'Slack Token':          (3.5, 4.5, 3.0, 5.0),
            'SendGrid API Key':     (4.0, 5.0, 3.5, 5.5),
            'Google API Key':       (3.5, 4.5, 3.0, 5.0),
            'Private Key':          (2.0, 5.5, 1.5, 6.0),
            'JWT Token':            (3.0, 5.5, 2.0, 6.0),
            'Database Connection String': (2.5, 4.5, 2.0, 5.0),
            'Hardcoded Password':   (2.5, 4.0, 2.0, 4.5),
        }

        default_band = (3.0, 4.5, 2.5, 5.0)
        ideal_low, ideal_high, acc_low, acc_high = ENTROPY_BANDS.get(ftype, default_band)

        if ideal_low <= entropy <= ideal_high:
            f_entropy = 100  # perfect range
        elif acc_low <= entropy <= acc_high:
            f_entropy = 60   # acceptable range
        elif entropy > acc_high:
            f_entropy = 10   # too high = likely binary/random noise
        elif entropy < acc_low:
            f_entropy = 10   # too low = likely placeholder
        else:
            f_entropy = 30

        # Binary signature entropy (very high) = likely not a real token
        if entropy > 5.5:
            f_entropy = 0

        # Binary/WASM files — entropy is meaningless noise
        if any(ext in src_lower for ext in ['.wasm', '.bin', '.dat', '.so', '.dll', '.exe']):
            f_entropy = 0

        # Generic types with high entropy are less trustworthy
        if ftype in ('High-Entropy Secret', 'Generic API Key', 'Generic Secret') and entropy > 4.2:
            f_entropy = min(f_entropy, 20)

        # Third-party CDN — entropy match is less meaningful
        if any(cdn in src_lower for cdn in THIRD_PARTY_CDN):
            f_entropy = min(f_entropy, 30)

        # ══════════════════════════════════════
        #  FACTOR 6: Live Validation (0-100)
        # ══════════════════════════════════════

        if finding.get('verified_live') is True:
            f_live = 100    # confirmed active
        elif finding.get('verified_live') is False:
            f_live = 0      # confirmed dead
        else:
            f_live = 50     # not tested = neutral

        # ══════════════════════════════════════
        #  WEIGHTED CONFIDENCE SCORE
        #  Upgrade 2: Weights are dynamic
        # ══════════════════════════════════════

        w = weights
        confidence = (
            (f_format    * w.get('format_validity', 0.30)) +
            (f_context   * w.get('context_strength', 0.20)) +
            (f_ownership * w.get('domain_ownership', 0.15)) +
            (f_file      * w.get('file_risk_weight', 0.10)) +
            (f_entropy   * w.get('entropy_range_fit', 0.10)) +
            (f_live      * w.get('live_validation', 0.15))
        )

        confidence = max(0, min(100, int(round(confidence))))

        # ══════════════════════════════════════
        #  EXPLOITABILITY = Confidence x Impact
        # ══════════════════════════════════════

        IMPACT_WEIGHTS = {
            'AWS Access Key': 100, 'AWS Secret Key': 100,
            'Private Key': 95,
            'Database Connection String': 95,
            'Stripe API Key': 90,
            'PayPal Client Secret': 90,
            'Terraform Cloud Token': 85,
            'GitHub Token': 80,
            'GitLab Token': 80,
            'Slack Token': 75,
            'SendGrid API Key': 75,
            'Twilio API Key': 75,
            'OpenAI API Key': 70,
            'Anthropic API Key': 70,
            'Google API Key': 65,
            'Firebase Config': 60,
            'Shopify Access Token': 70,
            'Square Access Token': 70,
            'Mapbox Token': 50,
            'JWT Token': 60,
            'OAuth Access Token': 65,
            'OAuth Refresh Token': 70,
            'Sentry DSN': 40,
            'Hardcoded Password': 70,
            'High-Entropy Secret': 50,
            'Generic API Key': 50,
            'Generic Secret': 40,
            'Generic Bearer Token': 55,
            'Base64-Encoded Secret': 60,
            'Base64-Encoded Secret (atob)': 60,
            'URL-Encoded Secret': 60,
        }

        impact = IMPACT_WEIGHTS.get(ftype, 50)
        risk_score = int(round((confidence * impact) / 100))

        # Return full breakdown for transparency
        return {
            'confidence': confidence,
            'risk_score': risk_score,
            'impact_weight': impact,
            'factors': {
                'format_validity': f_format,
                'context_strength': f_context,
                'domain_ownership': f_ownership,
                'file_risk_weight': f_file,
                'entropy_range_fit': f_entropy,
                'live_validation': f_live,
            },
        }

    @staticmethod
    def score_to_severity(score: int) -> str:
        """Map confidence score to severity tier."""
        if score >= 85:
            return 'CRITICAL'
        elif score >= 70:
            return 'HIGH'
        elif score >= 50:
            return 'MEDIUM'
        elif score >= 30:
            return 'LOW'
        else:
            return 'INFO'

    @staticmethod
    def score_to_label(score: int) -> str:
        """Map confidence score to confidence label."""
        if score >= 85:
            return 'HIGH'
        elif score >= 50:
            return 'MEDIUM'
        else:
            return 'LOW'

    # ═══════════════════════════════════════════
    #  Main Processing Pipeline
    # ═══════════════════════════════════════════

    def process_findings(self, findings: List[Dict], all_content: Dict[str, str] = None) -> List[Dict]:
        """
        Run all 8 accuracy systems on a list of findings.

        Args:
            findings: Raw findings from scanner
            all_content: Dict of {source_url: content} for context analysis
        """
        if not findings:
            return findings

        all_content = all_content or {}

        # ── Upgrade 2: Detect environment, set dynamic weights ──
        all_sources = [f.get('source', '') for f in findings]
        self.environment_profile = self.detect_environment(all_sources)
        dynamic_weights = self.get_weights()
        if self.environment_profile != 'default':
            self.upgrades_applied['dynamic_weights'] = self.environment_profile

        # ── Extract target domain for cross-repo ──
        target_domain = None
        for src in all_sources:
            if '://' in src:
                from urllib.parse import urlparse as _urlparse
                target_domain = _urlparse(src).netloc
                if target_domain:
                    break
        self.current_target = target_domain

        for f in findings:
            source = f.get('source', '')
            value = f.get('value', '')
            content = all_content.get(source, '')
            notes = f.get('accuracy_notes', [])

            # [1] Context window analysis
            ctx_result = {'score_delta': 0, 'is_dead_code': False}
            if content and value:
                pos = content.find(value)
                if pos >= 0:
                    ctx_result = self.analyze_context(value, content, pos)
                    if ctx_result['adjustments']:
                        adj_labels = [a[0] for a in ctx_result['adjustments']]
                        notes.append(f"Context: {', '.join(adj_labels)}")
                        self.upgrades_applied['context_analysis'] += 1

            # [3] Variable name scoring
            var_result = {'score_delta': 0}
            if content and value:
                pos = content.find(value)
                if pos >= 0:
                    var_result = self.score_variable_name(content, pos, value)
                    if var_result.get('varname'):
                        notes.append(f"Variable: {var_result['varname']}")
                        self.upgrades_applied['varname_scoring'] += 1

            # [2][5] Track for cross-file correlation
            self.track_cross_file(value, source)

            # [8] Calculate confidence score (v2 weighted, Upgrade 2: dynamic weights)
            score_result = self.calculate_confidence_score(
                f, ctx_result, var_result, weights=dynamic_weights
            )
            confidence = score_result['confidence']

            # ── Upgrade 3: Trust Decay ──
            decay_multiplier = self.trust_decay_apply(f)
            if decay_multiplier < 1.0:
                original_conf = confidence
                confidence = int(round(confidence * decay_multiplier))
                score_result['confidence'] = confidence
                score_result['risk_score'] = int(round((confidence * score_result['impact_weight']) / 100))
                notes.append(f"Trust decay: {decay_multiplier:.2f}x ({original_conf} -> {confidence})")
                self.upgrades_applied['trust_decay'] += 1

            # ── Upgrade 4: Cross-Repo Leak Correlation ──
            if target_domain:
                self.cross_repo_record(f, target_domain)
                repo_info = self.cross_repo_boost(f)
                if repo_info['boost_multiplier'] > 1.0:
                    original_conf = confidence
                    confidence = min(100, int(round(confidence * repo_info['boost_multiplier'])))
                    score_result['confidence'] = confidence
                    score_result['risk_score'] = int(round((confidence * score_result['impact_weight']) / 100))
                    f['cross_repo'] = repo_info
                    notes.append(
                        f"Cross-repo: {repo_info['repo_count']} targets "
                        f"(x{repo_info['boost_multiplier']:.1f} boost, {original_conf} -> {confidence})"
                    )
                    self.upgrades_applied['cross_repo_boost'] += 1
                if repo_info['is_leaked_widely']:
                    notes.append(f"WIDELY LEAKED across {repo_info['repo_count']} targets")

            # Apply final scores to finding
            f['confidence_score'] = confidence
            f['risk_score'] = score_result['risk_score']
            f['impact_weight'] = score_result['impact_weight']
            f['score_factors'] = score_result['factors']
            f['confidence'] = self.score_to_label(confidence)

            # Override severity based on confidence score
            computed_severity = self.score_to_severity(confidence)
            original_severity = f.get('severity', 'LOW')
            sev_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
            if sev_order.get(computed_severity, 0) < sev_order.get(original_severity, 0):
                f['severity'] = computed_severity
                f['severity_downgraded'] = True
                notes.append(f"Severity {original_severity} -> {computed_severity} (confidence {confidence})")
            if f.get('verified_live') is True and sev_order.get(computed_severity, 0) > sev_order.get(original_severity, 0):
                f['severity'] = computed_severity

            # Dead code annotation
            if ctx_result.get('is_dead_code'):
                notes.append(f"Possibly dead code ({ctx_result.get('context_type', 'unknown')})")

            # Store notes
            if notes:
                f['accuracy_notes'] = notes

            # ── Upgrade 1: Calibration logging ──
            self.calibration_record(f)

            self.processed_count += 1

        # [2] Smart dedup (also handles [5] multi-file correlation)
        findings, deduped = self.smart_dedup(findings)
        self.upgrades_applied['smart_dedup'] = len(deduped)

        # Sort by risk score descending (confidence x impact)
        findings.sort(key=lambda x: (-x.get('risk_score', 0), -x.get('confidence_score', 0)))

        # ── Upgrade 1: Save calibration data ──
        self.calibration_save()

        return findings

    def pre_scan_content(self, content: str, source: str) -> Tuple[str, List[Dict]]:
        """
        Pre-processing pass before main regex scanning.
        Returns: (possibly_enhanced_content, extra_findings)

        [6] Decodes base64/URL-encoded secrets
        [7] Light deobfuscation for context extraction
        """
        extra_findings = []

        # [6] Scan for encoded secrets
        encoded_finds = self.decode_base64_secrets(content, source)
        if encoded_finds:
            extra_findings.extend(encoded_finds)
            self.upgrades_applied['base64_decode'] += len(encoded_finds)

        # [7] Extract obfuscated strings (hex, charcode, concat)
        obf_strings = self.extract_string_assignments(content)
        for encoding_type, decoded_val, pos in obf_strings:
            if shannon_entropy(decoded_val) > 3.0:
                extra_findings.append({
                    'type': f'Obfuscated Secret ({encoding_type})',
                    'value': decoded_val,
                    'source': source,
                    'severity': 'HIGH',
                    'confidence': 'HIGH',
                    'validated': False,
                    'entropy': shannon_entropy(decoded_val),
                    'encoding': encoding_type,
                    'accuracy_notes': [f'Decoded from {encoding_type} obfuscation'],
                })
                self.upgrades_applied['deobfuscation'] += 1

        return content, extra_findings

    # ═══════════════════════════════════════════
    #  UPGRADE 1: Calibration Mode
    #  Log findings → plot → tune weights
    # ═══════════════════════════════════════════

    def calibration_record(self, finding: dict):
        """Record a finding for calibration analysis."""
        record = {
            'timestamp': int(time.time()),
            'type': finding.get('type', ''),
            'confidence_score': finding.get('confidence_score', 0),
            'risk_score': finding.get('risk_score', 0),
            'factors': finding.get('score_factors', {}),
            'verified_live': finding.get('verified_live'),
            'severity': finding.get('severity', ''),
            'entropy': finding.get('entropy', 0),
            'source_ext': os.path.splitext(finding.get('source', ''))[-1],
            'value_hash': hashlib.sha256(finding.get('value', '').encode()).hexdigest()[:12],
        }
        self.calibration_log.append(record)

    def calibration_save(self):
        """Save calibration data to disk for analysis."""
        if not self.calibration_log:
            return
        try:
            os.makedirs(os.path.dirname(self.calibration_file), mode=0o700, exist_ok=True)
            existing = []
            if os.path.exists(self.calibration_file):
                with open(self.calibration_file) as f:
                    existing = json.load(f)
            existing.extend(self.calibration_log)
            # Keep last 2000 entries
            if len(existing) > 2000:
                existing = existing[-2000:]
            with open(self.calibration_file, 'w') as f:
                json.dump(existing, f, indent=1)
            os.chmod(self.calibration_file, 0o600)
        except Exception:
            pass

    @staticmethod
    def calibration_analyze(calibration_file: str) -> dict:
        """
        Analyze calibration data to suggest weight adjustments.
        Run: python3 -c "from arcanis import AccuracyEngine; AccuracyEngine.calibration_report()"

        Returns stats on how each factor correlates with live verification.
        """
        if not os.path.exists(calibration_file):
            return {'error': 'No calibration data found. Run more scans first.'}

        with open(calibration_file) as f:
            data = json.load(f)

        if len(data) < 20:
            return {'error': f'Only {len(data)} findings logged. Need 50+ for meaningful analysis.'}

        # Separate verified-live vs dead vs untested
        live = [d for d in data if d.get('verified_live') is True]
        dead = [d for d in data if d.get('verified_live') is False]
        untested = [d for d in data if d.get('verified_live') is None]

        # For each factor, calculate avg score for live vs dead findings
        factor_names = ['format_validity', 'context_strength', 'domain_ownership',
                        'file_risk_weight', 'entropy_range_fit', 'live_validation']

        analysis = {
            'total_findings': len(data),
            'verified_live': len(live),
            'verified_dead': len(dead),
            'untested': len(untested),
            'factor_correlation': {},
            'weight_suggestions': {},
        }

        current_weights = {
            'format_validity': 0.30, 'context_strength': 0.20,
            'domain_ownership': 0.15, 'file_risk_weight': 0.10,
            'entropy_range_fit': 0.10, 'live_validation': 0.15,
        }

        for factor in factor_names:
            if factor == 'live_validation':
                continue  # Skip — circular

            live_avg = 0
            dead_avg = 0
            if live:
                live_scores = [d.get('factors', {}).get(factor, 0) for d in live]
                live_avg = sum(live_scores) / len(live_scores)
            if dead:
                dead_scores = [d.get('factors', {}).get(factor, 0) for d in dead]
                dead_avg = sum(dead_scores) / len(dead_scores)

            # Separation = how well this factor distinguishes live from dead
            separation = live_avg - dead_avg
            analysis['factor_correlation'][factor] = {
                'live_avg': round(live_avg, 1),
                'dead_avg': round(dead_avg, 1),
                'separation': round(separation, 1),
            }

            # Suggest weight increase if high separation, decrease if low
            if separation > 30:
                suggestion = min(current_weights[factor] + 0.05, 0.40)
            elif separation < 10:
                suggestion = max(current_weights[factor] - 0.05, 0.05)
            else:
                suggestion = current_weights[factor]
            analysis['weight_suggestions'][factor] = round(suggestion, 2)

        return analysis

    # ═══════════════════════════════════════════
    #  UPGRADE 2: Dynamic Weight Adjustment
    #  Environment-aware weight profiles
    # ═══════════════════════════════════════════

    # Weight profiles for different environments
    WEIGHT_PROFILES = {
        'default': {
            'format_validity': 0.30, 'context_strength': 0.20,
            'domain_ownership': 0.15, 'file_risk_weight': 0.10,
            'entropy_range_fit': 0.10, 'live_validation': 0.15,
        },
        'cloud': {
            # Cloud repos: FILE weight up (IaC files = high risk), ownership matters more
            'format_validity': 0.25, 'context_strength': 0.15,
            'domain_ownership': 0.20, 'file_risk_weight': 0.20,
            'entropy_range_fit': 0.05, 'live_validation': 0.15,
        },
        'ci_cd': {
            # CI/CD: context matters more, live validation critical
            'format_validity': 0.25, 'context_strength': 0.25,
            'domain_ownership': 0.10, 'file_risk_weight': 0.10,
            'entropy_range_fit': 0.05, 'live_validation': 0.25,
        },
        'web_app': {
            # Web app scanning: format + live are king
            'format_validity': 0.30, 'context_strength': 0.15,
            'domain_ownership': 0.15, 'file_risk_weight': 0.05,
            'entropy_range_fit': 0.10, 'live_validation': 0.25,
        },
        'source_code': {
            # Source code review: context + variable names matter most
            'format_validity': 0.20, 'context_strength': 0.30,
            'domain_ownership': 0.10, 'file_risk_weight': 0.15,
            'entropy_range_fit': 0.10, 'live_validation': 0.15,
        },
    }

    def detect_environment(self, sources: List[str]) -> str:
        """Auto-detect environment profile from scan sources."""
        src_text = ' '.join(sources).lower()

        # Cloud indicators
        cloud_indicators = ['.tf', '.tfvars', 'terraform', 'cloudformation',
                            'k8s', 'kubernetes', 'helm', 'ansible', 'pulumi',
                            'aws', 'gcp', 'azure', '.yaml', '.yml']
        cloud_score = sum(1 for ind in cloud_indicators if ind in src_text)

        # CI/CD indicators
        ci_indicators = ['.github/workflows', 'gitlab-ci', 'jenkinsfile', 'circleci',
                         '.travis', 'bitbucket-pipelines', 'azure-pipelines',
                         'dockerfile', 'docker-compose', '.drone']
        ci_score = sum(1 for ind in ci_indicators if ind in src_text)

        # Source code indicators
        code_indicators = ['.py', '.js', '.ts', '.go', '.java', '.rb', '.php',
                           'src/', 'lib/', 'app/', 'internal/', 'pkg/']
        code_score = sum(1 for ind in code_indicators if ind in src_text)

        # Web app indicators (default for URL-based scanning)
        web_indicators = ['http://', 'https://', '.html', '.js', '.css',
                          'api/', 'graphql', 'swagger', '.env']
        web_score = sum(1 for ind in web_indicators if ind in src_text)

        scores = {
            'cloud': cloud_score,
            'ci_cd': ci_score,
            'source_code': code_score,
            'web_app': web_score,
        }

        best = max(scores, key=scores.get)
        if scores[best] >= 3:
            return best
        return 'default'

    def get_weights(self) -> dict:
        """Get current weight profile (with any manual overrides)."""
        profile = self.WEIGHT_PROFILES.get(self.environment_profile, self.WEIGHT_PROFILES['default'])
        weights = dict(profile)
        weights.update(self.weight_overrides)

        # Normalize to sum=1.0
        total = sum(weights.values())
        if total > 0:
            weights = {k: v / total for k, v in weights.items()}

        return weights

    # ═══════════════════════════════════════════
    #  UPGRADE 3: Trust Decay
    #  Old secrets lose confidence over time
    # ═══════════════════════════════════════════

    def trust_decay_load(self) -> dict:
        """Load known secrets database."""
        try:
            if os.path.exists(self.known_secrets_db):
                with open(self.known_secrets_db) as f:
                    return json.load(f)
        except Exception:
            pass
        return {'secrets': {}}

    def trust_decay_save(self, db: dict):
        """Save known secrets database."""
        try:
            os.makedirs(os.path.dirname(self.known_secrets_db), mode=0o700, exist_ok=True)
            with open(self.known_secrets_db, 'w') as f:
                json.dump(db, f, indent=1)
            os.chmod(self.known_secrets_db, 0o600)
        except Exception:
            pass

    def trust_decay_apply(self, finding: dict) -> float:
        """
        Calculate trust decay multiplier for a finding.

        Rules:
        - First time seen: multiplier = 1.0 (full trust)
        - Seen before, verified live last time: multiplier = 1.0
        - Seen before, NOT re-verified: decay based on age
          - < 7 days: 1.0
          - 7-30 days: 0.85
          - 30-90 days: 0.65
          - 90-180 days: 0.45
          - > 180 days: 0.25

        Returns multiplier (0.0 - 1.0) to apply to confidence.
        """
        if not self.trust_decay_enabled:
            return 1.0

        value_hash = hashlib.sha256(finding.get('value', '').encode()).hexdigest()[:16]
        db = self.trust_decay_load()
        secrets = db.get('secrets', {})

        now = int(time.time())

        if value_hash not in secrets:
            # First time seen — record it
            secrets[value_hash] = {
                'first_seen': now,
                'last_seen': now,
                'last_verified': now if finding.get('verified_live') is True else 0,
                'type': finding.get('type', ''),
                'times_seen': 1,
            }
            db['secrets'] = secrets
            self.trust_decay_save(db)
            return 1.0

        entry = secrets[value_hash]
        entry['last_seen'] = now
        entry['times_seen'] = entry.get('times_seen', 0) + 1

        # If just verified live, reset decay
        if finding.get('verified_live') is True:
            entry['last_verified'] = now
            db['secrets'] = secrets
            self.trust_decay_save(db)
            return 1.0

        # Calculate decay based on time since last verification
        last_verified = entry.get('last_verified', entry.get('first_seen', now))
        age_days = (now - last_verified) / 86400

        if age_days < 7:
            multiplier = 1.0
        elif age_days < 30:
            multiplier = 0.85
        elif age_days < 90:
            multiplier = 0.65
        elif age_days < 180:
            multiplier = 0.45
        else:
            multiplier = 0.25

        db['secrets'] = secrets
        self.trust_decay_save(db)

        return multiplier

    # ═══════════════════════════════════════════
    #  UPGRADE 4: Cross-Repo Leak Correlation
    #  Same key across repos = exponential boost
    # ═══════════════════════════════════════════

    def cross_repo_load(self) -> dict:
        """Load cross-repo correlation database."""
        try:
            if os.path.exists(self.cross_repo_db):
                with open(self.cross_repo_db) as f:
                    return json.load(f)
        except Exception:
            pass
        return {'values': {}}

    def cross_repo_save(self, db: dict):
        """Save cross-repo database."""
        try:
            os.makedirs(os.path.dirname(self.cross_repo_db), mode=0o700, exist_ok=True)
            # Prune old entries (>90 days)
            now = int(time.time())
            values = db.get('values', {})
            pruned = {}
            for k, v in values.items():
                targets = {t: ts for t, ts in v.get('targets', {}).items()
                           if now - ts < 90 * 86400}
                if targets:
                    v['targets'] = targets
                    pruned[k] = v
            db['values'] = pruned
            with open(self.cross_repo_db, 'w') as f:
                json.dump(db, f, indent=1)
            os.chmod(self.cross_repo_db, 0o600)
        except Exception:
            pass

    def cross_repo_record(self, finding: dict, target_domain: str):
        """Record a finding's value against a target for cross-repo tracking."""
        value_hash = hashlib.sha256(finding.get('value', '').encode()).hexdigest()[:16]
        db = self.cross_repo_load()
        values = db.get('values', {})

        if value_hash not in values:
            values[value_hash] = {
                'type': finding.get('type', ''),
                'targets': {},
                'first_seen': int(time.time()),
            }

        values[value_hash]['targets'][target_domain] = int(time.time())
        db['values'] = values
        self.cross_repo_save(db)

    def cross_repo_boost(self, finding: dict) -> dict:
        """
        Check if this secret appears across multiple targets/repos.

        Returns:
        {
            'repo_count': N,
            'boost_multiplier': 1.0 - 2.0,
            'targets': ['target1.com', 'target2.com'],
            'is_leaked_widely': bool,
        }
        """
        value_hash = hashlib.sha256(finding.get('value', '').encode()).hexdigest()[:16]
        db = self.cross_repo_load()
        values = db.get('values', {})

        if value_hash not in values:
            return {'repo_count': 1, 'boost_multiplier': 1.0, 'targets': [], 'is_leaked_widely': False}

        entry = values[value_hash]
        targets = list(entry.get('targets', {}).keys())
        repo_count = len(targets)

        # Exponential boost: each additional repo dramatically increases confidence
        if repo_count >= 5:
            boost = 2.0     # 5+ repos = maximum boost
        elif repo_count >= 3:
            boost = 1.6     # 3-4 repos = strong boost
        elif repo_count >= 2:
            boost = 1.3     # 2 repos = moderate boost
        else:
            boost = 1.0     # 1 repo = no boost

        return {
            'repo_count': repo_count,
            'boost_multiplier': boost,
            'targets': targets[:10],  # Cap display at 10
            'is_leaked_widely': repo_count >= 3,
        }

    def get_stats(self) -> dict:
        """Return accuracy engine statistics."""
        return {
            'findings_processed': self.processed_count,
            'upgrades_applied': dict(self.upgrades_applied),
            'cross_file_values_tracked': len(self.cross_file_values),
            'environment_profile': self.environment_profile,
            'calibration_entries': len(self.calibration_log),
            'target_domain': self.current_target,
        }


# ═══════════════════════════════════════════════════════════════════
#  API Discovery v2.0 — v3.0
# ═══════════════════════════════════════════════════════════════════

class APIDiscoveryV2:
    """
    OpenAPI/Swagger harvesting, GraphQL schema attacks,
    gRPC/protobuf detection, REST path discovery.
    """

    SWAGGER_PATHS = [
        '/swagger.json', '/swagger/v1/swagger.json', '/swagger.yaml',
        '/api-docs', '/api-docs.json', '/api/swagger.json',
        '/v1/swagger.json', '/v2/swagger.json', '/v3/swagger.json',
        '/openapi.json', '/openapi.yaml', '/openapi/v3/api-docs',
        '/api/openapi.json', '/.well-known/openapi',
    ]

    GRAPHQL_MUTATION_PROBE = '{"query":"{ __schema { mutationType { name fields { name args { name type { name } } } } } }"}'
    GRAPHQL_FULL_SCHEMA = '{"query":"{ __schema { types { name kind fields { name type { name kind ofType { name } } } } } }"}'

    GRPC_INDICATORS = [
        r'\.proto(?:buf)?(?:\.js)?["\']',
        r'grpc[_\-]?(?:web|gateway)',
        r'application/grpc',
        r'google\.protobuf\.',
        r'\.pb\.(?:js|go|py)',
    ]

    def __init__(self, session, rate_limiter, verbose=False):
        self.session = session
        self.rate_limiter = rate_limiter
        self.verbose = verbose
        self.swagger_specs: List[Dict] = []
        self.graphql_schemas: List[Dict] = []
        self.grpc_endpoints: List[Dict] = []

    def probe_swagger(self, base_url, get_fn):
        """Probe for OpenAPI/Swagger spec files."""
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if self.verbose:
            print(f"{Colors.OKCYAN}  [*] Probing {len(self.SWAGGER_PATHS)} "
                  f"Swagger/OpenAPI paths...{Colors.ENDC}")
        for path in self.SWAGGER_PATHS:
            url = origin + path
            try:
                resp = get_fn(url, timeout=8)
                if resp and resp.status_code == 200:
                    ct = resp.headers.get('Content-Type', '')
                    if 'json' in ct or 'yaml' in ct or resp.text.strip().startswith('{'):
                        try:
                            spec = resp.json()
                            info = spec.get('info', {})
                            paths = spec.get('paths', {})
                            self.swagger_specs.append({
                                'url': url,
                                'title': info.get('title', 'N/A'),
                                'version': info.get('version', 'N/A'),
                                'endpoints': len(paths),
                                'paths_sample': list(paths.keys())[:20],
                            })
                            print(f"{Colors.FAIL}[CRITICAL]{Colors.ENDC} "
                                  f"[conf:HIGH] Swagger/OpenAPI: {url} "
                                  f"({len(paths)} endpoints)")
                        except (json.JSONDecodeError, ValueError):
                            pass
            except Exception:
                pass

    def probe_graphql_schema(self, base_url, get_fn):
        """Enhanced GraphQL: extract full schema + mutations."""
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        gql_paths = [
            '/graphql', '/api/graphql', '/graphql/console', '/gql',
            '/query', '/api/query', '/graphiql', '/playground',
            '/v1/graphql', '/api/v1/graphql',
        ]
        for path in gql_paths:
            url = origin + path
            try:
                self.rate_limiter.wait()
                headers = {'Content-Type': 'application/json'}
                resp = self.session.post(url, data=self.GRAPHQL_FULL_SCHEMA,
                                          headers=headers, timeout=8)
                if resp.status_code == 200:
                    data = resp.json()
                    schema = (data.get('data') or {}).get('__schema', {})
                    if schema:
                        types = schema.get('types', [])
                        user_types = [t for t in types
                                      if not t.get('name', '').startswith('__')]
                        mutations = []
                        # Try mutation probe
                        try:
                            resp2 = self.session.post(url, data=self.GRAPHQL_MUTATION_PROBE,
                                                       headers=headers, timeout=8)
                            if resp2.status_code == 200:
                                mdata = resp2.json()
                                mt = ((mdata.get('data') or {}).get('__schema') or {}).get('mutationType')
                                if mt:
                                    mutations = [f.get('name', '?') for f in mt.get('fields', [])]
                        except Exception:
                            pass
                        self.graphql_schemas.append({
                            'url': url, 'types': len(user_types),
                            'type_names': [t['name'] for t in user_types[:20]],
                            'mutations': mutations[:20],
                            'has_mutations': len(mutations) > 0,
                        })
                        if mutations:
                            print(f"{Colors.FAIL}[CRITICAL]{Colors.ENDC} "
                                  f"GraphQL mutations exposed: {url} "
                                  f"({len(mutations)} mutations)")
            except Exception:
                pass

    def scan_grpc(self, content: str, source: str):
        """Detect gRPC/protobuf indicators in content."""
        for pattern in self.GRPC_INDICATORS:
            for m in re.finditer(pattern, content, re.I):
                val = m.group(0)
                h = f"gRPC:{val}:{source}"
                if not any(e.get('indicator') == val and e.get('source') == source
                           for e in self.grpc_endpoints):
                    self.grpc_endpoints.append({
                        'indicator': val, 'source': source,
                    })

    def get_summary(self) -> Dict:
        return {
            'swagger_specs': self.swagger_specs,
            'graphql_schemas': self.graphql_schemas,
            'grpc_endpoints': self.grpc_endpoints,
        }


# ═══════════════════════════════════════════════════════════════════
#  WAF Bypass v4.0 — v3.0
# ═══════════════════════════════════════════════════════════════════

class WAFBypassV4:
    """
    Advanced WAF evasion: path normalization, encoding tricks,
    method override, header smuggling.
    """

    @staticmethod
    def generate_bypass_urls(url: str) -> List[str]:
        """Generate multiple bypass variants for a blocked URL."""
        parsed = urlparse(url)
        path = parsed.path
        base = f"{parsed.scheme}://{parsed.netloc}"
        variants = [url]  # Original

        # Path normalization tricks
        if path and path != '/':
            variants.extend([
                base + path + '/',              # Trailing slash
                base + path + '/.',             # Dot trailing
                base + path + '%20',            # Space suffix
                base + path + '%09',            # Tab suffix
                base + path + '?',              # Empty query
                base + path + '#',              # Fragment
                base + '//' + path.lstrip('/'), # Double slash prefix
                base + path.replace('/', '/./'),  # Dot segments
            ])

            # Double URL encoding
            encoded_path = quote(path, safe='')
            variants.append(base + encoded_path)

            # Case variation (for case-insensitive servers)
            if any(c.isalpha() for c in path):
                swapped = ''.join(c.swapcase() if c.isalpha() else c for c in path)
                variants.append(base + swapped)

        return variants[:10]  # Cap at 10

    @staticmethod
    def get_bypass_headers() -> List[Dict]:
        """Return header sets for WAF bypass."""
        return [
            {},  # No extra headers
            {'X-Original-URL': '/', 'X-Rewrite-URL': '/'},
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Forwarded-Host': 'localhost'},
            {'X-Custom-IP-Authorization': '127.0.0.1'},
            {'Content-Type': 'application/x-www-form-urlencoded'},
            {'Transfer-Encoding': 'chunked'},
            {'X-HTTP-Method-Override': 'GET'},
        ]


# ═══════════════════════════════════════════════════════════════════
#  Cloud Native Scanner — v3.0
# ═══════════════════════════════════════════════════════════════════

class CloudNativeScanner:
    """
    Detect cloud-native misconfigurations: IAM policies, K8s RBAC,
    serverless configs, Terraform/CloudFormation credential exposure.
    """

    PATTERNS = {
        'AWS IAM Policy': {
            'patterns': [
                r'"Effect"\s*:\s*"Allow"[^}]*"Action"\s*:\s*"\*"',
                r'"Effect"\s*:\s*"Allow"[^}]*"Resource"\s*:\s*"\*"',
                r'arn:aws:iam::\d{12}:(?:role|user|policy)/[A-Za-z0-9+=,.@_-]+',
            ],
            'severity': 'CRITICAL',
        },
        'AWS Lambda Config': {
            'patterns': [
                r'arn:aws:lambda:[a-z0-9-]+:\d{12}:function:[A-Za-z0-9_-]+',
                r'LAMBDA_TASK_ROOT|AWS_LAMBDA_FUNCTION_NAME',
            ],
            'severity': 'MEDIUM',
        },
        'Kubernetes Secret': {
            'patterns': [
                r'kind:\s*Secret\s+metadata:',
                r'kubectl\s+(?:create|apply|get)\s+secret',
                r'kubernetes\.io/service-account-token',
            ],
            'severity': 'CRITICAL',
        },
        'Kubernetes RBAC': {
            'patterns': [
                r'kind:\s*(?:Cluster)?RoleBinding',
                r'kind:\s*(?:Cluster)?Role[^B]',
                r'apiGroups:\s*\["\*"\]',
            ],
            'severity': 'HIGH',
        },
        'Terraform Credential': {
            'patterns': [
                r'(?:access_key|secret_key|password)\s*=\s*"[^"]{8,}"',
                r'provider\s*"(?:aws|azurerm|google)"\s*\{[^}]*(?:token|key)\s*=',
            ],
            'severity': 'CRITICAL',
        },
        'CloudFormation Secret': {
            'patterns': [
                r'AWSTemplateFormatVersion',
                r'Type:\s*AWS::(?:IAM|SecretsManager|KMS)',
            ],
            'severity': 'MEDIUM',
        },
        'GCP Service Account': {
            'patterns': [
                r'"type"\s*:\s*"service_account"',
                r'"private_key_id"\s*:\s*"[a-f0-9]{40}"',
                r'[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com',
            ],
            'severity': 'CRITICAL',
        },
        'Azure Connection String': {
            'patterns': [
                r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}',
                r'Server=tcp:[^;]+;.*Password=[^;]+',
            ],
            'severity': 'CRITICAL',
        },
    }

    def __init__(self):
        self.findings: List[Dict] = []

    def scan(self, content: str, source: str):
        """Scan content for cloud-native misconfigurations."""
        for finding_type, config in self.PATTERNS.items():
            for pattern in config['patterns']:
                for m in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
                    val = m.group(0)[:200]
                    h = f"Cloud:{finding_type}:{val[:50]}"
                    if not any(f.get('_hash') == h for f in self.findings):
                        self.findings.append({
                            'type': finding_type, 'value': val,
                            'source': source, 'severity': config['severity'],
                            '_hash': h,
                        })


# ═══════════════════════════════════════════════════════════════════
#  CI/CD Integration — v3.0
# ═══════════════════════════════════════════════════════════════════

class CICDIntegration:
    """Generate CI/CD configs and baseline diff."""

    @staticmethod
    def generate_github_action(filename='secret-scan.yml'):
        """Generate GitHub Actions workflow YAML."""
        action = """name: Secret Scan
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'  # Weekly Monday 6am

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install requests pyyaml

      - name: Run Secret Scanner
        run: |
          python secret_scanner_v3.0.py ${{ vars.SCAN_TARGET }} \\
            --verify --probe-env --probe-graphql \\
            --sarif results.sarif \\
            -o results.json --html report.html \\
            --rate-limit 5

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif

      - name: Upload artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: scan-results
          path: |
            results.json
            report.html
"""
        with open(filename, 'w') as f:
            f.write(action)
        print(f"{Colors.OKGREEN}[+] GitHub Action: {filename}{Colors.ENDC}")
        return filename

    @staticmethod
    def generate_gitlab_ci(filename='.gitlab-ci-scan.yml'):
        """Generate GitLab CI pipeline YAML."""
        ci = """secret-scan:
  stage: test
  image: python:3.11-slim
  script:
    - pip install requests pyyaml
    - python secret_scanner_v3.0.py $SCAN_TARGET
        --verify --probe-env --probe-graphql
        --sarif gl-secret-detection-report.json
        -o results.json --rate-limit 5
  artifacts:
    reports:
      sast: gl-secret-detection-report.json
    paths:
      - results.json
    when: always
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"
    - if: $CI_PIPELINE_SOURCE == "schedule"
"""
        with open(filename, 'w') as f:
            f.write(ci)
        print(f"{Colors.OKGREEN}[+] GitLab CI: {filename}{Colors.ENDC}")
        return filename

    @staticmethod
    def generate_pre_commit_hook(filename='pre-commit-scan.sh'):
        """Generate pre-commit hook script."""
        hook = """#!/bin/bash
# Arcanis pre-commit hook
# Install: cp pre-commit-scan.sh .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit

echo "[*] Running secret scan on staged files..."

STAGED=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\\.(js|ts|jsx|tsx|json|env|yml|yaml|py|rb|go|java)$')

if [ -z "$STAGED" ]; then
    echo "[*] No relevant files staged, skipping scan."
    exit 0
fi

# Check for common secret patterns in staged files
FOUND=0
for FILE in $STAGED; do
    # Check for hardcoded secrets
    if grep -nP '(AKIA[0-9A-Z]{16}|sk_live_|ghp_[0-9a-zA-Z]{36}|-----BEGIN.*PRIVATE KEY)' "$FILE" 2>/dev/null; then
        echo "[!] Potential secret found in $FILE"
        FOUND=1
    fi
done

if [ $FOUND -eq 1 ]; then
    echo ""
    echo "[!] BLOCKED: Potential secrets detected in staged files."
    echo "[!] Review findings above and remove secrets before committing."
    echo "[!] To bypass (NOT recommended): git commit --no-verify"
    exit 1
fi

echo "[+] No secrets detected. Commit OK."
exit 0
"""
        with open(filename, 'w') as f:
            f.write(hook)
        print(f"{Colors.OKGREEN}[+] Pre-commit hook: {filename}{Colors.ENDC}")
        return filename

    @staticmethod
    def diff_baseline(current_findings: List[Dict], baseline_path: str) -> Tuple[List[Dict], List[Dict]]:
        """Compare current scan against baseline, return (new, resolved)."""
        try:
            with open(baseline_path) as f:
                baseline = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"{Colors.FAIL}[!] Baseline error: {e}{Colors.ENDC}")
            return current_findings, []

        prev = baseline.get('findings', [])
        prev_keys = {f"{f['type']}:{f['value']}" for f in prev}
        curr_keys = {f"{f['type']}:{f['value']}" for f in current_findings}

        new_findings = [f for f in current_findings
                        if f"{f['type']}:{f['value']}" not in prev_keys]
        resolved = [f for f in prev
                    if f"{f['type']}:{f['value']}" not in curr_keys]

        return new_findings, resolved


# ═══════════════════════════════════════════════════════════════════
#  Team Collaboration — v3.0 (Webhook Notifications)
# ═══════════════════════════════════════════════════════════════════

class TeamNotifier:
    """Push scan results to Slack/Teams/Discord/generic webhooks."""

    def __init__(self, webhook_url: str, session: requests.Session):
        self.webhook_url = webhook_url
        self.session = session
        self._detect_platform()

    def _detect_platform(self):
        url_l = self.webhook_url.lower()
        if 'hooks.slack.com' in url_l:
            self.platform = 'slack'
        elif 'discord.com/api/webhooks' in url_l or 'discordapp.com' in url_l:
            self.platform = 'discord'
        elif 'webhook.office.com' in url_l or 'outlook.office.com' in url_l:
            self.platform = 'teams'
        else:
            self.platform = 'generic'

    def send_alert(self, findings: List[Dict], stats: Dict, target: str):
        """Send scan summary to webhook."""
        critical = sum(1 for f in findings if f['severity'] == 'CRITICAL')
        high = sum(1 for f in findings if f['severity'] == 'HIGH')
        live = sum(1 for f in findings if f.get('verified_live') is True)

        if self.platform == 'slack':
            self._send_slack(findings, stats, target, critical, high, live)
        elif self.platform == 'discord':
            self._send_discord(findings, stats, target, critical, high, live)
        elif self.platform == 'teams':
            self._send_teams(findings, stats, target, critical, high, live)
        else:
            self._send_generic(findings, stats, target, critical, high, live)

    def _send_slack(self, findings, stats, target, critical, high, live):
        emoji = '🚨' if critical > 0 else ('⚠️' if high > 0 else '✅')
        blocks = [{
            'type': 'section',
            'text': {'type': 'mrkdwn', 'text':
                     f'{emoji} *Secret Scanner v{__version__}*\n'
                     f'*Target:* `{target}`\n'
                     f'*Findings:* {len(findings)} total · '
                     f'{critical} CRITICAL · {high} HIGH · {live} verified live\n'
                     f'*URLs scanned:* {stats.get("requests_made", 0)}'}
        }]
        if critical > 0:
            crit_list = [f for f in findings if f['severity'] == 'CRITICAL'][:5]
            text = '\n'.join(f"• `{f['type']}` in {f['source'][:50]}"
                             for f in crit_list)
            blocks.append({
                'type': 'section',
                'text': {'type': 'mrkdwn', 'text': f'*Critical Findings:*\n{text}'}
            })
        try:
            self.session.post(self.webhook_url, json={'blocks': blocks}, timeout=10)
            print(f"{Colors.OKGREEN}[+] Slack notification sent{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[!] Slack notification failed: {e}{Colors.ENDC}")

    def _send_discord(self, findings, stats, target, critical, high, live):
        color = 0xFF0000 if critical > 0 else (0xFF8C00 if high > 0 else 0x00FF00)
        embed = {
            'title': f'🔍 Secret Scanner v{__version__}',
            'description': f'**Target:** `{target}`',
            'color': color,
            'fields': [
                {'name': 'Findings', 'value': str(len(findings)), 'inline': True},
                {'name': 'Critical', 'value': str(critical), 'inline': True},
                {'name': 'Verified Live', 'value': str(live), 'inline': True},
            ],
        }
        try:
            self.session.post(self.webhook_url, json={'embeds': [embed]}, timeout=10)
            print(f"{Colors.OKGREEN}[+] Discord notification sent{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[!] Discord notification failed: {e}{Colors.ENDC}")

    def _send_teams(self, findings, stats, target, critical, high, live):
        card = {
            '@type': 'MessageCard', '@context': 'https://schema.org/extensions',
            'summary': f'Secret Scan: {len(findings)} findings',
            'themeColor': 'FF0000' if critical > 0 else '00FF00',
            'title': f'🔍 Secret Scanner v{__version__}',
            'sections': [{'facts': [
                {'name': 'Target', 'value': target},
                {'name': 'Findings', 'value': f'{len(findings)} ({critical} CRITICAL, {high} HIGH)'},
                {'name': 'Verified Live', 'value': str(live)},
            ]}],
        }
        try:
            self.session.post(self.webhook_url, json=card, timeout=10)
            print(f"{Colors.OKGREEN}[+] Teams notification sent{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[!] Teams notification failed: {e}{Colors.ENDC}")

    def _send_generic(self, findings, stats, target, critical, high, live):
        payload = {
            'tool': f'Arcanis v{__version__}',
            'target': target, 'total_findings': len(findings),
            'critical': critical, 'high': high, 'verified_live': live,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'top_findings': [
                {'type': f['type'], 'severity': f['severity'],
                 'source': f['source'][:100]}
                for f in sorted(findings, key=lambda x: {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3}.get(x['severity'],4))[:10]
            ],
        }
        try:
            self.session.post(self.webhook_url, json=payload, timeout=10)
            print(f"{Colors.OKGREEN}[+] Webhook notification sent{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[!] Webhook notification failed: {e}{Colors.ENDC}")



# ═══════════════════════════════════════════════════════════════════
#  OFFENSIVE RECON: Wayback Machine Historical Miner — v4.0
# ═══════════════════════════════════════════════════════════════════

class WaybackMiner:
    """Mine archived JS/HTML from Wayback Machine for historical secrets."""

    WAYBACK_CDX = 'https://web.archive.org/cdx/search/cdx'

    # Domains that should NEVER be scanned — they're infrastructure, not targets
    EXCLUDED_DOMAINS = {
        'web.archive.org', 'archive.org', 'cloudflare.com', 'cdnjs.cloudflare.com',
        'cdn.cloudflare.com', 'ajax.cloudflare.com', 'ruffle.rs',
        'cdn.jsdelivr.net', 'unpkg.com', 'cdnjs.com', 'fonts.googleapis.com',
        'fonts.gstatic.com', 'google-analytics.com', 'googletagmanager.com',
        'www.googletagmanager.com', 'connect.facebook.net', 'platform.twitter.com',
        'cdn.segment.com', 'js.stripe.com', 'cdn.shopify.com',
        'static.cloudflareinsights.com', 'challenges.cloudflare.com',
        'www.google.com', 'apis.google.com', 'maps.googleapis.com',
    }

    def __init__(self, session, rate_limiter, verbose=False):
        self.session = session
        self.rate_limiter = rate_limiter
        self.verbose = verbose
        self.archived_urls: List[Dict] = []
        self.filtered_count = 0  # track how many off-scope URLs were dropped

    def _is_in_scope(self, url: str, target_domain: str) -> bool:
        """Check if URL belongs to the target domain (strict scope)."""
        try:
            parsed = urlparse(url)
            url_domain = parsed.netloc.lower().lstrip('www.')
            target_clean = target_domain.lower().lstrip('www.')

            # Reject known infrastructure domains
            for excluded in self.EXCLUDED_DOMAINS:
                if url_domain == excluded or url_domain.endswith('.' + excluded):
                    return False

            # Must match target domain or be a subdomain of it
            if url_domain == target_clean:
                return True
            if url_domain.endswith('.' + target_clean):
                return True

            return False
        except Exception:
            return False

    def mine(self, domain: str, max_results: int = 100) -> List[str]:
        """Fetch archived JS/HTML URLs from Wayback Machine (target-scoped, deduplicated)."""
        urls = []
        seen_paths = set()  # Dedup by base path (strip query params)
        self.filtered_count = 0
        self.dedup_count = 0
        target_domain = domain.lower().lstrip('www.')

        for mime in ['application/javascript', 'text/html']:
            try:
                self.rate_limiter.wait()
                params = {
                    'url': f'{domain}/*', 'output': 'json',
                    'filter': f'mimetype:{mime}',
                    'fl': 'timestamp,original,statuscode',
                    'limit': str(max_results // 2),
                    'collapse': 'urlkey',
                }
                resp = self.session.get(self.WAYBACK_CDX, params=params, timeout=30)
                if resp.status_code == 200:
                    rows = resp.json()
                    for row in rows[1:]:  # Skip header
                        if len(row) >= 3 and row[2] == '200':
                            original_url = row[1]
                            # STRICT SCOPE: only accept URLs on the target domain
                            if not self._is_in_scope(original_url, target_domain):
                                self.filtered_count += 1
                                if self.verbose:
                                    print(f"{Colors.DIM}  Wayback skip (off-scope): "
                                          f"{urlparse(original_url).netloc}{Colors.ENDC}")
                                continue
                            # Dedup: strip query params to avoid scanning same file 20x
                            base_path = urlparse(original_url).path.lower()
                            if base_path in seen_paths:
                                self.dedup_count += 1
                                continue
                            seen_paths.add(base_path)
                            wb_url = f"https://web.archive.org/web/{row[0]}if_/{row[1]}"
                            urls.append(wb_url)
                            self.archived_urls.append({
                                'timestamp': row[0], 'original': original_url,
                                'wayback_url': wb_url, 'type': mime,
                            })
            except Exception as e:
                if self.verbose:
                    print(f"{Colors.DIM}  Wayback error: {e}{Colors.ENDC}")
        dedup_msg = f", {self.dedup_count} duplicates removed" if self.dedup_count else ""
        if self.verbose or self.filtered_count > 0:
            print(f"{Colors.OKCYAN}  [*] Wayback: {len(urls)} unique in-scope URLs "
                  f"({self.filtered_count} off-scope filtered{dedup_msg}){Colors.ENDC}")
        return urls


# ═══════════════════════════════════════════════════════════════════
#  OFFENSIVE RECON: Subdomain Takeover / Dangling CNAME — v4.0
# ═══════════════════════════════════════════════════════════════════

class SubdomainTakeoverChecker:
    """Check for dangling CNAMEs and subdomain takeover conditions."""

    VULNERABLE_CNAMES = {
        'herokuapp.com': 'Heroku', 'herokudns.com': 'Heroku',
        'github.io': 'GitHub Pages', 'azurewebsites.net': 'Azure',
        'cloudapp.net': 'Azure', 'trafficmanager.net': 'Azure Traffic Manager',
        's3.amazonaws.com': 'AWS S3', 's3-website': 'AWS S3 Website',
        'elasticbeanstalk.com': 'AWS EB', 'shopify.com': 'Shopify',
        'myshopify.com': 'Shopify', 'zendesk.com': 'Zendesk',
        'readme.io': 'ReadMe', 'ghost.io': 'Ghost',
        'netlify.app': 'Netlify', 'pantheon.io': 'Pantheon',
        'surge.sh': 'Surge', 'bitbucket.io': 'Bitbucket',
        'wordpress.com': 'WordPress', 'tumblr.com': 'Tumblr',
        'statuspage.io': 'Statuspage', 'fastly.net': 'Fastly',
        'unbounce.com': 'Unbounce', 'uservoice.com': 'UserVoice',
    }

    TAKEOVER_SIGNATURES = [
        "There isn't a GitHub Pages site here",
        "NoSuchBucket", "No such app", "Heroku | No such app",
        "404 Blog is not found", "is not a registered InCloud",
        "Domain is not configured", "project not found",
        "Sorry, this shop is currently unavailable",
        "Do you want to register",
    ]

    def __init__(self, session, verbose=False):
        self.session = session
        self.verbose = verbose
        self.findings: List[Dict] = []

    def check_cname(self, domain: str):
        """Check if domain has dangling CNAME pointing to vulnerable service."""
        try:
            socket.getaddrinfo(domain, None)
            try:
                resp = self.session.get(f'https://{domain}', timeout=10, allow_redirects=True)
                for sig in self.TAKEOVER_SIGNATURES:
                    if sig.lower() in resp.text.lower():
                        self.findings.append({
                            'domain': domain, 'signature': sig,
                            'severity': 'CRITICAL', 'status_code': resp.status_code,
                        })
                        return True
            except requests.exceptions.SSLError:
                self.findings.append({
                    'domain': domain, 'signature': 'SSL error (possible dangling CNAME)',
                    'severity': 'HIGH', 'status_code': 0,
                })
                return True
            except Exception:
                pass
        except socket.gaierror:
            self.findings.append({
                'domain': domain, 'signature': 'NXDOMAIN (dangling DNS)',
                'severity': 'HIGH', 'status_code': 0,
            })
            return True
        return False


# ═══════════════════════════════════════════════════════════════════
#  OFFENSIVE RECON: SSRF Cloud Metadata Prober — v4.0
# ═══════════════════════════════════════════════════════════════════

class SSRFProber:
    """Detect SSRF vectors and cloud metadata exposure."""

    METADATA_URLS = {
        'AWS': 'http://169.254.169.254/latest/meta-data/',
        'GCP': 'http://metadata.google.internal/computeMetadata/v1/',
        'Azure': 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
        'DigitalOcean': 'http://169.254.169.254/metadata/v1/',
    }

    SSRF_INDICATORS = [
        r'(?:url|uri|path|dest|redirect|next|data|load|fetch|proxy|img|src)\s*=\s*["\']?(https?://)',
        r'urllib\.request\.urlopen|requests\.get|http\.get|fetch\(',
        r'file:///|gopher://|dict://|ldap://|tftp://',
    ]

    def __init__(self):
        self.vectors: List[Dict] = []

    def scan_for_ssrf(self, content: str, source: str):
        """Detect potential SSRF vectors in source code."""
        for pattern in self.SSRF_INDICATORS:
            for m in re.finditer(pattern, content, re.I):
                h = f"ssrf:{m.group()[:30]}:{source}"
                if not any(v.get('_hash') == h for v in self.vectors):
                    ctx = content[max(0, m.start()-50):m.end()+50]
                    self.vectors.append({
                        'indicator': m.group()[:100], 'source': source,
                        'context': ctx[:200], 'severity': 'MEDIUM', '_hash': h,
                    })

    def check_metadata_leaks(self, content: str, source: str):
        """Check if content references cloud metadata endpoints."""
        for cloud, url in self.METADATA_URLS.items():
            if url in content or '169.254.169.254' in content:
                h = f"meta:{cloud}:{source}"
                if not any(v.get('_hash') == h for v in self.vectors):
                    self.vectors.append({
                        'indicator': f'Cloud metadata reference ({cloud})',
                        'source': source, 'context': url,
                        'severity': 'CRITICAL', '_hash': h,
                    })


# ═══════════════════════════════════════════════════════════════════
#  OFFENSIVE RECON: Auth Bypass / IDOR / BOLA Fuzzer — v4.0
# ═══════════════════════════════════════════════════════════════════

class IDORFuzzer:
    """Automated IDOR/BOLA detection via ID enumeration."""

    ID_PATTERNS = [
        r'/(?:api/)?(?:v\d+/)?(?:users?|accounts?|profiles?|orders?|invoices?|'
        r'documents?|files?|projects?|teams?|organizations?)/(\d{1,10})(?:/|$|\?)',
        r'/(?:api/)?(?:v\d+/)?(?:users?|accounts?)/([a-f0-9]{24})(?:/|$|\?)',
        r'[?&](?:user_?id|account_?id|order_?id|doc_?id|file_?id)=(\d{1,10})',
        r'[?&](?:id|uid|oid)=([a-f0-9\-]{20,})',
    ]

    def __init__(self, session, rate_limiter, verbose=False):
        self.session = session
        self.rate_limiter = rate_limiter
        self.verbose = verbose
        self.idor_candidates: List[Dict] = []

    def find_candidates(self, content: str, base_url: str):
        """Find potential IDOR-vulnerable endpoints in content."""
        for pattern in self.ID_PATTERNS:
            for m in re.finditer(pattern, content, re.I):
                self.idor_candidates.append({
                    'url_pattern': m.group(0), 'id_value': m.group(1),
                    'base_url': base_url, 'severity': 'HIGH',
                })

    def fuzz_endpoint(self, url: str, original_id: str, get_fn, max_attempts: int = 5):
        """Try adjacent IDs to detect IDOR."""
        results = []
        try:
            orig_id_int = int(original_id)
            test_ids = [orig_id_int - 1, orig_id_int + 1, orig_id_int + 100, 1, 0]
        except ValueError:
            return results
        for test_id in test_ids[:max_attempts]:
            test_url = url.replace(original_id, str(test_id))
            try:
                self.rate_limiter.wait()
                resp = get_fn(test_url, timeout=8)
                if resp and resp.status_code == 200:
                    results.append({'url': test_url, 'id_tested': test_id,
                                    'status': resp.status_code, 'size': len(resp.text)})
            except Exception:
                pass
        return results


# ═══════════════════════════════════════════════════════════════════
#  OFFENSIVE RECON: Internal API Enumeration — v4.0
# ═══════════════════════════════════════════════════════════════════

class InternalAPIEnumerator:
    """Extract internal API routes from source maps and JS bundles."""

    ROUTE_PATTERNS = [
        r'(?:path|route|url)\s*:\s*["\'](/api/[^\s"\']{3,})["\']',
        r'(?:get|post|put|delete|patch)\s*\(\s*["\'](/[^\s"\']{3,})["\']',
        r'fetch\s*\(\s*[`"\']([^`"\']*?/api/[^`"\']*?)[`"\']',
        r'axios\.\w+\s*\(\s*[`"\']([^`"\']*?/api/[^`"\']*?)[`"\']',
        r'(?:BASE_URL|API_URL|API_BASE|ENDPOINT)["\']?\s*[+\=]\s*["\']([^\s"\']+)["\']',
        r'router\.\w+\s*\(\s*["\']([^\s"\']+)["\']',
    ]

    def __init__(self):
        self.routes: List[Dict] = []
        self._seen: Set[str] = set()

    def extract_routes(self, content: str, source: str):
        """Extract API routes from content."""
        for pattern in self.ROUTE_PATTERNS:
            for m in re.finditer(pattern, content, re.I):
                route = m.group(1)
                if route not in self._seen and len(route) > 3:
                    self._seen.add(route)
                    sev = 'LOW'
                    low = route.lower()
                    if any(k in low for k in ['admin', 'internal', 'debug', 'manage']):
                        sev = 'CRITICAL'
                    elif any(k in low for k in ['user', 'auth', 'token', 'session', 'password']):
                        sev = 'HIGH'
                    elif any(k in low for k in ['config', 'setting', 'private', 'secret']):
                        sev = 'HIGH'
                    self.routes.append({'route': route, 'source': source, 'severity': sev})

    def extract_from_sourcemap(self, sourcemap_data: Dict, source: str):
        """Deep-mine API routes from source map contents."""
        sources = sourcemap_data.get('sources', [])
        for i, content in enumerate(sourcemap_data.get('sourcesContent', []) or []):
            if content:
                src_name = sources[i] if i < len(sources) else '?'
                self.extract_routes(content, f"{source}:{src_name}")


# ═══════════════════════════════════════════════════════════════════
#  VALIDATION v2.0: 50+ Live API Verifiers — v4.0
# ═══════════════════════════════════════════════════════════════════

class ActiveVerifierV2(ActiveVerifier):
    """Extended verifier with 50+ API validation methods."""

    def __init__(self, session):
        super().__init__(session)

    def verify(self, secret_type: str, value: str) -> Optional[Dict]:
        """Route to appropriate verifier — 50+ types."""
        dispatch = {
            # Original 15 from v2.9
            'Google API Key': lambda v: self.verify_google_maps(v),
            'Firebase Config': lambda v: self.verify_google_maps(v),
            'Slack Token': lambda v: self.verify_slack_token(v),
            'Slack Webhook': lambda v: self.verify_slack_webhook(v),
            'GitHub Token': lambda v: self.verify_github_token(v),
            'Stripe API Key': lambda v: self.verify_stripe_key(v),
            'SendGrid API Key': lambda v: self.verify_sendgrid(v),
            'Twilio Credentials': lambda v: self.verify_twilio(v),
            'Mapbox Token': lambda v: self.verify_mapbox(v),
            'HubSpot API Key': lambda v: self.verify_hubspot(v),
            'AWS Access Key': lambda v: self.verify_aws_sts(v),
            'Mailgun API Key': lambda v: self.verify_mailgun(v),
            'Notion API Key': lambda v: self.verify_notion(v),
            'Linear API Key': lambda v: self.verify_linear(v),
            'Datadog RUM Token': lambda v: self.verify_datadog(v),
            # v4.0: 36 new verifiers
            'OpenAI API Key': lambda v: self.verify_openai(v),
            'Anthropic API Key': lambda v: self.verify_anthropic(v),
            'HuggingFace Token': lambda v: self.verify_huggingface(v),
            'Cloudflare API Token': lambda v: self.verify_cloudflare(v),
            'Cloudflare Global API Key': lambda v: self.verify_cloudflare(v),
            'DigitalOcean Token': lambda v: self.verify_digitalocean(v),
            'Heroku API Key': lambda v: self.verify_heroku(v),
            'GitLab Token': lambda v: self.verify_gitlab(v),
            'npm Token': lambda v: self.verify_npm(v),
            'New Relic API Key': lambda v: self.verify_newrelic(v),
            'Grafana API Key': lambda v: self.verify_grafana(v),
            'Elastic API Key': lambda v: self.verify_elastic(v),
            'PagerDuty API Key': lambda v: self.verify_pagerduty(v),
            'PostHog API Key': lambda v: self.verify_posthog(v),
            'Okta API Token': lambda v: self.verify_okta(v),
            'Shopify API Key': lambda v: self.verify_shopify(v),
            'Square Access Token': lambda v: self.verify_square(v),
            'PayPal Client Secret': lambda v: self.verify_paypal(v),
            'Discord Bot Token': lambda v: self.verify_discord(v),
            'Twitch API Token': lambda v: self.verify_twitch(v),
            'Airtable API Key': lambda v: self.verify_airtable(v),
            'Contentful Token': lambda v: self.verify_contentful(v),
            'Terraform Cloud Token': lambda v: self.verify_terraform(v),
            'HashiCorp Vault Token': lambda v: self.verify_vault(v),
            'PlanetScale Password': lambda v: self.verify_planetscale(v),
            'CircleCI Token': lambda v: self.verify_circleci(v),
            'Bitbucket App Password': lambda v: self.verify_bitbucket(v),
            'Spotify Client Secret': lambda v: self.verify_spotify(v),
            'Supabase Key': lambda v: self.verify_supabase(v),
            'Vercel Token': lambda v: self.verify_vercel(v),
            'Netlify Token': lambda v: self.verify_netlify(v),
            'Pinecone API Key': lambda v: self.verify_pinecone(v),
            'Cohere API Key': lambda v: self.verify_cohere(v),
            'Replicate API Token': lambda v: self.verify_replicate(v),
            'OAuth Access Token': lambda v: self.verify_oauth_token(v),
            'OAuth Refresh Token': lambda v: self.verify_oauth_token(v),
            'Firebase Auth': lambda v: self.verify_firebase_auth(v),
        }
        fn = dispatch.get(secret_type)
        if fn:
            return fn(value)
        return None

    def verify_openai(self, key, **kw):
        try:
            r = self.session.get('https://api.openai.com/v1/models',
                                  headers={'Authorization': f'Bearer {key}'}, timeout=8)
            if r.status_code == 200:
                models = r.json().get('data', [])
                return {'live': True, 'models': len(models), 'permissions': 'full_api_access'}
            return {'live': False, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_anthropic(self, key, **kw):
        try:
            r = self.session.get('https://api.anthropic.com/v1/models',
                                  headers={'x-api-key': key, 'anthropic-version': '2023-06-01'}, timeout=8)
            return {'live': r.status_code == 200, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_huggingface(self, key, **kw):
        try:
            r = self.session.get('https://huggingface.co/api/whoami-v2',
                                  headers={'Authorization': f'Bearer {key}'}, timeout=8)
            if r.status_code == 200:
                d = r.json()
                return {'live': True, 'user': d.get('name', '?'),
                        'orgs': [o.get('name') for o in d.get('orgs', [])]}
            return {'live': False, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_cohere(self, key, **kw):
        try:
            r = self.session.get('https://api.cohere.ai/v1/models',
                                  headers={'Authorization': f'Bearer {key}'}, timeout=8)
            return {'live': r.status_code == 200, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_replicate(self, key, **kw):
        try:
            r = self.session.get('https://api.replicate.com/v1/account',
                                  headers={'Authorization': f'Token {key}'}, timeout=8)
            return {'live': r.status_code == 200, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_pinecone(self, key, **kw):
        try:
            r = self.session.get('https://api.pinecone.io/indexes',
                                  headers={'Api-Key': key}, timeout=8)
            return {'live': r.status_code == 200, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_cloudflare(self, key, **kw):
        try:
            r = self.session.get('https://api.cloudflare.com/client/v4/user',
                                  headers={'Authorization': f'Bearer {key}'}, timeout=8)
            if r.status_code == 200:
                d = r.json().get('result', {})
                return {'live': True, 'email': d.get('email', '?')}
            return {'live': False, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_digitalocean(self, key, **kw):
        try:
            r = self.session.get('https://api.digitalocean.com/v2/account',
                                  headers={'Authorization': f'Bearer {key}'}, timeout=8)
            if r.status_code == 200:
                acct = r.json().get('account', {})
                return {'live': True, 'email': acct.get('email', '?'),
                        'droplet_limit': acct.get('droplet_limit')}
            return {'live': False, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_heroku(self, key, **kw):
        try:
            r = self.session.get('https://api.heroku.com/account',
                                  headers={'Authorization': f'Bearer {key}',
                                           'Accept': 'application/vnd.heroku+json; version=3'}, timeout=8)
            return {'live': r.status_code == 200, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_vercel(self, key, **kw):
        try:
            r = self.session.get('https://api.vercel.com/v2/user',
                                  headers={'Authorization': f'Bearer {key}'}, timeout=8)
            return {'live': r.status_code == 200, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_netlify(self, key, **kw):
        try:
            r = self.session.get('https://api.netlify.com/api/v1/user',
                                  headers={'Authorization': f'Bearer {key}'}, timeout=8)
            return {'live': r.status_code == 200, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_terraform(self, key, **kw):
        try:
            r = self.session.get('https://app.terraform.io/api/v2/account/details',
                                  headers={'Authorization': f'Bearer {key}'}, timeout=8)
            return {'live': r.status_code == 200, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_vault(self, key, **kw):
        return {'live': None, 'note': 'Requires Vault server URL'}

    def verify_supabase(self, key, **kw):
        try:
            parts = key.split('.')
            if len(parts) == 3:
                payload = json.loads(base64.b64decode(parts[1] + '==').decode('utf-8', errors='ignore'))
                return {'live': True, 'role': payload.get('role', '?'), 'iss': payload.get('iss', '?')}
            return {'live': False}
        except Exception: return {'live': False}

    def verify_gitlab(self, key, **kw):
        try:
            r = self.session.get('https://gitlab.com/api/v4/user',
                                  headers={'PRIVATE-TOKEN': key}, timeout=8)
            if r.status_code == 200:
                d = r.json()
                return {'live': True, 'username': d.get('username', '?'),
                        'is_admin': d.get('is_admin', False)}
            return {'live': False, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_circleci(self, key, **kw):
        try:
            r = self.session.get('https://circleci.com/api/v2/me',
                                  headers={'Circle-Token': key}, timeout=8)
            return {'live': r.status_code == 200, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_bitbucket(self, key, **kw):
        try:
            r = self.session.get('https://api.bitbucket.org/2.0/user',
                                  headers={'Authorization': f'Bearer {key}'}, timeout=8)
            return {'live': r.status_code == 200, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_npm(self, key, **kw):
        try:
            r = self.session.get('https://registry.npmjs.org/-/npm/v1/user',
                                  headers={'Authorization': f'Bearer {key}'}, timeout=8)
            return {'live': r.status_code == 200, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_shopify(self, key, **kw):
        return {'live': None, 'note': 'Requires store domain for validation'}

    def verify_square(self, key, **kw):
        try:
            r = self.session.get('https://connect.squareup.com/v2/merchants',
                                  headers={'Authorization': f'Bearer {key}'}, timeout=8)
            return {'live': r.status_code == 200, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_paypal(self, key, **kw):
        return {'live': None, 'note': 'Requires client_id pair'}

    def verify_newrelic(self, key, **kw):
        try:
            r = self.session.get('https://api.newrelic.com/v2/applications.json',
                                  headers={'Api-Key': key}, timeout=8)
            return {'live': r.status_code == 200, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_grafana(self, key, **kw):
        try:
            r = self.session.get('https://grafana.com/api/user',
                                  headers={'Authorization': f'Bearer {key}'}, timeout=8)
            return {'live': r.status_code == 200, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_elastic(self, key, **kw):
        return {'live': None, 'note': 'Requires cluster URL'}

    def verify_pagerduty(self, key, **kw):
        try:
            r = self.session.get('https://api.pagerduty.com/users/me',
                                  headers={'Authorization': f'Token token={key}'}, timeout=8)
            return {'live': r.status_code == 200, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_posthog(self, key, **kw):
        try:
            r = self.session.post('https://app.posthog.com/api/projects/',
                                   headers={'Authorization': f'Bearer {key}'}, timeout=8)
            return {'live': r.status_code in (200, 403), 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_okta(self, key, **kw):
        return {'live': None, 'note': 'Requires Okta domain'}

    def verify_firebase_auth(self, key, **kw):
        return {'live': None, 'note': 'Requires project ID'}

    def verify_discord(self, key, **kw):
        try:
            r = self.session.get('https://discord.com/api/v10/users/@me',
                                  headers={'Authorization': f'Bot {key}'}, timeout=8)
            if r.status_code == 200:
                d = r.json()
                return {'live': True, 'username': d.get('username', '?'), 'bot': d.get('bot', False)}
            return {'live': False, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_twitch(self, key, **kw):
        return {'live': None, 'note': 'Requires client_id pair'}

    def verify_spotify(self, key, **kw):
        return {'live': None, 'note': 'Requires client_id pair'}

    def verify_airtable(self, key, **kw):
        try:
            r = self.session.get('https://api.airtable.com/v0/meta/whoami',
                                  headers={'Authorization': f'Bearer {key}'}, timeout=8)
            return {'live': r.status_code == 200, 'status': r.status_code}
        except Exception: return {'live': False}

    def verify_contentful(self, key, **kw):
        return {'live': None, 'note': 'Requires space_id'}

    def verify_planetscale(self, key, **kw):
        return {'live': None, 'note': 'Requires DB URL'}

    def verify_oauth_token(self, key, **kw):
        try:
            for url in ['https://oauth2.googleapis.com/tokeninfo',
                        'https://graph.facebook.com/me']:
                r = self.session.get(url, params={'access_token': key}, timeout=5)
                if r.status_code == 200:
                    return {'live': True, 'provider': url.split('/')[2]}
            return {'live': None, 'note': 'Could not determine OAuth provider'}
        except Exception: return {'live': False}


# ═══════════════════════════════════════════════════════════════════
#  ATTACK CHAIN BUILDER — v4.0
# ═══════════════════════════════════════════════════════════════════

class AttackChainBuilder:
    """Map secrets into attack chains with exploitability scoring and bounty estimates."""

    BOUNTY_TIERS = {
        'CRITICAL': {'label': 'P1 — Critical Exploitability'},
        'HIGH':     {'label': 'P2 — High Exploitability'},
        'MEDIUM':   {'label': 'P3 — Moderate Exploitability'},
        'LOW':      {'label': 'P4 — Low Exploitability'},
    }

    ESCALATION_PATHS = {
        'AWS Access Key': [
            'STS:GetCallerIdentity -> identify account',
            'IAM:ListUsers -> enumerate users',
            'IAM:ListRoles -> find assumable roles',
            'S3:ListBuckets -> access all storage',
            'Lambda:ListFunctions -> extract code/secrets',
            'SecretsManager:ListSecrets -> vault access',
        ],
        'OpenAI API Key': [
            'models/list -> enumerate models',
            'chat/completions -> data exfiltration via prompts',
            'files/list -> access training data',
            'fine-tuning/jobs -> model manipulation',
        ],
        'Anthropic API Key': [
            'models/list -> enumerate models',
            'messages/create -> prompt injection / data exfil',
            'billing -> financial impact',
        ],
        'GitHub Token': [
            'user -> identify account + orgs',
            'repos -> access private repositories',
            'actions/secrets -> extract CI/CD secrets',
            'admin/org -> organization takeover',
        ],
        'GitLab Token': [
            'user -> identify account',
            'projects -> access private repos',
            'pipelines/variables -> CI/CD secret extraction',
        ],
        'Stripe API Key': [
            'customers/list -> PII exposure',
            'charges/list -> financial data',
            'payouts/create -> financial theft',
        ],
        'Slack Token': [
            'auth.test -> identify workspace',
            'conversations.list -> enumerate channels',
            'conversations.history -> read messages',
        ],
        'Discord Bot Token': [
            'users/@me -> bot identity',
            'guilds -> server access',
            'channels/messages -> read all messages',
        ],
        'Google API Key': [
            'Service enumeration (Maps/Drive/Calendar)',
            'Unrestricted key -> billing abuse',
        ],
        'Firebase Config': [
            'Firestore -> data access',
            'Auth users -> PII exposure',
            'Storage -> file access',
        ],
        'Database Connection String': [
            'Connect -> full database access',
            'Enumerate tables -> data mapping',
            'Extract credentials -> chain further',
        ],
        'OAuth Refresh Token': [
            'Token refresh -> persistent access',
            'Scope enumeration -> permission mapping',
        ],
        'Cloudflare API Token': [
            'zones/list -> domain enumeration',
            'dns_records -> DNS manipulation',
            'firewall/rules -> WAF bypass',
        ],
        'DigitalOcean Token': [
            'droplets -> infrastructure access',
            'databases -> data access',
            'domains -> DNS takeover',
        ],
        'Terraform Cloud Token': [
            'workspaces -> infrastructure state',
            'variables -> secret extraction',
            'runs -> infrastructure manipulation',
        ],
    }

    @staticmethod
    def build_chains(findings: List[Dict]) -> List[Dict]:
        """Build attack chains from findings."""
        chains = []
        for f in findings:
            chain = {
                'secret_type': f['type'], 'severity': f['severity'],
                'source': f['source'], 'value_preview': f['value'][:20] + '...',
                'escalation_paths': AttackChainBuilder.ESCALATION_PATHS.get(f['type'], []),
                'verified_live': f.get('verified_live', False),
                'exploitability_score': 0, 'bounty_tier': '', 'chain_steps': [],
            }
            score = {'CRITICAL': 40, 'HIGH': 25, 'MEDIUM': 15, 'LOW': 5}.get(f['severity'], 0)
            if f.get('verified_live'): score += 30
            if chain['escalation_paths']: score += 15
            if f.get('confidence') == 'HIGH': score += 10
            if f.get('entropy', 0) > 4.0: score += 5
            chain['exploitability_score'] = min(score, 100)

            if chain['exploitability_score'] >= 70:
                chain['bounty_tier'] = AttackChainBuilder.BOUNTY_TIERS['CRITICAL']['label']
            elif chain['exploitability_score'] >= 50:
                chain['bounty_tier'] = AttackChainBuilder.BOUNTY_TIERS['HIGH']['label']
            elif chain['exploitability_score'] >= 30:
                chain['bounty_tier'] = AttackChainBuilder.BOUNTY_TIERS['MEDIUM']['label']
            else:
                chain['bounty_tier'] = AttackChainBuilder.BOUNTY_TIERS['LOW']['label']

            steps = [f"1. FOUND: {f['type']} in {f['source'][:50]}"]
            if f.get('verified_live'):
                steps.append("2. VERIFIED: Key is active")
            if chain['escalation_paths']:
                steps.append(f"3. ESCALATE: {chain['escalation_paths'][0]}")
                if len(chain['escalation_paths']) > 1:
                    steps.append(f"4. PIVOT: {chain['escalation_paths'][1]}")
            chain['chain_steps'] = steps
            chains.append(chain)
        chains.sort(key=lambda x: x['exploitability_score'], reverse=True)
        return chains

    @staticmethod
    def print_chains(chains: List[Dict]):
        """Display attack chains."""
        if not chains: return
        print(f"\n{Colors.BOLD}{'=' * 60}")
        print(f"  ATTACK CHAIN ANALYSIS -- {len(chains)} chain(s)")
        print(f"{'=' * 60}{Colors.ENDC}")
        for i, c in enumerate(chains[:15], 1):
            color = Colors.FAIL if c['exploitability_score'] >= 70 else (
                Colors.WARNING if c['exploitability_score'] >= 50 else Colors.OKCYAN)
            live_tag = f" {Colors.FAIL}* LIVE{Colors.ENDC}" if c['verified_live'] else ""
            print(f"\n{color}Chain #{i}: {c['secret_type']} "
                  f"[Score: {c['exploitability_score']}/100] [{c['bounty_tier']}]{Colors.ENDC}{live_tag}")
            for step in c['chain_steps']:
                print(f"  {step}")
            if c['escalation_paths']:
                print(f"  Escalation ({len(c['escalation_paths'])} paths):")
                for ep in c['escalation_paths'][:3]:
                    print(f"    -> {ep}")


# ═══════════════════════════════════════════════════════════════════
#  PRIVILEGE ESCALATION SIMULATOR — v4.0
# ═══════════════════════════════════════════════════════════════════

class PrivilegeEscalationSimulator:
    """Simulate privilege escalation paths (safe read-only operations)."""

    def __init__(self, session):
        self.session = session
        self.results: List[Dict] = []

    def simulate_aws(self, access_key: str, finding: Dict):
        """Document AWS privilege escalation paths."""
        if access_key.startswith('AKIA'):
            result = {
                'provider': 'AWS', 'key_type': 'IAM Access Key',
                'potential_paths': [
                    'sts:GetCallerIdentity -> Account + ARN',
                    'iam:ListUsers -> User enumeration',
                    'iam:ListAttachedUserPolicies -> Policy mapping',
                    's3:ListBuckets -> Storage enumeration',
                    'ec2:DescribeInstances -> Infrastructure mapping',
                    'lambda:ListFunctions -> Serverless code access',
                    'secretsmanager:ListSecrets -> Secret vault access',
                ],
                'risk_level': 'CRITICAL',
            }
            self.results.append(result)
            return result
        return None

    def simulate_gcp(self, key_data: str, finding: Dict):
        """Document GCP privilege escalation paths."""
        result = {
            'provider': 'GCP', 'key_type': 'Service Account',
            'potential_paths': [
                'iam.serviceAccounts.list -> SA enumeration',
                'storage.buckets.list -> Bucket enumeration',
                'compute.instances.list -> VM enumeration',
                'cloudfunctions.functions.list -> Function code access',
            ],
            'risk_level': 'CRITICAL',
        }
        self.results.append(result)
        return result

    def simulate_jwt(self, jwt_analysis: Dict, finding: Dict):
        """Simulate JWT privilege escalation."""
        vulns = jwt_analysis.get('vulnerabilities', [])
        paths = []
        if 'ALG_NONE' in vulns:
            paths.append('Algorithm:none -> Forge any JWT claim')
        if 'WEAK_ALG' in vulns:
            paths.append('HS256 weak key -> Brute-force secret')
        if jwt_analysis.get('sensitive_permissions'):
            paths.append(f'Admin perms: {jwt_analysis["sensitive_permissions"][:3]} -> Admin access')
        if 'NO_EXPIRY' in vulns:
            paths.append('No expiration -> Persistent access token')
        result = {
            'provider': 'JWT', 'key_type': 'Token',
            'potential_paths': paths or ['Standard JWT -- limited escalation'],
            'risk_level': jwt_analysis.get('risk_grade', 'MEDIUM'),
        }
        self.results.append(result)
        return result


# ═══════════════════════════════════════════════════════════════════
#  v5.0: CVE Auto-Lookup from Source Map Packages
# ═══════════════════════════════════════════════════════════════════

class CVELookup:
    """
    Cross-reference npm packages discovered via Source Map Intelligence
    against known vulnerability databases (OSV.dev + local DB).
    """

    # Expanded local CVE database for offline/fast lookup
    LOCAL_CVE_DB = {
        'lodash': [
            {'version_below': '4.17.21', 'cve': 'CVE-2021-23337', 'severity': 'HIGH',
             'detail': 'Prototype pollution via set/setWith functions'},
            {'version_below': '4.17.12', 'cve': 'CVE-2019-10744', 'severity': 'CRITICAL',
             'detail': 'Prototype pollution via defaultsDeep'},
        ],
        'axios': [
            {'version_below': '1.6.0', 'cve': 'CVE-2023-45857', 'severity': 'HIGH',
             'detail': 'CSRF/SSRF bypass via proxy configuration'},
            {'version_below': '0.21.1', 'cve': 'CVE-2021-3749', 'severity': 'MEDIUM',
             'detail': 'ReDoS in content-type parsing'},
        ],
        'express': [
            {'version_below': '4.17.3', 'cve': 'CVE-2022-24999', 'severity': 'MEDIUM',
             'detail': 'Open redirect via qs prototype pollution'},
        ],
        'jquery': [
            {'version_below': '3.5.0', 'cve': 'CVE-2020-11022', 'severity': 'MEDIUM',
             'detail': 'XSS via htmlPrefilter regex'},
            {'version_below': '3.0.0', 'cve': 'CVE-2015-9251', 'severity': 'HIGH',
             'detail': 'Selector XSS via cross-site scripting'},
        ],
        'minimist': [
            {'version_below': '1.2.6', 'cve': 'CVE-2021-44906', 'severity': 'CRITICAL',
             'detail': 'Prototype pollution via constructor/proto'},
        ],
        'node-fetch': [
            {'version_below': '2.6.7', 'cve': 'CVE-2022-0235', 'severity': 'HIGH',
             'detail': 'SSRF bypass via redirect handling'},
        ],
        'ua-parser-js': [
            {'version_below': '0.7.31', 'cve': 'CVE-2021-44906', 'severity': 'CRITICAL',
             'detail': 'Supply chain attack — malicious code injection'},
        ],
        'ejs': [
            {'version_below': '3.1.7', 'cve': 'CVE-2022-29078', 'severity': 'CRITICAL',
             'detail': 'RCE via template injection'},
        ],
        'handlebars': [
            {'version_below': '4.7.7', 'cve': 'CVE-2021-23369', 'severity': 'HIGH',
             'detail': 'Prototype pollution via template compilation'},
        ],
        'marked': [
            {'version_below': '4.0.10', 'cve': 'CVE-2022-21680', 'severity': 'HIGH',
             'detail': 'ReDoS via crafted markdown input'},
        ],
        'dompurify': [
            {'version_below': '3.0.6', 'cve': 'CVE-2023-48219', 'severity': 'HIGH',
             'detail': 'mXSS bypass via nested forms'},
        ],
        'next': [
            {'version_below': '13.4.6', 'cve': 'CVE-2023-46298', 'severity': 'HIGH',
             'detail': 'SSRF via Server Actions'},
        ],
        'socket.io': [
            {'version_below': '4.6.2', 'cve': 'CVE-2023-32695', 'severity': 'MEDIUM',
             'detail': 'DoS via malformed packet'},
        ],
        'json5': [
            {'version_below': '2.2.2', 'cve': 'CVE-2022-46175', 'severity': 'MEDIUM',
             'detail': 'Prototype pollution via parse()'},
        ],
        'sanitize-html': [
            {'version_below': '2.3.2', 'cve': 'CVE-2021-26539', 'severity': 'HIGH',
             'detail': 'XSS bypass via crafted attributes'},
        ],
        'tinymce': [
            {'version_below': '5.10.0', 'cve': 'CVE-2022-23494', 'severity': 'HIGH',
             'detail': 'Stored XSS via crafted content'},
        ],
        'terser': [
            {'version_below': '5.14.2', 'cve': 'CVE-2022-25858', 'severity': 'MEDIUM',
             'detail': 'ReDoS via crafted input'},
        ],
        'glob-parent': [
            {'version_below': '5.1.2', 'cve': 'CVE-2020-28469', 'severity': 'HIGH',
             'detail': 'ReDoS via crafted glob pattern'},
        ],
        'underscore': [
            {'version_below': '1.13.6', 'cve': 'CVE-2021-23358', 'severity': 'MEDIUM',
             'detail': 'Code injection via template()'},
        ],
        'moment': [
            {'version_below': '2.29.4', 'cve': 'CVE-2022-31129', 'severity': 'MEDIUM',
             'detail': 'ReDoS via crafted date string'},
        ],
        'semver': [
            {'version_below': '7.5.2', 'cve': 'CVE-2022-25883', 'severity': 'MEDIUM',
             'detail': 'ReDoS via crafted version string'},
        ],
        'tough-cookie': [
            {'version_below': '4.1.3', 'cve': 'CVE-2023-26136', 'severity': 'MEDIUM',
             'detail': 'Prototype pollution via cookie parsing'},
        ],
        'word-wrap': [
            {'version_below': '1.2.4', 'cve': 'CVE-2023-26115', 'severity': 'MEDIUM',
             'detail': 'ReDoS via crafted input'},
        ],
        'xml2js': [
            {'version_below': '0.5.0', 'cve': 'CVE-2023-0842', 'severity': 'MEDIUM',
             'detail': 'Prototype pollution via XML parsing'},
        ],
        'postcss': [
            {'version_below': '8.4.31', 'cve': 'CVE-2023-44270', 'severity': 'MEDIUM',
             'detail': 'Line return parsing error'},
        ],
        'undici': [
            {'version_below': '5.26.2', 'cve': 'CVE-2023-45143', 'severity': 'HIGH',
             'detail': 'Cookie header leak via cross-origin redirect'},
        ],
        '@babel/traverse': [
            {'version_below': '7.23.2', 'cve': 'CVE-2023-45133', 'severity': 'CRITICAL',
             'detail': 'Arbitrary code execution via crafted AST'},
        ],
        'crypto-js': [
            {'version_below': '4.2.0', 'cve': 'CVE-2023-46233', 'severity': 'CRITICAL',
             'detail': 'Weak default PRNG in encrypt functions'},
        ],
    }

    def __init__(self, session=None, verbose=False):
        self.session = session
        self.verbose = verbose
        self.results: List[Dict] = []
        self._cache: Dict[str, List[Dict]] = {}

    def lookup_packages(self, packages: List[str], source_map_intel: List[Dict]) -> List[Dict]:
        """
        Cross-reference npm packages against CVE databases.
        Uses source map intel to attempt version detection.
        """
        # Build package -> version map from source map paths
        pkg_versions = self._extract_versions_from_sourcemaps(source_map_intel)

        for pkg in packages:
            pkg_lower = pkg.lower().strip()
            if not pkg_lower or pkg_lower.startswith('.'):
                continue

            version = pkg_versions.get(pkg_lower)

            # Check local DB first
            local_hits = self._check_local_db(pkg_lower, version)
            if local_hits:
                self.results.extend(local_hits)

            # Try OSV.dev API for packages not in local DB
            if not local_hits and self.session and version:
                osv_hits = self._query_osv(pkg_lower, version)
                if osv_hits:
                    self.results.extend(osv_hits)

        return self.results

    def _extract_versions_from_sourcemaps(self, source_map_intel: List[Dict]) -> Dict[str, str]:
        """Extract package versions from source map file paths."""
        versions = {}
        for sm in source_map_intel:
            for path in sm.get('file_tree', []):
                # node_modules/pkg@version or node_modules/pkg/package.json
                m = re.search(r'node_modules/(@?[^/]+(?:/[^/]+)?)/.*?(\d+\.\d+\.\d+)', path)
                if m:
                    pkg_name = m.group(1).lower()
                    pkg_ver = m.group(2)
                    versions[pkg_name] = pkg_ver
        return versions

    def _check_local_db(self, package: str, version: Optional[str]) -> List[Dict]:
        """Check package against local CVE database."""
        hits = []
        entries = self.LOCAL_CVE_DB.get(package, [])
        if not entries:
            return hits

        for entry in entries:
            result = {
                'package': package,
                'version': version or 'unknown',
                'cve': entry['cve'],
                'severity': entry['severity'],
                'detail': entry['detail'],
                'version_below': entry['version_below'],
                'source': 'local_db',
                'vulnerable': None,
            }

            if version:
                result['vulnerable'] = self._version_lt(version, entry['version_below'])
                if result['vulnerable']:
                    hits.append(result)
            else:
                # No version info — flag as potential
                result['vulnerable'] = None
                result['note'] = 'Version unknown — manual check required'
                hits.append(result)

        return hits

    def _query_osv(self, package: str, version: str) -> List[Dict]:
        """Query OSV.dev API for known vulnerabilities."""
        cache_key = f"{package}@{version}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        hits = []
        try:
            resp = self.session.post(
                'https://api.osv.dev/v1/query',
                json={'package': {'name': package, 'ecosystem': 'npm'}, 'version': version},
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                for vuln in data.get('vulns', []):
                    severity = 'MEDIUM'
                    for sev_item in vuln.get('severity', []):
                        score = sev_item.get('score', '')
                        if isinstance(score, str) and ':' in score:
                            try:
                                base = float(score.split('/')[0].split(':')[-1])
                                if base >= 9.0: severity = 'CRITICAL'
                                elif base >= 7.0: severity = 'HIGH'
                                elif base >= 4.0: severity = 'MEDIUM'
                                else: severity = 'LOW'
                            except (ValueError, IndexError):
                                pass

                    aliases = vuln.get('aliases', [])
                    cve = next((a for a in aliases if a.startswith('CVE-')), vuln.get('id', '?'))

                    hits.append({
                        'package': package,
                        'version': version,
                        'cve': cve,
                        'severity': severity,
                        'detail': vuln.get('summary', vuln.get('details', 'N/A'))[:200],
                        'source': 'osv.dev',
                        'vulnerable': True,
                    })
        except Exception as e:
            if self.verbose:
                print(f"{Colors.DIM}  OSV.dev error for {package}: {e}{Colors.ENDC}")

        self._cache[cache_key] = hits
        return hits

    @staticmethod
    def _version_lt(a: str, b: str) -> bool:
        """Compare version strings: return True if a < b."""
        try:
            def _parts(v):
                return [int(x) for x in re.findall(r'\d+', v)][:4]
            pa, pb = _parts(a), _parts(b)
            while len(pa) < len(pb): pa.append(0)
            while len(pb) < len(pa): pb.append(0)
            return pa < pb
        except (ValueError, IndexError):
            return False

    def print_results(self):
        """Display CVE lookup results."""
        if not self.results:
            return
        confirmed = [r for r in self.results if r.get('vulnerable') is True]
        potential = [r for r in self.results if r.get('vulnerable') is None]

        print(f"\n{Colors.BOLD}📦 Source Map CVE Analysis:{Colors.ENDC}")
        if confirmed:
            print(f"  {Colors.FAIL}Confirmed vulnerable: {len(confirmed)}{Colors.ENDC}")
            seen = set()
            for r in confirmed:
                key = f"{r['package']}@{r['version']}:{r['cve']}"
                if key in seen:
                    continue
                seen.add(key)
                sc = {'CRITICAL': Colors.FAIL, 'HIGH': Colors.WARNING,
                      'MEDIUM': Colors.OKCYAN, 'LOW': Colors.OKBLUE}.get(r['severity'], Colors.ENDC)
                print(f"    {sc}[{r['severity']}]{Colors.ENDC} "
                      f"{r['package']}@{r['version']} — {r['cve']} — {r['detail'][:80]}")
        if potential:
            print(f"  {Colors.WARNING}Potential (version unknown): {len(potential)}{Colors.ENDC}")
            seen = set()
            for r in potential[:10]:
                key = f"{r['package']}:{r['cve']}"
                if key in seen:
                    continue
                seen.add(key)
                print(f"    {r['package']} — {r['cve']} (check manually: vuln below {r.get('version_below','')})")

    def get_summary(self) -> Dict:
        """Return CVE analysis summary."""
        return {
            'total_cves': len(self.results),
            'confirmed_vulnerable': sum(1 for r in self.results if r.get('vulnerable') is True),
            'potential': sum(1 for r in self.results if r.get('vulnerable') is None),
            'by_severity': {
                'CRITICAL': sum(1 for r in self.results if r['severity'] == 'CRITICAL'),
                'HIGH': sum(1 for r in self.results if r['severity'] == 'HIGH'),
                'MEDIUM': sum(1 for r in self.results if r['severity'] == 'MEDIUM'),
                'LOW': sum(1 for r in self.results if r['severity'] == 'LOW'),
            },
            'findings': self.results,
        }


# ═══════════════════════════════════════════════════════════════════
#  v5.0: API Rate Abuse Tester
# ═══════════════════════════════════════════════════════════════════

class RateAbuseTester:
    """
    Test verified API keys for rate limiting and quota enforcement.
    Estimates real-world cost exposure for billable APIs.

    SAFE MODE (default): Max 3 requests per key, extrapolate mathematically.
    No brute forcing. No billing damage. Ethical by default.
    """

    # Cost per request estimates for billable APIs
    API_COST_TABLE = {
        'Google Maps Geocoding': {'cost_per_req': 0.005, 'free_tier': 200, 'unit': 'req'},
        'Google Maps Directions': {'cost_per_req': 0.005, 'free_tier': 200, 'unit': 'req'},
        'Google Maps Places': {'cost_per_req': 0.017, 'free_tier': 100, 'unit': 'req'},
        'Google Maps Static': {'cost_per_req': 0.002, 'free_tier': 200, 'unit': 'req'},
        'YouTube Data': {'cost_per_req': 0.0001, 'free_tier': 10000, 'unit': 'unit'},
        'OpenAI GPT-4': {'cost_per_req': 0.03, 'free_tier': 0, 'unit': '1K tokens'},
        'OpenAI GPT-3.5': {'cost_per_req': 0.002, 'free_tier': 0, 'unit': '1K tokens'},
        'Anthropic Claude': {'cost_per_req': 0.015, 'free_tier': 0, 'unit': '1K tokens'},
        'SendGrid': {'cost_per_req': 0.001, 'free_tier': 100, 'unit': 'email'},
        'Twilio SMS': {'cost_per_req': 0.0075, 'free_tier': 0, 'unit': 'SMS'},
        'Stripe': {'cost_per_req': 0.0, 'free_tier': 0, 'unit': 'req (data access)'},
        'Mapbox': {'cost_per_req': 0.0005, 'free_tier': 50000, 'unit': 'req'},
    }

    PROBE_ENDPOINTS = {
        'Google API Key': {
            'url': 'https://maps.googleapis.com/maps/api/geocode/json',
            'params_fn': lambda key: {'address': 'test', 'key': key},
            'api_name': 'Google Maps Geocoding',
        },
        'OpenAI API Key': {
            'url': 'https://api.openai.com/v1/models',
            'headers_fn': lambda key: {'Authorization': f'Bearer {key}'},
            'api_name': 'OpenAI',
        },
        'Mapbox Token': {
            'url': 'https://api.mapbox.com/geocoding/v5/mapbox.places/test.json',
            'params_fn': lambda key: {'access_token': key},
            'api_name': 'Mapbox',
        },
        'SendGrid API Key': {
            'url': 'https://api.sendgrid.com/v3/scopes',
            'headers_fn': lambda key: {'Authorization': f'Bearer {key}'},
            'api_name': 'SendGrid',
        },
    }

    # Max probes in safe mode — enough to detect headers, not enough to cause damage
    SAFE_MODE_MAX_PROBES = 3

    def __init__(self, session, verbose=False):
        self.session = session
        self.verbose = verbose
        self.results: List[Dict] = []

    def test_key(self, secret_type: str, key: str, max_probes: int = None) -> Optional[Dict]:
        """
        Probe a verified live key for rate limits.
        SAFE MODE: Max 3 requests, then extrapolate mathematically.
        No brute forcing. No billing damage.
        """
        probe_config = self.PROBE_ENDPOINTS.get(secret_type)
        if not probe_config:
            return None

        # SAFE MODE: enforce max probe limit
        if max_probes is None:
            max_probes = self.SAFE_MODE_MAX_PROBES

        api_name = probe_config['api_name']
        url = probe_config['url']
        params = probe_config.get('params_fn', lambda k: {})(key)
        headers = probe_config.get('headers_fn', lambda k: {})(key)

        results = []
        rate_limited = False
        rate_limit_header = None

        for i in range(max_probes):
            try:
                start_t = time.time()
                resp = self.session.get(url, params=params, headers=headers, timeout=8)
                elapsed = time.time() - start_t

                result = {
                    'probe': i + 1,
                    'status': resp.status_code,
                    'latency_ms': round(elapsed * 1000),
                }

                # Check for rate limit headers
                for hdr in ['X-RateLimit-Limit', 'X-RateLimit-Remaining',
                            'X-Rate-Limit-Limit', 'RateLimit-Limit',
                            'Retry-After', 'X-RateLimit-Reset']:
                    val = resp.headers.get(hdr)
                    if val:
                        result[hdr] = val
                        rate_limit_header = {hdr: val}

                if resp.status_code == 429:
                    rate_limited = True
                    result['rate_limited'] = True
                    break

                results.append(result)
                time.sleep(0.3)  # Conservative delay between probes

            except Exception as e:
                results.append({'probe': i + 1, 'error': str(e)})

        # Analyze results — MATHEMATICAL EXTRAPOLATION, not brute force
        analysis = {
            'api_name': api_name,
            'secret_type': secret_type,
            'probes_sent': len(results),
            'safe_mode': True,
            'rate_limited': rate_limited,
            'rate_limit_headers': rate_limit_header,
            'avg_latency_ms': 0,
            'cost_estimate': {},
        }

        if results:
            latencies = [r['latency_ms'] for r in results if 'latency_ms' in r]
            if latencies:
                analysis['avg_latency_ms'] = round(sum(latencies) / len(latencies))

        # Extract rate limit info from headers
        rate_limit_value = None
        remaining_value = None
        for r in results:
            for hdr in ['X-RateLimit-Limit', 'X-Rate-Limit-Limit', 'RateLimit-Limit']:
                if hdr in r:
                    try:
                        rate_limit_value = int(r[hdr])
                    except (ValueError, TypeError):
                        pass
            for hdr in ['X-RateLimit-Remaining', 'X-Rate-Limit-Remaining']:
                if hdr in r:
                    try:
                        remaining_value = int(r[hdr])
                    except (ValueError, TypeError):
                        pass

        if rate_limited:
            analysis['rate_limit_status'] = 'RATE LIMITED (good — API protected)'
            analysis['exploitability_boost'] = 5
            analysis['risk_level'] = 'LOW'
        elif rate_limit_value:
            analysis['rate_limit_status'] = f'{rate_limit_value} req/window (has limits)'
            analysis['exploitability_boost'] = 10
            analysis['risk_level'] = 'MEDIUM'
            if remaining_value is not None:
                analysis['quota_remaining'] = remaining_value
        else:
            analysis['rate_limit_status'] = 'NO RATE LIMIT DETECTED'
            analysis['exploitability_boost'] = 25
            analysis['risk_level'] = 'HIGH'

        # Cost exposure — ESTIMATED mathematically, not tested
        cost_info = self.API_COST_TABLE.get(api_name)
        if cost_info:
            if not rate_limited and not rate_limit_value:
                # No protection detected — estimate theoretical max exposure
                reqs_per_day = 86400  # theoretical 1 req/sec
                daily_cost = reqs_per_day * cost_info['cost_per_req']
                analysis['cost_estimate'] = {
                    'method': 'mathematical_extrapolation',
                    'note': 'Estimated from headers, NOT from actual abuse',
                    'cost_per_request': cost_info['cost_per_req'],
                    'theoretical_reqs_per_day': reqs_per_day,
                    'theoretical_daily_cost': round(daily_cost, 2),
                    'theoretical_monthly_cost': round(daily_cost * 30, 2),
                    'free_tier': cost_info['free_tier'],
                    'unit': cost_info['unit'],
                }
            elif rate_limit_value:
                daily_cost = rate_limit_value * cost_info['cost_per_req']
                analysis['cost_estimate'] = {
                    'method': 'header_based_extrapolation',
                    'cost_per_request': cost_info['cost_per_req'],
                    'rate_limit': rate_limit_value,
                    'estimated_daily_cost': round(daily_cost, 2),
                    'unit': cost_info['unit'],
                }

        self.results.append(analysis)
        return analysis

    def test_findings(self, findings: List[Dict]):
        """Test all verified live findings for rate abuse (safe mode)."""
        live_findings = [f for f in findings if f.get('verified_live') is True]
        tested = set()  # Don't test same key type twice
        for f in live_findings:
            if f['type'] in tested:
                continue
            tested.add(f['type'])
            result = self.test_key(f['type'], f['value'])
            if result and self.verbose:
                print(f"{Colors.OKCYAN}  Rate test ({result['probes_sent']} probes, safe mode): "
                      f"{result['api_name']} — {result['rate_limit_status']}{Colors.ENDC}")

    def print_results(self):
        """Display rate abuse analysis."""
        if not self.results:
            return
        print(f"\n{Colors.BOLD}💰 API Rate Abuse Analysis (Safe Mode — {self.SAFE_MODE_MAX_PROBES} probes max):{Colors.ENDC}")
        for r in self.results:
            risk = r.get('risk_level', 'UNKNOWN')
            if risk == 'HIGH':
                status_color = Colors.FAIL
            elif risk == 'MEDIUM':
                status_color = Colors.WARNING
            else:
                status_color = Colors.OKGREEN
            print(f"\n  {Colors.BOLD}{r['api_name']}{Colors.ENDC}")
            print(f"    Rate limit: {status_color}{r['rate_limit_status']}{Colors.ENDC}")
            print(f"    Risk level: {status_color}{risk}{Colors.ENDC}")
            if r.get('avg_latency_ms'):
                print(f"    Avg latency: {r['avg_latency_ms']}ms")
            if r.get('quota_remaining') is not None:
                print(f"    Quota remaining: {r['quota_remaining']}")
            cost = r.get('cost_estimate', {})
            if cost:
                method = cost.get('method', 'unknown')
                if cost.get('theoretical_daily_cost'):
                    daily = cost['theoretical_daily_cost']
                    monthly = cost.get('theoretical_monthly_cost', daily * 30)
                    print(f"    {Colors.WARNING}Theoretical cost exposure: "
                          f"${daily}/day (${monthly}/month){Colors.ENDC}")
                    print(f"    {Colors.DIM}(Extrapolated from headers, not from actual requests){Colors.ENDC}")
                elif cost.get('estimated_daily_cost'):
                    print(f"    Estimated max cost: ${cost['estimated_daily_cost']}/day "
                          f"(rate limit: {cost.get('rate_limit', '?')})")
                if cost.get('free_tier'):
                    print(f"    Free tier: {cost['free_tier']} {cost.get('unit', 'req')}/day")
            print(f"    Exploitability boost: +{r.get('exploitability_boost', 0)} points")

    def get_summary(self) -> Dict:
        return {
            'apis_tested': len(self.results),
            'safe_mode': True,
            'max_probes_per_key': self.SAFE_MODE_MAX_PROBES,
            'unrestricted': sum(1 for r in self.results if 'NO RATE LIMIT' in r.get('rate_limit_status', '')),
            'rate_limited': sum(1 for r in self.results if r.get('rate_limited')),
            'results': self.results,
        }


# ═══════════════════════════════════════════════════════════════════
#  v5.0: Multi-Target Batch Scanner
# ═══════════════════════════════════════════════════════════════════

class BatchScanner:
    """
    Scan multiple targets from file or stdin with unified summary.
    Supports per-target output, resume, and parallel target processing.
    """

    def __init__(self):
        self.target_results: List[Dict] = []
        self.resume_file = '.scanner_resume.json'

    @staticmethod
    def load_targets(source: str) -> List[str]:
        """Load targets from file or stdin."""
        targets = []
        if source == '-':
            # Read from stdin
            import select
            if select.select([sys.stdin], [], [], 0.0)[0]:
                for line in sys.stdin:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if not line.startswith(('http://', 'https://')):
                            line = 'https://' + line
                        targets.append(line)
        else:
            try:
                with open(source) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if not line.startswith(('http://', 'https://')):
                                line = 'https://' + line
                            targets.append(line)
            except FileNotFoundError:
                print(f"{Colors.FAIL}[!] Target file not found: {source}{Colors.ENDC}")
        return targets

    def save_progress(self, completed_targets: List[str]):
        """Save progress for resume support."""
        try:
            with open(self.resume_file, 'w') as f:
                json.dump({
                    'completed': completed_targets,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                }, f)
        except Exception:
            pass

    def load_progress(self) -> List[str]:
        """Load previously completed targets for resume."""
        try:
            with open(self.resume_file) as f:
                data = json.load(f)
                return data.get('completed', [])
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def add_result(self, target: str, findings_count: int, duration: float,
                   findings: List[Dict]):
        """Record per-target results."""
        self.target_results.append({
            'target': target,
            'findings': findings_count,
            'duration': round(duration, 1),
            'critical': sum(1 for f in findings if f['severity'] == 'CRITICAL'),
            'high': sum(1 for f in findings if f['severity'] == 'HIGH'),
            'live': sum(1 for f in findings if f.get('verified_live') is True),
        })

    def print_batch_summary(self):
        """Print unified summary across all targets."""
        if not self.target_results:
            return
        print(f"\n{'=' * 70}")
        print(f"{Colors.BOLD}BATCH SCAN SUMMARY — {len(self.target_results)} targets{Colors.ENDC}")
        print(f"{'=' * 70}")

        total_findings = sum(r['findings'] for r in self.target_results)
        total_critical = sum(r['critical'] for r in self.target_results)
        total_high = sum(r['high'] for r in self.target_results)
        total_live = sum(r['live'] for r in self.target_results)
        total_time = sum(r['duration'] for r in self.target_results)

        print(f"\n  Targets scanned: {len(self.target_results)}")
        print(f"  Total findings:  {total_findings}")
        if total_critical:
            print(f"  {Colors.FAIL}Critical: {total_critical}{Colors.ENDC}")
        if total_high:
            print(f"  {Colors.WARNING}High: {total_high}{Colors.ENDC}")
        if total_live:
            print(f"  {Colors.FAIL}Verified live: {total_live}{Colors.ENDC}")
        print(f"  Total time: {total_time:.1f}s")

        print(f"\n  Per-target breakdown:")
        for r in sorted(self.target_results, key=lambda x: x['findings'], reverse=True):
            indicator = '🔴' if r['critical'] > 0 else ('🟡' if r['high'] > 0 else '🟢')
            live_tag = f" (⚡{r['live']} live)" if r['live'] > 0 else ''
            print(f"    {indicator} {r['target'][:50]:<50s} "
                  f"{r['findings']:>3d} findings  {r['duration']:>6.1f}s{live_tag}")

    def cleanup_resume(self):
        """Remove resume file after successful batch completion."""
        try:
            Path(self.resume_file).unlink(missing_ok=True)
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════
#  PHASE 1: SQLite Persistence Backend
# ═══════════════════════════════════════════════════════════════════

class ArcanisDB:
    """
    SQLite-backed persistence for findings, subdomains, scan history.
    Enables incremental scanning, historical comparison, and correlation.
    """

    DB_DIR = Path.home() / '.arcanis'
    DB_PATH = DB_DIR / 'arcanis.db'

    def __init__(self, db_path: str = None):
        self.db_path = db_path or str(self.DB_PATH)
        self.DB_DIR.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self._init_schema()

    def _init_schema(self):
        """Create tables if they don't exist."""
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                urls_scanned INTEGER DEFAULT 0,
                findings_count INTEGER DEFAULT 0,
                duration_seconds REAL,
                config TEXT
            );

            CREATE TABLE IF NOT EXISTS subdomains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                subdomain TEXT NOT NULL,
                source TEXT DEFAULT 'unknown',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                is_alive INTEGER DEFAULT 0,
                ip_address TEXT,
                risk_score INTEGER DEFAULT 0,
                risk_factors TEXT,
                http_status INTEGER,
                server_header TEXT,
                technologies TEXT,
                UNIQUE(domain, subdomain)
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                type TEXT NOT NULL,
                value_hash TEXT NOT NULL,
                value_preview TEXT,
                source TEXT,
                severity TEXT,
                confidence INTEGER,
                risk_score INTEGER,
                verified_live INTEGER DEFAULT 0,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                times_seen INTEGER DEFAULT 1,
                status TEXT DEFAULT 'active',
                raw_json TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS scan_urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                url TEXT NOT NULL,
                status_code INTEGER,
                content_hash TEXT,
                last_scanned TEXT,
                changed_since_last INTEGER DEFAULT 0,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            CREATE INDEX IF NOT EXISTS idx_subdomains_domain ON subdomains(domain);
            CREATE INDEX IF NOT EXISTS idx_findings_hash ON findings(value_hash);
            CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(type);
            CREATE INDEX IF NOT EXISTS idx_scan_urls_url ON scan_urls(url);
        """)
        self.conn.commit()

    def start_scan(self, target: str, config: dict = None) -> int:
        """Register a new scan, return scan_id."""
        cur = self.conn.execute(
            "INSERT INTO scans (target, started_at, config) VALUES (?, ?, ?)",
            (target, datetime.now(timezone.utc).isoformat(),
             json.dumps(config) if config else None)
        )
        self.conn.commit()
        return cur.lastrowid

    def finish_scan(self, scan_id: int, urls_scanned: int, findings_count: int, duration: float):
        """Mark scan complete."""
        self.conn.execute(
            """UPDATE scans SET finished_at=?, urls_scanned=?,
               findings_count=?, duration_seconds=? WHERE id=?""",
            (datetime.now(timezone.utc).isoformat(), urls_scanned,
             findings_count, round(duration, 2), scan_id)
        )
        self.conn.commit()

    def save_subdomain(self, domain: str, subdomain: str, source: str = 'ct',
                       is_alive: bool = False, ip_address: str = None,
                       risk_score: int = 0, risk_factors: list = None):
        """Upsert a subdomain record."""
        now = datetime.now(timezone.utc).isoformat()
        existing = self.conn.execute(
            "SELECT id FROM subdomains WHERE domain=? AND subdomain=?",
            (domain, subdomain)
        ).fetchone()
        if existing:
            self.conn.execute(
                """UPDATE subdomains SET last_seen=?, is_alive=?,
                   ip_address=COALESCE(?, ip_address),
                   risk_score=MAX(risk_score, ?),
                   risk_factors=COALESCE(?, risk_factors) WHERE id=?""",
                (now, int(is_alive), ip_address, risk_score,
                 json.dumps(risk_factors) if risk_factors else None, existing['id'])
            )
        else:
            self.conn.execute(
                """INSERT INTO subdomains
                   (domain, subdomain, source, first_seen, last_seen,
                    is_alive, ip_address, risk_score, risk_factors)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (domain, subdomain, source, now, now, int(is_alive),
                 ip_address, risk_score,
                 json.dumps(risk_factors) if risk_factors else None)
            )
        self.conn.commit()

    def save_finding(self, scan_id: int, finding: dict):
        """Upsert a finding — increment times_seen if already known."""
        value_hash = hashlib.sha256(
            f"{finding.get('type', '')}:{finding.get('value', '')}".encode()
        ).hexdigest()[:16]
        now = datetime.now(timezone.utc).isoformat()
        existing = self.conn.execute(
            "SELECT id, times_seen FROM findings WHERE value_hash=?",
            (value_hash,)
        ).fetchone()
        if existing:
            self.conn.execute(
                """UPDATE findings SET last_seen=?, times_seen=times_seen+1,
                   severity=?, confidence=?, verified_live=?,
                   risk_score=? WHERE id=?""",
                (now, finding.get('severity', '') or '',
                 finding.get('confidence_score') or 0,
                 int(finding.get('verified_live') or False),
                 finding.get('risk_score') or 0, existing['id'])
            )
        else:
            self.conn.execute(
                """INSERT INTO findings
                   (scan_id, type, value_hash, value_preview, source, severity,
                    confidence, risk_score, verified_live, first_seen, last_seen, raw_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (scan_id, finding.get('type', '') or '', value_hash,
                 (finding.get('value', '') or '')[:30] + '...', finding.get('source', '') or '',
                 finding.get('severity', '') or '', finding.get('confidence_score') or 0,
                 finding.get('risk_score') or 0, int(finding.get('verified_live') or False),
                 now, now, json.dumps(finding, default=str))
            )
        self.conn.commit()

    def get_subdomains(self, domain: str, alive_only: bool = False) -> List[dict]:
        """Get all known subdomains for a domain."""
        query = "SELECT * FROM subdomains WHERE domain=?"
        if alive_only:
            query += " AND is_alive=1"
        query += " ORDER BY risk_score DESC"
        return [dict(row) for row in self.conn.execute(query, (domain,)).fetchall()]

    def get_finding_history(self, value_hash: str) -> List[dict]:
        """Get all sightings of a specific finding."""
        return [dict(row) for row in self.conn.execute(
            "SELECT * FROM findings WHERE value_hash=? ORDER BY first_seen",
            (value_hash,)
        ).fetchall()]

    def get_scan_history(self, target: str = None, limit: int = 20) -> List[dict]:
        """Get recent scan history."""
        if target:
            rows = self.conn.execute(
                "SELECT * FROM scans WHERE target LIKE ? ORDER BY id DESC LIMIT ?",
                (f"%{target}%", limit)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def has_url_changed(self, url: str, content_hash: str) -> bool:
        """Check if URL content changed since last scan (for incremental mode)."""
        row = self.conn.execute(
            "SELECT content_hash FROM scan_urls WHERE url=? ORDER BY id DESC LIMIT 1",
            (url,)
        ).fetchone()
        if row and row['content_hash'] == content_hash:
            return False
        return True

    def save_url_state(self, scan_id: int, url: str, status_code: int, content_hash: str):
        """Record URL state for incremental scanning."""
        self.conn.execute(
            """INSERT INTO scan_urls (scan_id, url, status_code, content_hash, last_scanned)
               VALUES (?, ?, ?, ?, ?)""",
            (scan_id, url, status_code, content_hash,
             datetime.now(timezone.utc).isoformat())
        )
        self.conn.commit()

    def get_stats(self) -> dict:
        """Get overall database statistics."""
        stats = {}
        stats['total_scans'] = self.conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        stats['total_subdomains'] = self.conn.execute("SELECT COUNT(*) FROM subdomains").fetchone()[0]
        stats['alive_subdomains'] = self.conn.execute(
            "SELECT COUNT(*) FROM subdomains WHERE is_alive=1").fetchone()[0]
        stats['total_findings'] = self.conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        stats['active_findings'] = self.conn.execute(
            "SELECT COUNT(*) FROM findings WHERE status='active'").fetchone()[0]
        stats['unique_domains'] = self.conn.execute(
            "SELECT COUNT(DISTINCT domain) FROM subdomains").fetchone()[0]
        return stats

    def get_previous_scan_data(self, target: str) -> dict:
        """Get the previous scan's findings, subdomains, and URLs for diff comparison."""
        # Find the most recent completed scan for this target
        row = self.conn.execute(
            "SELECT id FROM scans WHERE target LIKE ? AND finished_at IS NOT NULL "
            "ORDER BY id DESC LIMIT 1",
            (f"%{target}%",)
        ).fetchone()
        if not row:
            return {}
        prev_scan_id = row['id']

        # Get previous findings
        prev_findings = [dict(r) for r in self.conn.execute(
            "SELECT type, value_hash, value_preview, source, severity, confidence "
            "FROM findings WHERE scan_id=?", (prev_scan_id,)
        ).fetchall()]

        # Get previous subdomains
        prev_subdomains = [dict(r) for r in self.conn.execute(
            "SELECT subdomain, is_alive, risk_score FROM subdomains WHERE domain LIKE ?",
            (f"%{target}%",)
        ).fetchall()]

        # Get previous scanned URLs
        prev_urls = [dict(r) for r in self.conn.execute(
            "SELECT url, content_hash FROM scan_urls WHERE scan_id=?", (prev_scan_id,)
        ).fetchall()]

        return {
            'scan_id': prev_scan_id,
            'findings': prev_findings,
            'subdomains': prev_subdomains,
            'urls': prev_urls,
            'finding_hashes': {f['value_hash'] for f in prev_findings},
            'url_hashes': {u['url']: u['content_hash'] for u in prev_urls},
            'subdomain_set': {s['subdomain'] for s in prev_subdomains},
        }

    def close(self):
        self.conn.close()


# ═══════════════════════════════════════════════════════════════════
#  PHASE 1: Certificate Transparency — Subdomain Discovery
# ═══════════════════════════════════════════════════════════════════

class CertTransparency:
    """
    Query Certificate Transparency logs (crt.sh) to discover subdomains.
    Returns deduplicated, cleaned subdomain list.
    """

    CRTSH_URL = "https://crt.sh/?q={}&output=json"

    def __init__(self, session, verbose=False):
        self.session = session
        self.verbose = verbose
        self.subdomains: Set[str] = set()
        self.wildcard_count = 0
        self.raw_count = 0

    def query(self, domain: str, timeout: int = 30) -> List[str]:
        """Query crt.sh for all subdomains of a domain."""
        if self.verbose:
            print(f"{Colors.OKCYAN}  [CT] Querying Certificate Transparency logs for {domain}...{Colors.ENDC}")

        try:
            url = self.CRTSH_URL.format(f"%.{domain}")
            resp = self.session.get(url, timeout=timeout)
            if not resp or resp.status_code != 200:
                if self.verbose:
                    print(f"{Colors.WARNING}  [CT] crt.sh returned {resp.status_code if resp else 'no response'}{Colors.ENDC}")
                return []

            entries = resp.json()
            self.raw_count = len(entries)

            for entry in entries:
                name = entry.get('name_value', '').lower().strip()
                # Handle multiline entries
                for sub in name.split('\n'):
                    sub = sub.strip()
                    if not sub:
                        continue
                    # Skip wildcards but count them
                    if sub.startswith('*.'):
                        self.wildcard_count += 1
                        sub = sub[2:]  # Still add the base
                    # Clean and validate
                    sub = sub.strip('.')
                    if not sub or not sub.endswith(domain):
                        continue
                    # Skip obvious noise
                    if any(c in sub for c in [' ', '/', '\\', '<', '>']):
                        continue
                    self.subdomains.add(sub)

            # Always include the apex domain
            self.subdomains.add(domain)

            result = sorted(self.subdomains)
            if self.verbose:
                print(f"{Colors.OKGREEN}  [CT] Found {len(result)} unique subdomains "
                      f"({self.raw_count} raw entries, {self.wildcard_count} wildcards){Colors.ENDC}")
            return result

        except json.JSONDecodeError:
            if self.verbose:
                print(f"{Colors.WARNING}  [CT] crt.sh returned invalid JSON (try again later){Colors.ENDC}")
            return []
        except Exception as e:
            if self.verbose:
                print(f"{Colors.WARNING}  [CT] Error querying crt.sh: {str(e)[:60]}{Colors.ENDC}")
            return []


# ═══════════════════════════════════════════════════════════════════
#  PHASE 1: DNS Resolver — Filter Dead Subdomains
# ═══════════════════════════════════════════════════════════════════

class DNSResolver:
    """
    Batch DNS resolution to filter dead subdomains before scanning.
    Multi-threaded for speed. Returns only alive hosts.
    """

    def __init__(self, verbose=False, max_workers=20, timeout=3):
        self.verbose = verbose
        self.max_workers = max_workers
        self.timeout = timeout
        self.alive: List[Dict] = []
        self.dead: List[str] = []
        self.errors: List[str] = []

    def resolve_one(self, subdomain: str) -> Optional[Dict]:
        """Resolve a single subdomain."""
        try:
            socket.setdefaulttimeout(self.timeout)
            ips = socket.getaddrinfo(subdomain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            if ips:
                # Get first IPv4 if available, else first result
                ip = None
                for family, _type, _proto, _canon, addr in ips:
                    if family == socket.AF_INET:
                        ip = addr[0]
                        break
                if not ip:
                    ip = ips[0][4][0]

                return {
                    'subdomain': subdomain,
                    'ip': ip,
                    'alive': True,
                }
        except (socket.gaierror, socket.timeout, OSError):
            return None
        return None

    def resolve_batch(self, subdomains: List[str]) -> List[Dict]:
        """Resolve all subdomains in parallel. Returns alive hosts."""
        if self.verbose:
            print(f"{Colors.OKCYAN}  [DNS] Resolving {len(subdomains)} subdomains "
                  f"({self.max_workers} workers)...{Colors.ENDC}")

        self.alive = []
        self.dead = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self.resolve_one, sd): sd for sd in subdomains}
            for future in as_completed(futures):
                sd = futures[future]
                try:
                    result = future.result()
                    if result:
                        self.alive.append(result)
                    else:
                        self.dead.append(sd)
                except Exception:
                    self.dead.append(sd)

        # Deduplicate by IP (multiple subdomains may point to same host)
        seen_ips = {}
        unique_alive = []
        for host in self.alive:
            ip = host['ip']
            if ip not in seen_ips:
                seen_ips[ip] = []
                unique_alive.append(host)
            seen_ips[ip].append(host['subdomain'])

        if self.verbose:
            print(f"{Colors.OKGREEN}  [DNS] {len(self.alive)} alive, {len(self.dead)} dead, "
                  f"{len(seen_ips)} unique IPs{Colors.ENDC}")
            if len(self.alive) > 5 and self.verbose:
                # Show IP clustering
                clustered = [(ip, subs) for ip, subs in seen_ips.items() if len(subs) > 1]
                if clustered:
                    for ip, subs in clustered[:3]:
                        print(f"{Colors.DIM}    {ip} -> {', '.join(subs[:4])}{'...' if len(subs) > 4 else ''}{Colors.ENDC}")

        return self.alive


# ═══════════════════════════════════════════════════════════════════
#  PHASE 1: Subdomain Risk Scorer — Prioritize Attack Surface
# ═══════════════════════════════════════════════════════════════════

class SubdomainRiskScorer:
    """
    Score subdomains by risk priority. High-risk subdomains get scanned first.
    Scoring based on name patterns, server type, HTTP status, and history.
    """

    # Subdomain name patterns that indicate higher risk
    HIGH_RISK_PATTERNS = {
        # Development / staging — often less secured
        'dev': 15, 'develop': 15, 'development': 15,
        'staging': 15, 'stage': 15, 'stg': 15,
        'test': 12, 'testing': 12, 'qa': 12, 'uat': 12,
        'sandbox': 12, 'demo': 10, 'beta': 10, 'alpha': 10,
        'preview': 10, 'pre-prod': 15, 'preprod': 15,
        # Internal / admin — high value targets
        'admin': 20, 'administrator': 20, 'panel': 15,
        'internal': 20, 'intranet': 18, 'private': 15,
        'console': 15, 'dashboard': 12, 'portal': 10,
        'manage': 12, 'manager': 12, 'management': 12,
        'backend': 15, 'backoffice': 15, 'bo': 10,
        'cms': 12, 'crm': 12, 'erp': 15,
        # API endpoints — often expose data
        'api': 15, 'api-v1': 15, 'api-v2': 15,
        'rest': 12, 'graphql': 15, 'grpc': 12,
        'gateway': 10, 'proxy': 10,
        # Infrastructure — might have exposed services
        'jenkins': 20, 'ci': 15, 'cd': 15, 'build': 12,
        'deploy': 12, 'gitlab': 18, 'git': 15, 'svn': 12,
        'docker': 15, 'k8s': 15, 'kubernetes': 15,
        'monitoring': 12, 'grafana': 15, 'kibana': 15,
        'elastic': 12, 'prometheus': 12, 'nagios': 12,
        'sonar': 12, 'sentry': 10, 'jira': 10,
        # Database / storage — jackpot if exposed
        'db': 20, 'database': 20, 'mysql': 20, 'postgres': 20,
        'mongo': 20, 'redis': 18, 'elastic': 15,
        'minio': 15, 's3': 15, 'storage': 12, 'backup': 15,
        'ftp': 12, 'sftp': 12, 'files': 10,
        # Auth / SSO — OAuth misconfigs
        'auth': 15, 'sso': 15, 'login': 12, 'oauth': 15,
        'idp': 15, 'identity': 12, 'accounts': 12,
        # Mail — sometimes has webmail or admin
        'mail': 10, 'webmail': 12, 'smtp': 10, 'imap': 10,
        'exchange': 12, 'owa': 15,
        # VPN / remote access
        'vpn': 15, 'remote': 12, 'rdp': 15, 'citrix': 15,
        'openvpn': 15, 'wireguard': 12,
    }

    # Low-risk patterns — deprioritize
    LOW_RISK_PATTERNS = {
        'www': -10, 'static': -8, 'cdn': -8, 'assets': -8,
        'img': -8, 'images': -8, 'media': -8, 'fonts': -8,
        'status': -5, 'docs': -3, 'help': -5, 'support': -3,
        'blog': -5, 'news': -5, 'marketing': -5,
    }

    @staticmethod
    def score(subdomain: str, domain: str, http_status: int = None,
              server: str = None, ip: str = None) -> Tuple[int, List[str]]:
        """
        Score a subdomain 0-100 for risk. Higher = scan first.
        Returns (score, list_of_risk_factors).
        """
        score = 30  # Base score
        factors = []

        # Extract the subdomain prefix (everything before the main domain)
        prefix = subdomain.replace(f".{domain}", "").lower()
        parts = re.split(r'[.\-_]', prefix)

        # Check name patterns
        for part in parts:
            if part in SubdomainRiskScorer.HIGH_RISK_PATTERNS:
                bonus = SubdomainRiskScorer.HIGH_RISK_PATTERNS[part]
                score += bonus
                factors.append(f"name:{part} (+{bonus})")
            elif part in SubdomainRiskScorer.LOW_RISK_PATTERNS:
                penalty = SubdomainRiskScorer.LOW_RISK_PATTERNS[part]
                score += penalty  # negative value
                factors.append(f"name:{part} ({penalty})")

        # Numeric prefix = likely autogenerated (lower risk)
        if parts and parts[0].isdigit():
            score -= 10
            factors.append("numeric_prefix (-10)")

        # Long subdomain chains = interesting (subdomain.of.subdomain.target.com)
        depth = prefix.count('.') + 1
        if depth >= 3:
            score += 10
            factors.append(f"deep_subdomain:{depth} (+10)")

        # HTTP status scoring
        if http_status:
            if http_status == 200:
                score += 5
                factors.append("http_200 (+5)")
            elif http_status in (401, 403):
                score += 15  # Forbidden = something worth protecting
                factors.append(f"http_{http_status}_auth_required (+15)")
            elif http_status == 301 or http_status == 302:
                score += 3
            elif http_status >= 500:
                score += 10  # Server errors = misconfigured
                factors.append(f"http_{http_status}_error (+10)")

        # Server header analysis
        if server:
            sv = server.lower()
            if any(s in sv for s in ['nginx', 'apache']):
                score += 2
            if any(s in sv for s in ['express', 'kestrel', 'gunicorn', 'uvicorn']):
                score += 5
                factors.append("app_server (+5)")
            if any(s in sv for s in ['iis', 'microsoft']):
                score += 3

        # IP-based scoring
        if ip:
            # Private IP ranges = internal service exposed
            if ip.startswith(('10.', '172.16.', '172.17.', '172.18.',
                              '192.168.', '127.')):
                score += 25
                factors.append(f"private_ip:{ip} (+25)")

        return (min(max(score, 0), 100), factors)

    @staticmethod
    def prioritize(subdomains: List[Dict], domain: str) -> List[Dict]:
        """Score and sort subdomains by risk priority."""
        for sd in subdomains:
            score, factors = SubdomainRiskScorer.score(
                sd['subdomain'], domain,
                http_status=sd.get('http_status'),
                server=sd.get('server'),
                ip=sd.get('ip'),
            )
            sd['risk_score'] = score
            sd['risk_factors'] = factors

        subdomains.sort(key=lambda x: x['risk_score'], reverse=True)
        return subdomains


# ═══════════════════════════════════════════════════════════════════
#  PHASE 1: Async Crawl Engine — Concurrent HTTP Foundation
# ═══════════════════════════════════════════════════════════════════

class AsyncCrawlEngine:
    """
    Async HTTP engine using aiohttp for 5-10x faster concurrent requests.
    Falls back to ThreadPoolExecutor if aiohttp not available.
    Used for: subdomain probing, batch URL fetching, alive checks.
    """

    def __init__(self, max_concurrent: int = 30, timeout: int = 8,
                 rate_limit: float = 0, verbose: bool = False,
                 ua: str = None):
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.verbose = verbose
        self.ua = ua or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        self.results: List[Dict] = []

    def probe_subdomains(self, subdomains: List[str],
                         ports: List[int] = None) -> List[Dict]:
        """
        Probe subdomains for HTTP(S) services. Returns alive hosts with metadata.
        Uses async if available, falls back to threaded.
        """
        ports = ports or [443, 80]
        targets = []
        for sd in subdomains:
            for port in ports:
                scheme = 'https' if port == 443 else 'http'
                targets.append(f"{scheme}://{sd}:{port}" if port not in (80, 443)
                               else f"{scheme}://{sd}")

        if HAS_ASYNC:
            return self._probe_async(targets)
        else:
            return self._probe_threaded(targets)

    def _probe_async(self, urls: List[str]) -> List[Dict]:
        """Async probing with aiohttp."""
        results = []

        async def _probe_one(session, url, sem):
            async with sem:
                try:
                    if self.rate_limit > 0:
                        await asyncio.sleep(1.0 / self.rate_limit)
                    timeout = aiohttp.ClientTimeout(total=self.timeout)
                    async with session.get(url, timeout=timeout,
                                           allow_redirects=True,
                                           ssl=False) as resp:
                        server = resp.headers.get('Server', '')
                        content_type = resp.headers.get('Content-Type', '')
                        title = ''
                        # Read small chunk for title extraction
                        body = await resp.read()
                        body_text = body[:4000].decode('utf-8', errors='ignore')
                        m = re.search(r'<title[^>]*>([^<]+)</title>', body_text, re.I)
                        if m:
                            title = m.group(1).strip()[:80]

                        return {
                            'url': url,
                            'subdomain': urlparse(url).netloc,
                            'status': resp.status,
                            'server': server,
                            'content_type': content_type,
                            'title': title,
                            'content_length': len(body),
                            'redirect_url': str(resp.url) if str(resp.url) != url else '',
                            'alive': True,
                        }
                except Exception:
                    return None

        async def _run():
            sem = asyncio.Semaphore(self.max_concurrent)
            connector = aiohttp.TCPConnector(limit=self.max_concurrent, ssl=False)
            headers = {'User-Agent': self.ua}
            async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
                tasks = [_probe_one(session, url, sem) for url in urls]
                return await asyncio.gather(*tasks)

        if self.verbose:
            print(f"{Colors.OKCYAN}  [ASYNC] Probing {len(urls)} URLs "
                  f"({self.max_concurrent} concurrent)...{Colors.ENDC}")

        # Run the async event loop
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            raw_results = loop.run_until_complete(_run())
            loop.close()
        except Exception as e:
            if self.verbose:
                print(f"{Colors.WARNING}  [ASYNC] Fallback to threaded: {e}{Colors.ENDC}")
            return self._probe_threaded(urls)

        results = [r for r in raw_results if r is not None]
        if self.verbose:
            print(f"{Colors.OKGREEN}  [ASYNC] {len(results)}/{len(urls)} responded{Colors.ENDC}")
        return results

    def _probe_threaded(self, urls: List[str]) -> List[Dict]:
        """Fallback threaded probing."""
        results = []

        def _probe(url):
            try:
                resp = requests.get(url, timeout=self.timeout, verify=False,
                                    allow_redirects=True,
                                    headers={'User-Agent': self.ua})
                server = resp.headers.get('Server', '')
                title = ''
                m = re.search(r'<title[^>]*>([^<]+)</title>', resp.text[:4000], re.I)
                if m:
                    title = m.group(1).strip()[:80]
                return {
                    'url': url,
                    'subdomain': urlparse(url).netloc,
                    'status': resp.status_code,
                    'server': server,
                    'content_type': resp.headers.get('Content-Type', ''),
                    'title': title,
                    'content_length': len(resp.content),
                    'redirect_url': resp.url if resp.url != url else '',
                    'alive': True,
                }
            except Exception:
                return None

        if self.verbose:
            print(f"{Colors.OKCYAN}  [THREAD] Probing {len(urls)} URLs "
                  f"({min(self.max_concurrent, len(urls))} workers)...{Colors.ENDC}")

        with ThreadPoolExecutor(max_workers=min(self.max_concurrent, len(urls))) as pool:
            futures = {pool.submit(_probe, u): u for u in urls}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)

        if self.verbose:
            print(f"{Colors.OKGREEN}  [THREAD] {len(results)}/{len(urls)} responded{Colors.ENDC}")
        return results

    @staticmethod
    def dedupe_by_subdomain(results: List[Dict]) -> List[Dict]:
        """Keep best result per subdomain (prefer HTTPS, prefer 200)."""
        best = {}
        for r in results:
            sd = r['subdomain']
            if sd not in best:
                best[sd] = r
            else:
                existing = best[sd]
                # Prefer HTTPS
                if r['url'].startswith('https://') and existing['url'].startswith('http://'):
                    best[sd] = r
                # Prefer 200 over others
                elif r['status'] == 200 and existing['status'] != 200:
                    best[sd] = r
        return list(best.values())


# ═══════════════════════════════════════════════════════════════════
#  PHASE 1: Smart Router — Adaptive Module Selection
# ═══════════════════════════════════════════════════════════════════

class SmartRouter:
    """
    Intelligence-driven scanning. Analyzes each target and enables
    only the modules that make sense for that specific asset.

    This is the core differentiator: not --full, but --smart.
    Most tools scan everything everywhere. Arcanis chooses.
    """

    # Asset classification rules: pattern → asset type
    ASSET_RULES = {
        'api': {
            'type': 'api_service',
            'modules': ['cors_check', 'jwt_exploit', 'probe_graphql', 'probe_swagger', 'fuzz_idor'],
            'reason': 'API endpoint — test auth, CORS, schema exposure',
        },
        'graphql': {
            'type': 'api_service',
            'modules': ['probe_graphql', 'cors_check', 'jwt_exploit'],
            'reason': 'GraphQL service — introspection + auth testing',
        },
        'rest': {
            'type': 'api_service',
            'modules': ['cors_check', 'jwt_exploit', 'probe_swagger', 'fuzz_idor'],
            'reason': 'REST API — schema + auth + access control',
        },
        'admin': {
            'type': 'admin_panel',
            'modules': ['dom_xss', 'open_redirect', 'cors_check', 'probe_env'],
            'reason': 'Admin panel — high value, test for XSS + redirect + env leak',
        },
        'panel': {
            'type': 'admin_panel',
            'modules': ['dom_xss', 'open_redirect', 'cors_check', 'probe_env'],
            'reason': 'Control panel — test auth bypass vectors',
        },
        'dashboard': {
            'type': 'admin_panel',
            'modules': ['dom_xss', 'open_redirect', 'cors_check'],
            'reason': 'Dashboard — client-side injection + redirect chains',
        },
        'console': {
            'type': 'admin_panel',
            'modules': ['dom_xss', 'probe_env', 'cors_check'],
            'reason': 'Console — likely management interface',
        },
        'internal': {
            'type': 'internal',
            'modules': ['probe_env', 'ssrf_probe', 'cors_check', 'dom_xss'],
            'reason': 'Internal service — often less hardened',
        },
        'intranet': {
            'type': 'internal',
            'modules': ['probe_env', 'ssrf_probe', 'cors_check'],
            'reason': 'Intranet — exposed internal tools',
        },
        'staging': {
            'type': 'staging',
            'modules': ['probe_env', 'dom_xss', 'cors_check', 'open_redirect'],
            'reason': 'Staging env — debug mode, exposed configs likely',
        },
        'dev': {
            'type': 'staging',
            'modules': ['probe_env', 'dom_xss', 'cors_check', 'probe_swagger'],
            'reason': 'Dev environment — weak security posture expected',
        },
        'test': {
            'type': 'staging',
            'modules': ['probe_env', 'dom_xss', 'cors_check'],
            'reason': 'Test environment — may have debug endpoints',
        },
        'auth': {
            'type': 'auth_service',
            'modules': ['jwt_exploit', 'cors_check', 'open_redirect'],
            'reason': 'Auth service — JWT + OAuth redirect chains',
        },
        'sso': {
            'type': 'auth_service',
            'modules': ['jwt_exploit', 'cors_check', 'open_redirect'],
            'reason': 'SSO — token manipulation + redirect bypass',
        },
        'login': {
            'type': 'auth_service',
            'modules': ['jwt_exploit', 'open_redirect', 'cors_check'],
            'reason': 'Login endpoint — credential + redirect attacks',
        },
        'oauth': {
            'type': 'auth_service',
            'modules': ['jwt_exploit', 'open_redirect', 'cors_check'],
            'reason': 'OAuth endpoint — redirect_uri + state bypass',
        },
        'storage': {
            'type': 'cloud_storage',
            'modules': ['cloud_perms', 'scan_cloud'],
            'reason': 'Storage service — test read/write permissions',
        },
        's3': {
            'type': 'cloud_storage',
            'modules': ['cloud_perms', 'scan_cloud'],
            'reason': 'S3 reference — bucket permission testing',
        },
        'cdn': {
            'type': 'static_asset',
            'modules': ['dep_confusion'],
            'reason': 'CDN — check source maps for dependency confusion',
        },
        'static': {
            'type': 'static_asset',
            'modules': ['dep_confusion'],
            'reason': 'Static assets — source map intelligence only',
        },
        'assets': {
            'type': 'static_asset',
            'modules': ['dep_confusion'],
            'reason': 'Asset server — source map mining',
        },
        'jenkins': {
            'type': 'ci_cd',
            'modules': ['probe_env', 'cors_check', 'ssrf_probe'],
            'reason': 'Jenkins CI — credential exposure + SSRF',
        },
        'gitlab': {
            'type': 'ci_cd',
            'modules': ['probe_env', 'cors_check'],
            'reason': 'GitLab — repo access + secret exposure',
        },
        'ci': {
            'type': 'ci_cd',
            'modules': ['probe_env', 'cors_check'],
            'reason': 'CI/CD — pipeline secrets',
        },
        'grafana': {
            'type': 'monitoring',
            'modules': ['cors_check', 'ssrf_probe', 'probe_env'],
            'reason': 'Grafana — SSRF via data sources + default creds',
        },
        'kibana': {
            'type': 'monitoring',
            'modules': ['cors_check', 'ssrf_probe'],
            'reason': 'Kibana — data access + SSRF',
        },
        'db': {
            'type': 'database',
            'modules': ['probe_env', 'ssrf_probe'],
            'reason': 'Database interface — connection string exposure',
        },
        'mongo': {
            'type': 'database',
            'modules': ['probe_env', 'cloud_perms'],
            'reason': 'MongoDB — open access testing',
        },
        'redis': {
            'type': 'database',
            'modules': ['probe_env', 'ssrf_probe'],
            'reason': 'Redis — unauthenticated access',
        },
        'mail': {
            'type': 'email',
            'modules': ['cors_check', 'open_redirect'],
            'reason': 'Mail service — phishing redirect potential',
        },
        'vpn': {
            'type': 'remote_access',
            'modules': ['cors_check', 'probe_env'],
            'reason': 'VPN — credential exposure',
        },
    }

    # Default modules for unknown asset types
    DEFAULT_MODULES = ['probe_env', 'cors_check', 'dom_xss']

    # Always-on modules (run on every target regardless)
    ALWAYS_ON = ['verify', 'scan_cloud']

    @staticmethod
    def classify(subdomain: str, domain: str, http_data: dict = None) -> dict:
        """
        Classify a subdomain and determine which modules to enable.
        Returns: {'type': str, 'modules': list, 'reasons': list}
        """
        prefix = subdomain.replace(f".{domain}", "").lower()
        parts = re.split(r'[.\-_]', prefix)

        matched_modules = set()
        matched_types = set()
        reasons = []

        for part in parts:
            if part in SmartRouter.ASSET_RULES:
                rule = SmartRouter.ASSET_RULES[part]
                matched_modules.update(rule['modules'])
                matched_types.add(rule['type'])
                reasons.append(rule['reason'])

        # HTTP-based classification
        if http_data:
            title = (http_data.get('title', '') or '').lower()
            server = (http_data.get('server', '') or '').lower()
            ct = (http_data.get('content_type', '') or '').lower()

            # JSON API response → enable API modules
            if 'application/json' in ct:
                matched_modules.update(['cors_check', 'jwt_exploit', 'fuzz_idor'])
                matched_types.add('api_service')
                reasons.append('JSON content-type — likely API')

            # GraphQL indicator in response
            if 'graphql' in title or 'graphiql' in title:
                matched_modules.update(['probe_graphql', 'cors_check'])
                reasons.append('GraphQL detected in title')

            # Swagger/OpenAPI indicator
            if 'swagger' in title or 'openapi' in title:
                matched_modules.update(['probe_swagger', 'cors_check'])
                reasons.append('Swagger/OpenAPI detected')

            # Login page
            if any(kw in title for kw in ['login', 'sign in', 'log in', 'authenticate']):
                matched_modules.update(['jwt_exploit', 'open_redirect', 'cors_check'])
                matched_types.add('auth_service')
                reasons.append('Login page detected')

            # Admin indicators
            if any(kw in title for kw in ['admin', 'dashboard', 'panel', 'console', 'management']):
                matched_modules.update(['dom_xss', 'probe_env', 'cors_check'])
                matched_types.add('admin_panel')
                reasons.append('Admin interface detected in title')

            # Server-based hints
            if 'express' in server or 'node' in server:
                matched_modules.add('dep_confusion')
                reasons.append('Node.js server — check npm deps')
            if 'nginx' in server and http_data.get('status') == 403:
                matched_modules.add('probe_env')
                reasons.append('Nginx 403 — might have hidden paths')

        # Fallback: if nothing matched, use defaults
        if not matched_modules:
            matched_modules = set(SmartRouter.DEFAULT_MODULES)
            matched_types.add('web_app')
            reasons.append('Unknown asset type — using default modules')

        # Always-on modules
        matched_modules.update(SmartRouter.ALWAYS_ON)

        # Determine primary type
        type_priority = ['auth_service', 'admin_panel', 'api_service', 'ci_cd',
                         'database', 'internal', 'staging', 'cloud_storage',
                         'monitoring', 'remote_access', 'email', 'static_asset', 'web_app']
        primary_type = 'web_app'
        for t in type_priority:
            if t in matched_types:
                primary_type = t
                break

        return {
            'type': primary_type,
            'modules': sorted(matched_modules),
            'reasons': reasons,
        }

    @staticmethod
    def plan(targets: List[dict], domain: str, verbose: bool = False) -> List[dict]:
        """
        Build a scan plan: for each target, determine what to scan.
        Returns targets enriched with module selections.
        """
        plans = []
        module_usage = defaultdict(int)

        for target in targets:
            sd = target.get('subdomain', '')
            classification = SmartRouter.classify(sd, domain, target)
            target['smart_type'] = classification['type']
            target['smart_modules'] = classification['modules']
            target['smart_reasons'] = classification['reasons']
            plans.append(target)

            for mod in classification['modules']:
                module_usage[mod] += 1

        if verbose or True:  # Always show the plan — it's the key feature
            print(f"\n{Colors.BOLD}{'=' * 60}")
            print(f"  SMART SCAN PLAN — {len(plans)} targets")
            print(f"{'=' * 60}{Colors.ENDC}")

            # Group by type
            by_type = defaultdict(list)
            for p in plans:
                by_type[p['smart_type']].append(p)

            type_colors = {
                'auth_service': Colors.FAIL,
                'admin_panel': Colors.FAIL,
                'api_service': Colors.WARNING,
                'ci_cd': Colors.FAIL,
                'database': Colors.FAIL,
                'internal': Colors.WARNING,
                'staging': Colors.WARNING,
                'cloud_storage': Colors.OKCYAN,
                'monitoring': Colors.OKCYAN,
                'web_app': Colors.DIM,
                'static_asset': Colors.DIM,
            }

            type_order = ['auth_service', 'admin_panel', 'database', 'ci_cd',
                          'api_service', 'internal', 'staging', 'monitoring',
                          'cloud_storage', 'web_app', 'static_asset']

            for asset_type in type_order:
                group = by_type.get(asset_type, [])
                if not group:
                    continue
                color = type_colors.get(asset_type, Colors.DIM)
                label = asset_type.upper().replace('_', ' ')
                print(f"\n  {color}{label} ({len(group)}):{Colors.ENDC}")
                for p in group[:8]:
                    mods = ', '.join(m for m in p['smart_modules']
                                     if m not in SmartRouter.ALWAYS_ON)
                    reason = p['smart_reasons'][0] if p['smart_reasons'] else ''
                    print(f"    [{p.get('risk_score', 0):3d}] {p['subdomain']}")
                    print(f"         {Colors.DIM}modules: {mods}{Colors.ENDC}")
                    if reason:
                        print(f"         {Colors.DIM}reason: {reason}{Colors.ENDC}")
                if len(group) > 8:
                    print(f"    {Colors.DIM}... +{len(group) - 8} more{Colors.ENDC}")

            # Module usage summary
            print(f"\n  {Colors.BOLD}Module Activation:{Colors.ENDC}")
            for mod, count in sorted(module_usage.items(), key=lambda x: -x[1]):
                if mod in SmartRouter.ALWAYS_ON:
                    continue
                bar = '+' * min(count, 30)
                print(f"    {mod:20s} {bar} ({count})")
            print()

        return plans

    @staticmethod
    def get_modules_for_url(url: str, plans: List[dict]) -> set:
        """Given a URL, return which modules should be active for it."""
        parsed = urlparse(url)
        netloc = parsed.netloc.lower()

        for plan in plans:
            if plan.get('subdomain', '').lower() == netloc:
                return set(plan.get('smart_modules', []))

        # URL not in plan — return defaults + always-on
        return set(SmartRouter.DEFAULT_MODULES + SmartRouter.ALWAYS_ON)



class ReconOrchestrator:
    """
    Orchestrates the full recon pipeline:
    1. CT log query → raw subdomains
    2. DNS resolution → filter dead
    3. HTTP probing → check alive with metadata
    4. Risk scoring → prioritize targets
    5. Store in DB → persist for incremental scans
    """

    def __init__(self, session, db: ArcanisDB = None, verbose: bool = False,
                 rate_limit: float = 0, max_workers: int = 20):
        self.session = session
        self.db = db
        self.verbose = verbose
        self.ct = CertTransparency(session, verbose)
        self.dns = DNSResolver(verbose, max_workers=max_workers)
        self.async_engine = AsyncCrawlEngine(
            max_concurrent=max_workers, rate_limit=rate_limit, verbose=verbose
        )
        self.subdomains: List[Dict] = []
        self.stats = {
            'ct_total': 0, 'dns_alive': 0, 'dns_dead': 0,
            'http_alive': 0, 'high_risk': 0,
        }

    def discover(self, domain: str, skip_dns: bool = False) -> List[Dict]:
        """
        Full recon pipeline. Returns prioritized list of alive subdomains.
        """
        print(f"\n{Colors.BOLD}{'=' * 60}")
        print(f"  RECON: Subdomain Discovery & Risk Scoring")
        print(f"{'=' * 60}{Colors.ENDC}")

        # Step 1: CT log query
        raw_subdomains = self.ct.query(domain)
        self.stats['ct_total'] = len(raw_subdomains)
        if not raw_subdomains:
            print(f"{Colors.WARNING}  [!] No subdomains found via CT logs{Colors.ENDC}")
            return []

        # Step 2: DNS resolution
        if not skip_dns:
            alive_hosts = self.dns.resolve_batch(raw_subdomains)
            self.stats['dns_alive'] = len(alive_hosts)
            self.stats['dns_dead'] = len(self.dns.dead)
        else:
            alive_hosts = [{'subdomain': s, 'ip': None, 'alive': True} for s in raw_subdomains]
            self.stats['dns_alive'] = len(alive_hosts)

        if not alive_hosts:
            print(f"{Colors.WARNING}  [!] No subdomains resolved — all appear dead{Colors.ENDC}")
            return []

        # Step 3: HTTP probing
        alive_subs = [h['subdomain'] for h in alive_hosts]
        http_results = self.async_engine.probe_subdomains(alive_subs)
        http_results = AsyncCrawlEngine.dedupe_by_subdomain(http_results)
        self.stats['http_alive'] = len(http_results)

        # Merge DNS + HTTP data
        ip_map = {h['subdomain']: h.get('ip') for h in alive_hosts}
        for r in http_results:
            r['ip'] = ip_map.get(r['subdomain'], '')

        # Step 4: Risk scoring
        scored = SubdomainRiskScorer.prioritize(http_results, domain)
        self.stats['high_risk'] = sum(1 for s in scored if s['risk_score'] >= 60)
        self.subdomains = scored

        # Step 5: Store in DB
        if self.db:
            for sd in scored:
                self.db.save_subdomain(
                    domain=domain,
                    subdomain=sd['subdomain'],
                    source='ct',
                    is_alive=True,
                    ip_address=sd.get('ip'),
                    risk_score=sd['risk_score'],
                    risk_factors=sd.get('risk_factors', []),
                )

        # Print summary
        self._print_results(domain, scored)
        return scored

    def _print_results(self, domain: str, scored: List[Dict]):
        """Display discovered subdomains grouped by risk."""
        print(f"\n{Colors.BOLD}  Recon Results for {domain}{Colors.ENDC}")
        print(f"  CT entries: {self.stats['ct_total']} | "
              f"DNS alive: {self.stats['dns_alive']} | "
              f"HTTP alive: {self.stats['http_alive']} | "
              f"High risk: {self.stats['high_risk']}")
        print()

        # Group by risk tier
        critical = [s for s in scored if s['risk_score'] >= 70]
        high     = [s for s in scored if 50 <= s['risk_score'] < 70]
        medium   = [s for s in scored if 30 <= s['risk_score'] < 50]
        low      = [s for s in scored if s['risk_score'] < 30]

        for label, group, color in [
            ("HIGH PRIORITY", critical, Colors.FAIL),
            ("MEDIUM PRIORITY", high, Colors.WARNING),
            ("NORMAL", medium, Colors.OKCYAN),
            ("LOW PRIORITY", low, Colors.DIM),
        ]:
            if not group:
                continue
            print(f"  {color}{label} ({len(group)}):{Colors.ENDC}")
            for sd in group[:10]:  # Show top 10 per tier
                risk = sd['risk_score']
                status = sd.get('status', '?')
                title = sd.get('title', '')[:40]
                server = sd.get('server', '')[:20]
                factors = ', '.join(sd.get('risk_factors', [])[:3])

                print(f"    {color}[{risk:3d}] {sd['subdomain']}{Colors.ENDC}"
                      f"  HTTP:{status}"
                      f"  {title}"
                      f"  {Colors.DIM}{factors}{Colors.ENDC}")
            if len(group) > 10:
                print(f"    {Colors.DIM}... and {len(group) - 10} more{Colors.ENDC}")
            print()

    def get_scan_urls(self, top_n: int = None) -> List[str]:
        """Get prioritized URLs to feed into the scanner."""
        urls = []
        subs = self.subdomains[:top_n] if top_n else self.subdomains
        for sd in subs:
            urls.append(sd.get('url', f"https://{sd['subdomain']}"))
        return urls


# ═══════════════════════════════════════════════════════════════════
#  v6.0: CORS Misconfiguration Detector
# ═══════════════════════════════════════════════════════════════════

class CORSDetector:
    """
    Test for CORS misconfigurations: reflected origins, null origin,
    subdomain wildcards, credential leakage.
    """

    def __init__(self, session, rate_limiter, verbose=False):
        self.session = session
        self.rate_limiter = rate_limiter
        self.verbose = verbose
        self.findings: List[Dict] = []

    def test_url(self, url: str, target_domain: str):
        """Run all CORS tests against a URL."""
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        tests = [
            # (origin_to_send, test_name, severity_if_reflected)
            ("https://evil.com", "arbitrary_origin", "CRITICAL"),
            ("null", "null_origin", "HIGH"),
            (f"https://{target_domain}.evil.com", "subdomain_suffix", "HIGH"),
            (f"https://evil-{target_domain}", "prefix_bypass", "HIGH"),
            (f"https://sub.{target_domain}", "subdomain_match", "MEDIUM"),
            (origin.replace("https://", "http://"), "http_downgrade", "MEDIUM"),
        ]

        for test_origin, test_name, severity in tests:
            try:
                self.rate_limiter.wait()
                headers = {'Origin': test_origin}
                resp = self.session.get(url, headers=headers, timeout=8, allow_redirects=False)
                if resp is None:
                    continue

                acao = resp.headers.get('Access-Control-Allow-Origin', '')
                acac = resp.headers.get('Access-Control-Allow-Credentials', '').lower()

                if not acao:
                    continue

                vuln = False
                detail = ""

                if acao == '*' and acac == 'true':
                    vuln = True
                    severity = "CRITICAL"
                    detail = "Wildcard origin with credentials — full CORS bypass"
                elif acao == test_origin and test_name in ('arbitrary_origin', 'subdomain_suffix', 'prefix_bypass'):
                    vuln = True
                    cred_note = " WITH credentials" if acac == 'true' else ""
                    detail = f"Origin '{test_origin}' reflected{cred_note} ({test_name})"
                    if acac == 'true':
                        severity = "CRITICAL"
                elif acao == 'null' and test_name == 'null_origin':
                    vuln = True
                    detail = "null origin accepted — sandbox/iframe CORS bypass"
                    if acac == 'true':
                        severity = "CRITICAL"

                if vuln:
                    finding = {
                        'type': 'CORS Misconfiguration',
                        'url': url,
                        'test': test_name,
                        'severity': severity,
                        'origin_sent': test_origin,
                        'acao': acao,
                        'credentials': acac == 'true',
                        'detail': detail,
                    }
                    self.findings.append(finding)
                    if self.verbose:
                        sev_color = {'CRITICAL': Colors.FAIL, 'HIGH': Colors.WARNING}.get(severity, Colors.OKCYAN)
                        print(f"{sev_color}  [CORS] [{severity}] {detail}{Colors.ENDC}")
                    break  # One finding per URL is enough

            except Exception:
                continue

    def get_summary(self) -> dict:
        critical = sum(1 for f in self.findings if f['severity'] == 'CRITICAL')
        return {
            'total': len(self.findings),
            'critical': critical,
            'findings': self.findings,
        }


# ═══════════════════════════════════════════════════════════════════
#  v6.0: Open Redirect Detector
# ═══════════════════════════════════════════════════════════════════

class OpenRedirectDetector:
    """
    Detect open redirect vulnerabilities by testing URL parameters
    with external redirect targets.
    """

    REDIRECT_PARAMS = [
        'redirect', 'redirect_uri', 'redirect_url', 'redir',
        'next', 'url', 'return', 'return_to', 'returnTo',
        'goto', 'dest', 'destination', 'continue', 'forward',
        'rurl', 'target', 'link', 'out', 'view', 'ref',
        'callback', 'cb', 'jump', 'to', 'path',
    ]

    PAYLOADS = [
        'https://evil.com',
        '//evil.com',
        '/\\evil.com',
        'https:evil.com',
        '////evil.com',
        'https://evil.com%00.target.com',
        'https://evil.com%23.target.com',
    ]

    def __init__(self, session, rate_limiter, verbose=False):
        self.session = session
        self.rate_limiter = rate_limiter
        self.verbose = verbose
        self.findings: List[Dict] = []
        self._tested = set()

    def scan_url(self, url: str):
        """Test URL parameters for open redirect."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # Test existing redirect-like parameters
        for param in params:
            if param.lower() in self.REDIRECT_PARAMS:
                self._test_param(url, param)

        # Also probe common redirect params if not present
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        for param in self.REDIRECT_PARAMS[:8]:  # Top 8 most common
            test_key = f"{base_url}:{param}"
            if test_key not in self._tested:
                self._tested.add(test_key)
                test_url = f"{base_url}?{param}=https://evil.com"
                self._test_redirect(test_url, param, "https://evil.com")

    def _test_param(self, url: str, param: str):
        """Test a specific parameter with multiple payloads."""
        parsed = urlparse(url)
        for payload in self.PAYLOADS[:3]:  # Limit to 3 payloads per param
            key = f"{parsed.netloc}{parsed.path}:{param}:{payload}"
            if key in self._tested:
                continue
            self._tested.add(key)

            # Replace the param value
            params = parse_qs(parsed.query)
            params[param] = [payload]
            new_query = urlencode(params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
            self._test_redirect(test_url, param, payload)

    def _test_redirect(self, url: str, param: str, payload: str):
        """Send request and check if redirect goes to our target."""
        try:
            self.rate_limiter.wait()
            resp = self.session.get(url, timeout=8, allow_redirects=False)
            if resp is None:
                return

            location = resp.headers.get('Location', '')
            status = resp.status_code

            is_redirect = status in (301, 302, 303, 307, 308)
            redirects_external = False

            if is_redirect and location:
                loc_parsed = urlparse(location)
                if loc_parsed.netloc and 'evil.com' in loc_parsed.netloc:
                    redirects_external = True
                elif location.startswith('//evil.com') or location.startswith('/\\evil.com'):
                    redirects_external = True

            # Also check meta refresh in body
            if not is_redirect and status == 200:
                body = resp.text[:2000].lower()
                if 'evil.com' in body and ('meta' in body and 'refresh' in body or 'window.location' in body):
                    redirects_external = True

            if redirects_external:
                severity = "HIGH" if 'oauth' in url.lower() or 'auth' in url.lower() else "MEDIUM"
                finding = {
                    'type': 'Open Redirect',
                    'url': url,
                    'param': param,
                    'payload': payload,
                    'severity': severity,
                    'status_code': status,
                    'location': location[:200],
                    'detail': f"Parameter '{param}' redirects to external domain",
                }
                self.findings.append(finding)
                if self.verbose:
                    print(f"{Colors.WARNING}  [REDIRECT] [{severity}] "
                          f"?{param}= redirects to evil.com (HTTP {status}){Colors.ENDC}")
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════
#  v6.0: Cloud Permission Tester
# ═══════════════════════════════════════════════════════════════════

class CloudPermissionTester:
    """
    Test discovered cloud resources for misconfigurations:
    - S3 bucket listing/write
    - GCS bucket access
    - Firebase open read
    - Azure blob public access
    """

    def __init__(self, session, rate_limiter, verbose=False):
        self.session = session
        self.rate_limiter = rate_limiter
        self.verbose = verbose
        self.findings: List[Dict] = []

    def test_s3_bucket(self, bucket_name: str):
        """Test S3 bucket for public listing and write access."""
        bucket_name = bucket_name.strip().strip('/')
        urls_to_try = [
            f"https://{bucket_name}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{bucket_name}",
        ]

        for base_url in urls_to_try:
            try:
                # Test LIST
                self.rate_limiter.wait()
                resp = self.session.get(base_url, timeout=10)
                if resp and resp.status_code == 200:
                    body = resp.text[:5000]
                    if '<ListBucketResult' in body or '<Contents>' in body:
                        # Count objects
                        import re as _re
                        keys = _re.findall(r'<Key>([^<]+)</Key>', body)
                        self.findings.append({
                            'type': 'S3 Bucket Public Listing',
                            'severity': 'HIGH',
                            'bucket': bucket_name,
                            'url': base_url,
                            'objects_visible': len(keys),
                            'sample_keys': keys[:5],
                            'detail': f"S3 bucket '{bucket_name}' allows public listing ({len(keys)} objects visible)",
                        })
                        if self.verbose:
                            print(f"{Colors.FAIL}  [S3] [HIGH] Public listing: {bucket_name} "
                                  f"({len(keys)} objects){Colors.ENDC}")

                        # Test WRITE (safe — upload empty test file, immediately delete)
                        test_key = f"arcanis-security-test-{int(time.time())}.txt"
                        try:
                            self.rate_limiter.wait()
                            put_resp = self.session.put(
                                f"{base_url}/{test_key}",
                                data="arcanis security test - safe to delete",
                                timeout=8
                            )
                            if put_resp and put_resp.status_code in (200, 204):
                                self.findings.append({
                                    'type': 'S3 Bucket Public Write',
                                    'severity': 'CRITICAL',
                                    'bucket': bucket_name,
                                    'url': base_url,
                                    'detail': f"S3 bucket '{bucket_name}' allows PUBLIC WRITE — full takeover possible",
                                })
                                if self.verbose:
                                    print(f"{Colors.FAIL}  [S3] [CRITICAL] PUBLIC WRITE: {bucket_name}{Colors.ENDC}")
                                # Clean up
                                try:
                                    self.session.delete(f"{base_url}/{test_key}", timeout=5)
                                except Exception:
                                    pass
                        except Exception:
                            pass
                        return  # Found listing, no need to try other URL format
                elif resp and resp.status_code == 403:
                    # Bucket exists but not listable — that's OK
                    pass
                elif resp and resp.status_code == 404:
                    pass  # Bucket doesn't exist
            except Exception:
                continue

    def test_gcs_bucket(self, bucket_url: str):
        """Test GCS bucket/object for public access."""
        try:
            self.rate_limiter.wait()
            resp = self.session.get(bucket_url, timeout=10)
            if resp and resp.status_code == 200:
                # Check if it's a directory listing
                ct = resp.headers.get('Content-Type', '')
                if 'xml' in ct and '<ListBucketResult' in resp.text[:1000]:
                    self.findings.append({
                        'type': 'GCS Bucket Public Listing',
                        'severity': 'HIGH',
                        'url': bucket_url,
                        'detail': f"GCS bucket allows public listing",
                    })
                    if self.verbose:
                        print(f"{Colors.FAIL}  [GCS] [HIGH] Public listing: {bucket_url}{Colors.ENDC}")
        except Exception:
            pass

    def test_firebase(self, firebase_url: str):
        """Test Firebase for open read access."""
        # Firebase DBs expose data at /.json
        base = firebase_url.rstrip('/')
        if not base.endswith('.json'):
            test_url = base + '/.json'
        else:
            test_url = base

        try:
            self.rate_limiter.wait()
            resp = self.session.get(test_url, timeout=10)
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    if data and data != 'null' and isinstance(data, dict):
                        keys = list(data.keys())[:10]
                        self.findings.append({
                            'type': 'Firebase Open Read',
                            'severity': 'CRITICAL',
                            'url': test_url,
                            'collections': keys,
                            'detail': f"Firebase database is publicly readable ({len(keys)} top-level collections)",
                        })
                        if self.verbose:
                            print(f"{Colors.FAIL}  [FIREBASE] [CRITICAL] Open read: {test_url} "
                                  f"({', '.join(keys[:5])}){Colors.ENDC}")
                except Exception:
                    pass
        except Exception:
            pass

    def test_azure_blob(self, container_url: str):
        """Test Azure blob container for public listing."""
        test_url = container_url.rstrip('/') + '?restype=container&comp=list'
        try:
            self.rate_limiter.wait()
            resp = self.session.get(test_url, timeout=10)
            if resp and resp.status_code == 200 and '<EnumerationResults' in resp.text[:1000]:
                self.findings.append({
                    'type': 'Azure Blob Public Listing',
                    'severity': 'HIGH',
                    'url': container_url,
                    'detail': "Azure blob container allows public listing",
                })
                if self.verbose:
                    print(f"{Colors.FAIL}  [AZURE] [HIGH] Public listing: {container_url}{Colors.ENDC}")
        except Exception:
            pass

    def test_from_findings(self, findings: List[Dict]):
        """Auto-test cloud resources found by the secret scanner."""
        for f in findings:
            ftype = f.get('type', '')
            value = f.get('value', '')

            if ftype == 'AWS S3 Bucket' or ('s3.amazonaws.com' in value and 'amazonaws' in value):
                # Extract bucket name
                if 's3.amazonaws.com/' in value:
                    bucket = value.split('s3.amazonaws.com/')[-1].split('/')[0]
                elif '.s3.' in value:
                    bucket = urlparse(value).netloc.split('.s3.')[0]
                else:
                    bucket = value
                if bucket:
                    self.test_s3_bucket(bucket)

            elif ftype == 'GCS Bucket' or 'storage.googleapis.com' in value:
                self.test_gcs_bucket(value)

            elif 'firebaseio.com' in value or 'firebase' in value.lower():
                self.test_firebase(value)

            elif '.blob.core.windows.net' in value:
                self.test_azure_blob(value)


# ═══════════════════════════════════════════════════════════════════
#  v6.0: DOM XSS Sink/Source Mapper
# ═══════════════════════════════════════════════════════════════════

class DOMXSSMapper:
    """
    Static analysis of JavaScript to map DOM XSS sources → sinks.
    Identifies potential DOM XSS attack vectors without active exploitation.
    """

    SOURCES = {
        'location.hash': 'URL fragment',
        'location.search': 'URL query string',
        'location.href': 'Full URL',
        'location.pathname': 'URL path',
        'document.referrer': 'Referrer header',
        'document.URL': 'Document URL',
        'document.documentURI': 'Document URI',
        'window.name': 'Window name (cross-origin writable)',
        'document.cookie': 'Cookie values',
        'window.location': 'Window location',
        'postMessage': 'Cross-origin message',
        'addEventListener\\s*\\(\\s*[\'"]message': 'postMessage listener',
        'URLSearchParams': 'URL parameter parser',
        'url\\.searchParams': 'URL search params',
    }

    SINKS = {
        'innerHTML': 'HTML injection — HIGH risk',
        'outerHTML': 'HTML injection — HIGH risk',
        'document\\.write': 'Document write — HIGH risk',
        'document\\.writeln': 'Document writeln — HIGH risk',
        'eval\\s*\\(': 'Code execution — CRITICAL risk',
        'setTimeout\\s*\\(\\s*["\']': 'String-based setTimeout — HIGH risk',
        'setTimeout\\s*\\(\\s*[^,)]+\\+': 'Concatenated setTimeout — MEDIUM risk',
        'setInterval\\s*\\(\\s*["\']': 'String-based setInterval — HIGH risk',
        'Function\\s*\\(': 'Dynamic Function — CRITICAL risk',
        '\\.html\\s*\\(': 'jQuery .html() — HIGH risk',
        'insertAdjacentHTML': 'Adjacent HTML injection — HIGH risk',
        'createContextualFragment': 'Fragment injection — HIGH risk',
        'srcdoc\\s*=': 'iframe srcdoc — HIGH risk',
        'v-html': 'Vue v-html directive — HIGH risk',
        'dangerouslySetInnerHTML': 'React dangerous HTML — HIGH risk',
        '\\$sce\\.trustAsHtml': 'Angular trust HTML — HIGH risk',
        'bypassSecurityTrust': 'Angular security bypass — CRITICAL risk',
    }

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.findings: List[Dict] = []
        self._compiled_sources = {k: re.compile(k, re.IGNORECASE) for k in self.SOURCES}
        self._compiled_sinks = {k: re.compile(k, re.IGNORECASE) for k in self.SINKS}

    def analyze(self, js_content: str, source_url: str):
        """Analyze JS content for DOM XSS source → sink flows."""
        if not js_content or len(js_content) < 50:
            return

        found_sources = []
        found_sinks = []

        # Scan for sources
        for pattern, desc in self.SOURCES.items():
            regex = self._compiled_sources[pattern]
            matches = regex.finditer(js_content)
            for m in matches:
                # Get line number approximation
                line_no = js_content[:m.start()].count('\n') + 1
                found_sources.append({
                    'pattern': pattern.replace('\\s*', ' ').replace('\\(', '('),
                    'description': desc,
                    'line': line_no,
                    'context': js_content[max(0, m.start()-30):m.end()+30].strip(),
                })

        # Scan for sinks
        for pattern, desc in self.SINKS.items():
            regex = self._compiled_sinks[pattern]
            matches = regex.finditer(js_content)
            for m in matches:
                line_no = js_content[:m.start()].count('\n') + 1
                found_sinks.append({
                    'pattern': pattern.replace('\\s*', ' ').replace('\\(', '('),
                    'description': desc,
                    'line': line_no,
                    'context': js_content[max(0, m.start()-30):m.end()+30].strip(),
                })

        if found_sources and found_sinks:
            # Determine severity based on sink types
            has_critical = any('CRITICAL' in s['description'] for s in found_sinks)
            has_high = any('HIGH' in s['description'] for s in found_sinks)
            severity = 'CRITICAL' if has_critical else ('HIGH' if has_high else 'MEDIUM')

            finding = {
                'type': 'DOM XSS Vector',
                'severity': severity,
                'url': source_url,
                'sources': found_sources[:10],
                'sinks': found_sinks[:10],
                'source_count': len(found_sources),
                'sink_count': len(found_sinks),
                'detail': (f"{len(found_sources)} source(s) + {len(found_sinks)} sink(s) "
                           f"in {source_url.split('/')[-1][:40]}"),
            }
            self.findings.append(finding)

            if self.verbose:
                sc = Colors.FAIL if severity == 'CRITICAL' else Colors.WARNING
                print(f"{sc}  [DOM-XSS] [{severity}] {len(found_sources)} sources → "
                      f"{len(found_sinks)} sinks in {source_url.split('/')[-1][:50]}{Colors.ENDC}")
                for src in found_sources[:3]:
                    print(f"{Colors.DIM}    Source: {src['pattern']} (line ~{src['line']}){Colors.ENDC}")
                for snk in found_sinks[:3]:
                    print(f"{Colors.DIM}    Sink: {snk['pattern']} — {snk['description']}{Colors.ENDC}")

        elif found_sinks and not found_sources:
            # Sinks without visible sources — still worth noting
            if len(found_sinks) >= 3:
                self.findings.append({
                    'type': 'DOM XSS Sinks (no source mapped)',
                    'severity': 'LOW',
                    'url': source_url,
                    'sinks': found_sinks[:10],
                    'sink_count': len(found_sinks),
                    'detail': f"{len(found_sinks)} dangerous sink(s), sources may be in other files",
                })


# ═══════════════════════════════════════════════════════════════════
#  v6.0: Dependency Confusion Scanner
# ═══════════════════════════════════════════════════════════════════

class DependencyConfusionScanner:
    """
    From source maps, detect internal/scoped npm packages that
    may not exist on public registries → dependency confusion attack.
    """

    def __init__(self, session, rate_limiter, verbose=False):
        self.session = session
        self.rate_limiter = rate_limiter
        self.verbose = verbose
        self.findings: List[Dict] = []
        self._checked = set()

    def check_packages(self, packages: List[str], target_domain: str = ""):
        """Check if scoped/internal packages exist on public npm."""
        for pkg in packages:
            pkg = pkg.strip()
            if not pkg or pkg in self._checked:
                continue
            self._checked.add(pkg)

            # Only check scoped packages (@company/xxx) or unusual names
            is_scoped = pkg.startswith('@')
            is_internal_looking = any(kw in pkg.lower() for kw in [
                'internal', 'private', 'core', 'shared', 'common',
                'utils', 'helpers', 'config', 'auth', 'lib',
            ])

            # Also check if package name contains the target domain
            domain_parts = target_domain.replace('.com', '').replace('.my', '').replace('.io', '').split('.')
            has_domain = any(part in pkg.lower() for part in domain_parts if len(part) > 3)

            if not (is_scoped or is_internal_looking or has_domain):
                continue

            # Check npm registry
            try:
                self.rate_limiter.wait()
                npm_url = f"https://registry.npmjs.org/{pkg}"
                resp = self.session.get(npm_url, timeout=8)

                if resp and resp.status_code == 404:
                    # Package doesn't exist on public npm — potential confusion!
                    severity = "CRITICAL" if is_scoped else "HIGH"
                    finding = {
                        'type': 'Dependency Confusion',
                        'severity': severity,
                        'package': pkg,
                        'detail': (f"Package '{pkg}' used in source but NOT on public npm — "
                                   f"dependency confusion attack possible"),
                        'is_scoped': is_scoped,
                    }
                    self.findings.append(finding)
                    if self.verbose:
                        print(f"{Colors.FAIL}  [DEP-CONFUSION] [{severity}] '{pkg}' "
                              f"NOT on public npm!{Colors.ENDC}")

                elif resp and resp.status_code == 200:
                    # Exists — check if it might be a squatter
                    try:
                        data = resp.json()
                        latest = data.get('dist-tags', {}).get('latest', '')
                        created = data.get('time', {}).get('created', '')[:10]
                        weekly = data.get('downloads', 0) if 'downloads' in data else 'unknown'

                        # Suspicious if very low downloads or very recent
                        if has_domain and created:
                            self.findings.append({
                                'type': 'Dependency Confusion (potential squatter)',
                                'severity': 'MEDIUM',
                                'package': pkg,
                                'npm_version': latest,
                                'npm_created': created,
                                'detail': (f"Package '{pkg}' exists on npm (v{latest}, created {created}) — "
                                           f"verify this is the intended package"),
                            })
                    except Exception:
                        pass

            except Exception:
                continue

    def check_from_source_maps(self, source_map_intel: List[Dict], target_domain: str = ""):
        """Extract packages from source map data and check them."""
        all_packages = set()
        for sm in source_map_intel:
            if sm.get('npm_packages'):
                all_packages.update(sm['npm_packages'])

        if all_packages:
            if self.verbose:
                print(f"{Colors.OKCYAN}  [*] Checking {len(all_packages)} packages for "
                      f"dependency confusion...{Colors.ENDC}")
            self.check_packages(list(all_packages), target_domain)


# ═══════════════════════════════════════════════════════════════════
#  v6.0: JWT Deep Exploitation Tester
# ═══════════════════════════════════════════════════════════════════

class JWTExploitTester:
    """
    Extends JWTAnalyzer with active exploitation tests:
    - alg:none bypass
    - HS256 weak secret brute-force
    - RS256→HS256 algorithm confusion
    - Expired token acceptance
    """

    COMMON_SECRETS = [
        'secret', 'password', 'key', '123456', 'admin',
        'jwt_secret', 'changeme', 'default', 'test',
        'supersecret', 'mysecret', 'your-256-bit-secret',
        'shhhhh', 'keyboard cat', 'secretkey',
    ]

    def __init__(self, session, rate_limiter, verbose=False):
        self.session = session
        self.rate_limiter = rate_limiter
        self.verbose = verbose
        self.findings: List[Dict] = []

    def test_token(self, token: str, source_url: str):
        """Run all JWT exploitation tests."""
        analysis = JWTAnalyzer.analyze(token)
        if not analysis:
            return

        header = analysis['header']
        payload = analysis['payload']

        # ── Test 1: alg:none bypass ──
        self._test_alg_none(header, payload, token, source_url)

        # ── Test 2: Weak secret brute-force (HS256 only) ──
        alg = header.get('alg', '').upper()
        if alg.startswith('HS'):
            self._test_weak_secrets(token, alg, source_url)

        # ── Test 3: Expired token still accepted? ──
        if analysis['analysis'].get('expired'):
            self._test_expired_acceptance(token, source_url)

    def _test_alg_none(self, header: dict, payload: dict, original_token: str, source_url: str):
        """Forge token with alg:none and test if accepted."""
        for alg in ['none', 'None', 'NONE', 'nOnE']:
            forged_header = {**header, 'alg': alg}
            try:
                h_b64 = base64.urlsafe_b64encode(
                    json.dumps(forged_header, separators=(',', ':')).encode()
                ).rstrip(b'=').decode()
                p_b64 = base64.urlsafe_b64encode(
                    json.dumps(payload, separators=(',', ':')).encode()
                ).rstrip(b'=').decode()
                forged = f"{h_b64}.{p_b64}."

                self.findings.append({
                    'type': 'JWT alg:none Forge',
                    'severity': 'HIGH',
                    'source': source_url,
                    'original_alg': header.get('alg', '?'),
                    'forged_token': forged[:60] + '...',
                    'detail': f"Forged JWT with alg:{alg} — test against API endpoints for auth bypass",
                    'needs_manual_test': True,
                })
                if self.verbose:
                    print(f"{Colors.WARNING}  [JWT] [HIGH] alg:none token forged — "
                          f"needs manual testing against API{Colors.ENDC}")
                break  # One forge attempt is enough
            except Exception:
                continue

    def _test_weak_secrets(self, token: str, alg: str, source_url: str):
        """Try common secrets to sign the JWT."""
        import hmac as _hmac
        import hashlib as _hashlib

        parts = token.split('.')
        if len(parts) < 3:
            return

        signing_input = f"{parts[0]}.{parts[1]}".encode()
        original_sig = parts[2]

        hash_func = {
            'HS256': _hashlib.sha256,
            'HS384': _hashlib.sha384,
            'HS512': _hashlib.sha512,
        }.get(alg, _hashlib.sha256)

        for secret in self.COMMON_SECRETS:
            sig = base64.urlsafe_b64encode(
                _hmac.new(secret.encode(), signing_input, hash_func).digest()
            ).rstrip(b'=').decode()

            if sig == original_sig:
                self.findings.append({
                    'type': 'JWT Weak Secret',
                    'severity': 'CRITICAL',
                    'source': source_url,
                    'algorithm': alg,
                    'secret': secret,
                    'detail': f"JWT signed with weak secret '{secret}' — full token forgery possible",
                })
                if self.verbose:
                    print(f"{Colors.FAIL}  [JWT] [CRITICAL] Weak secret found: '{secret}'{Colors.ENDC}")
                return  # Found it

    def _test_expired_acceptance(self, token: str, source_url: str):
        """Note that an expired token was found — may still be accepted."""
        self.findings.append({
            'type': 'JWT Expired Token',
            'severity': 'MEDIUM',
            'source': source_url,
            'detail': "Expired JWT found in source — test if API still accepts it (session fixation)",
            'needs_manual_test': True,
        })


# ═══════════════════════════════════════════════════════════════════
#  v5.0: Enhanced HTML/PDF Report Generator
# ═══════════════════════════════════════════════════════════════════

class ReportGenerator:
    """
    Professional visual reports with severity charts, executive summary,
    attack chain diagrams. Supports HTML and PDF output.
    """

    @staticmethod
    def generate_severity_chart_svg(findings: List[Dict]) -> str:
        """Generate inline SVG severity donut chart."""
        by_sev = defaultdict(int)
        for f in findings:
            by_sev[f['severity']] += 1

        total = len(findings) or 1
        colors = {'CRITICAL': '#dc3545', 'HIGH': '#fd7e14', 'MEDIUM': '#0dcaf0', 'LOW': '#0d6efd'}
        sevs = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

        # SVG donut chart
        cx, cy, r = 80, 80, 60
        r_inner = 35
        svg_parts = [f'<svg width="260" height="180" xmlns="http://www.w3.org/2000/svg">']

        start_angle = -90
        for sev in sevs:
            count = by_sev.get(sev, 0)
            if count == 0:
                continue
            pct = count / total
            angle = pct * 360
            end_angle = start_angle + angle
            large = 1 if angle > 180 else 0

            x1 = cx + r * math.cos(math.radians(start_angle))
            y1 = cy + r * math.sin(math.radians(start_angle))
            x2 = cx + r * math.cos(math.radians(end_angle))
            y2 = cy + r * math.sin(math.radians(end_angle))
            x3 = cx + r_inner * math.cos(math.radians(end_angle))
            y3 = cy + r_inner * math.sin(math.radians(end_angle))
            x4 = cx + r_inner * math.cos(math.radians(start_angle))
            y4 = cy + r_inner * math.sin(math.radians(start_angle))

            path = (f'M {x1:.1f} {y1:.1f} A {r} {r} 0 {large} 1 {x2:.1f} {y2:.1f} '
                    f'L {x3:.1f} {y3:.1f} A {r_inner} {r_inner} 0 {large} 0 {x4:.1f} {y4:.1f} Z')
            svg_parts.append(f'<path d="{path}" fill="{colors[sev]}" opacity="0.9"/>')
            start_angle = end_angle

        # Center text
        svg_parts.append(f'<text x="{cx}" y="{cy-5}" text-anchor="middle" '
                         f'fill="#c9d1d9" font-size="20" font-weight="bold">{total}</text>')
        svg_parts.append(f'<text x="{cx}" y="{cy+12}" text-anchor="middle" '
                         f'fill="#8b949e" font-size="10">findings</text>')

        # Legend
        ly = 20
        for sev in sevs:
            count = by_sev.get(sev, 0)
            if count == 0:
                continue
            svg_parts.append(f'<rect x="175" y="{ly}" width="12" height="12" '
                             f'rx="2" fill="{colors[sev]}"/>')
            svg_parts.append(f'<text x="192" y="{ly+10}" fill="#c9d1d9" '
                             f'font-size="11">{sev}: {count}</text>')
            ly += 20

        svg_parts.append('</svg>')
        return '\n'.join(svg_parts)

    @staticmethod
    def generate_executive_summary(findings, stats, attack_chains, cve_results, rate_results):
        """Generate executive summary section."""
        total = len(findings)
        critical = sum(1 for f in findings if f['severity'] == 'CRITICAL')
        high = sum(1 for f in findings if f['severity'] == 'HIGH')
        live = sum(1 for f in findings if f.get('verified_live') is True)

        risk_level = 'CRITICAL' if critical > 0 else ('HIGH' if high > 0 else ('MEDIUM' if total > 0 else 'LOW'))
        risk_color = {'CRITICAL': '#dc3545', 'HIGH': '#fd7e14', 'MEDIUM': '#0dcaf0', 'LOW': '#198754'}

        summary = f'''
        <div class="exec-summary">
            <h2>Executive Summary</h2>
            <div class="risk-badge" style="background:{risk_color[risk_level]}">
                Overall Risk: {risk_level}
            </div>
            <div class="summary-grid">
                <div class="summary-card">
                    <div class="summary-number">{total}</div>
                    <div class="summary-label">Total Findings</div>
                </div>
                <div class="summary-card" style="border-color:#dc3545">
                    <div class="summary-number" style="color:#dc3545">{critical}</div>
                    <div class="summary-label">Critical</div>
                </div>
                <div class="summary-card" style="border-color:#fd7e14">
                    <div class="summary-number" style="color:#fd7e14">{live}</div>
                    <div class="summary-label">Verified Live</div>
                </div>
                <div class="summary-card">
                    <div class="summary-number">{stats.get("source_maps_found", 0)}</div>
                    <div class="summary-label">Source Maps</div>
                </div>
            </div>
        '''

        if cve_results:
            cve_count = cve_results.get('confirmed_vulnerable', 0)
            if cve_count:
                summary += f'''
                <div class="alert alert-danger">
                    ⚠️ {cve_count} confirmed CVE(s) found in source map dependencies
                </div>'''

        if rate_results:
            unrestricted = rate_results.get('unrestricted', 0)
            if unrestricted:
                summary += f'''
                <div class="alert alert-warning">
                    💰 {unrestricted} API key(s) with NO rate limiting detected
                </div>'''

        summary += '</div>'
        return summary

    @staticmethod
    def generate_pdf(html_path: str, pdf_path: str) -> bool:
        """Convert HTML report to PDF using available tools (4 fallback engines)."""
        import subprocess

        # Engine 1: weasyprint (best quality)
        try:
            subprocess.run(['python3', '-c', 'import weasyprint'], check=True,
                           capture_output=True, timeout=5)
            result = subprocess.run([
                'python3', '-c',
                f"import weasyprint; weasyprint.HTML(filename='{html_path}').write_pdf('{pdf_path}')"
            ], check=True, capture_output=True, timeout=120)
            print(f"{Colors.OKGREEN}[+] PDF: {pdf_path} (weasyprint){Colors.ENDC}")
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            if hasattr(e, 'stderr') and e.stderr:
                err_msg = e.stderr.decode(errors='replace').strip().split('\n')[-1]
                print(f"{Colors.DIM}[!] weasyprint: {err_msg[:60]}{Colors.ENDC}")

        # Engine 2: wkhtmltopdf (widely available)
        try:
            subprocess.run(['wkhtmltopdf', '--quiet',
                           '--enable-local-file-access',
                           '--no-stop-slow-scripts',
                           '--javascript-delay', '500',
                           html_path, pdf_path],
                           check=True, capture_output=True, timeout=120)
            print(f"{Colors.OKGREEN}[+] PDF: {pdf_path} (wkhtmltopdf){Colors.ENDC}")
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Engine 3: chromium/chrome headless (common on Kali/Linux)
        for browser in ['chromium', 'chromium-browser', 'google-chrome', 'google-chrome-stable']:
            try:
                abs_html = os.path.abspath(html_path)
                abs_pdf = os.path.abspath(pdf_path)
                subprocess.run([browser, '--headless', '--disable-gpu', '--no-sandbox',
                               f'--print-to-pdf={abs_pdf}',
                               '--run-all-compositor-stages-before-draw',
                               '--virtual-time-budget=5000',
                               f'file://{abs_html}'],
                               check=True, capture_output=True, timeout=60)
                if os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 100:
                    print(f"{Colors.OKGREEN}[+] PDF: {pdf_path} ({browser} headless){Colors.ENDC}")
                    return True
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
                continue

        # Engine 4: xhtml2pdf (pure Python fallback — no system deps)
        try:
            subprocess.run(['python3', '-c', 'import xhtml2pdf'], check=True,
                           capture_output=True, timeout=5)
            conv_script = (
                f"from xhtml2pdf import pisa; "
                f"src = open('{html_path}', 'r', encoding='utf-8').read(); "
                f"out = open('{pdf_path}', 'wb'); "
                f"pisa.CreatePDF(src, dest=out); out.close()"
            )
            subprocess.run(['python3', '-c', conv_script],
                           check=True, capture_output=True, timeout=120)
            if os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 100:
                print(f"{Colors.OKGREEN}[+] PDF: {pdf_path} (xhtml2pdf){Colors.ENDC}")
                return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            pass

        print(f"{Colors.WARNING}[!] PDF skipped — install one of: "
              f"weasyprint, wkhtmltopdf, chromium, xhtml2pdf{Colors.ENDC}")
        print(f"{Colors.DIM}    pip install weasyprint  OR  apt install wkhtmltopdf  OR  "
              f"pip install xhtml2pdf{Colors.ENDC}")
        return False

def load_custom_rules(filepath: str) -> Dict:
    """
    Load custom patterns from YAML or JSON file.
    Format:
      rules:
        - name: "My Custom Token"
          patterns: ["(myapp_[a-z0-9]{32})"]
          severity: HIGH
          case_sensitive: true
    """
    rules = {}
    path = Path(filepath)
    if not path.exists():
        print(f"{Colors.FAIL}[!] Rules file not found: {filepath}{Colors.ENDC}")
        return rules

    try:
        content = path.read_text()
        if filepath.endswith(('.yaml', '.yml')):
            if not HAS_YAML:
                print(f"{Colors.FAIL}[!] PyYAML not installed. "
                      f"Install with: pip install pyyaml{Colors.ENDC}")
                return rules
            data = yaml.safe_load(content)
        else:
            data = json.loads(content)

        for rule in data.get('rules', []):
            name = rule.get('name', 'Custom Rule')
            rules[name] = {
                'patterns': rule.get('patterns', []),
                'severity': rule.get('severity', 'MEDIUM').upper(),
                'validate': None,
                'case_sensitive': rule.get('case_sensitive', False),
                'context_required': rule.get('context_required', False),
            }
        if rules:
            print(f"{Colors.OKGREEN}[+] Loaded {len(rules)} custom rules "
                  f"from {filepath}{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error loading rules: {e}{Colors.ENDC}")

    return rules


# ═══════════════════════════════════════════════════════════════════
#  SARIF Output — v2.8
# ═══════════════════════════════════════════════════════════════════

def export_sarif(findings: List[Dict], stats: Dict, filename: str):
    """Export findings in SARIF 2.1.0 format for GitHub/GitLab CI integration."""
    rules = {}
    results = []

    for i, f in enumerate(findings):
        rule_id = f['type'].lower().replace(' ', '-')
        if rule_id not in rules:
            rules[rule_id] = {
                'id': rule_id,
                'name': f['type'],
                'shortDescription': {'text': f"Detected {f['type']}"},
                'defaultConfiguration': {
                    'level': {
                        'CRITICAL': 'error', 'HIGH': 'error',
                        'MEDIUM': 'warning', 'LOW': 'note',
                    }.get(f['severity'], 'warning')
                },
                'properties': {
                    'security-severity': {
                        'CRITICAL': '9.5', 'HIGH': '7.5',
                        'MEDIUM': '5.0', 'LOW': '2.5',
                    }.get(f['severity'], '5.0')
                },
            }

        val_masked = f['value']
        if len(val_masked) > 12:
            val_masked = val_masked[:6] + '***' + val_masked[-4:]

        result = {
            'ruleId': rule_id,
            'level': rules[rule_id]['defaultConfiguration']['level'],
            'message': {
                'text': f"Found {f['type']} (confidence: {f.get('confidence','?')}, "
                        f"entropy: {f.get('entropy',0)}) — {val_masked}"
            },
            'locations': [{
                'physicalLocation': {
                    'artifactLocation': {'uri': f['source']},
                }
            }],
            'properties': {
                'confidence': f.get('confidence', 'LOW'),
                'validated': f.get('validated', False),
                'entropy': f.get('entropy', 0),
            },
        }
        if f.get('verified_live') is not None:
            result['properties']['verified_live'] = f['verified_live']
            result['properties']['verification_detail'] = f.get('verification_detail', '')

        results.append(result)

    sarif = {
        '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
        'version': '2.1.0',
        'runs': [{
            'tool': {
                'driver': {
                    'name': 'Arcanis',
                    'version': __version__,
                    'informationUri': 'https://github.com/muizzamri/arcanis',
                    'rules': list(rules.values()),
                }
            },
            'results': results,
            'invocations': [{
                'executionSuccessful': True,
                'properties': {'network_stats': stats},
            }],
        }]
    }

    with open(filename, 'w') as f:
        json.dump(sarif, f, indent=2, default=str)
    print(f"{Colors.OKGREEN}[+] SARIF exported to {filename}{Colors.ENDC}")


# ═══════════════════════════════════════════════════════════════════
#  Main Scanner
# ═══════════════════════════════════════════════════════════════════

class SecretScanner:
    def __init__(self, verbose=False, max_workers=5, crawl_depth=0,
                 no_validate=False, max_retries=3, ua_rotate=False,
                 probe_env=False, probe_graphql=False,
                 show_progress=True, verify_live=False,
                 rate_limit=0, scope_domains=None, custom_rules=None,
                 notify_url=None, baseline_path=None,
                 probe_swagger=False, scan_cloud=False,
                 wayback=False, subtko=False, ssrf_probe=False,
                 fuzz_idor=False, cors_check=False, open_redirect=False,
                 dom_xss=False, dep_confusion=False, jwt_exploit=False,
                 cloud_perms=False):
        self.verbose = verbose
        self.max_workers = max_workers
        self.crawl_depth = crawl_depth
        self.no_validate = no_validate
        self.max_retries = max_retries
        self.ua_rotate = ua_rotate
        self.probe_env = probe_env
        self.probe_graphql = probe_graphql
        self.probe_swagger = probe_swagger
        self.scan_cloud = scan_cloud
        self.enable_wayback = wayback
        self.enable_subtko = subtko
        self.enable_ssrf = ssrf_probe
        self.enable_fuzz_idor = fuzz_idor
        self.enable_cors = cors_check
        self.enable_redirect = open_redirect
        self.enable_dom_xss = dom_xss
        self.enable_dep_confusion = dep_confusion
        self.enable_jwt_exploit = jwt_exploit
        self.enable_cloud_perms = cloud_perms
        self.verify_live = verify_live
        self.scope_domains = scope_domains or []
        self.baseline_path = baseline_path
        self.found_secrets: List[Dict] = []
        self.seen_secrets: Set[str] = set()
        self.scanned_urls: Set[str] = set()
        self.blocked_urls: Set[str] = set()
        self.discovered_endpoints: List[Dict] = []
        self.discovered_internal_urls: List[Dict] = []
        self.graphql_endpoints: List[Dict] = []
        self.env_files_found: List[Dict] = []
        self.google_scope_results: List[Dict] = []
        self.source_map_intel: List[Dict] = []
        self.supply_chain = SupplyChainMapper()
        self.headers_auditor = SecurityHeadersAuditor()
        self.cloud_scanner = CloudNativeScanner() if scan_cloud else None
        self.fp_removed: List[Dict] = []
        self.progress = ProgressBar(enabled=show_progress and not verbose)
        self.rate_limiter = RateLimiter(rate_limit)
        self.accuracy_engine = AccuracyEngine()
        self.content_cache: Dict[str, str] = {}  # source_url -> content (for context analysis)

        self.stats = {
            'requests_made': 0, 'requests_failed': 0,
            'retries_used': 0, 'waf_blocked': 0,
            'source_maps_found': 0, 'chunks_discovered': 0,
            'env_files_found': 0, 'graphql_found': 0,
            'endpoints_discovered': 0, 'internal_ips_found': 0,
            'private_keys_found': 0, 'buckets_found': 0,
            'secrets_verified_live': 0, 'db_strings_found': 0,
            'high_entropy_found': 0, 'passwords_found': 0,
            'sourcemap_files_found': 0, 'supply_chain_vulns': 0,
            'sri_missing': 0, 'jwt_critical': 0,
            'cloud_findings': 0, 'swagger_specs': 0,
            'header_issues': 0, 'fp_filtered': 0,
            'wayback_urls': 0, 'subtko_findings': 0,
            'ssrf_vectors': 0, 'idor_candidates': 0,
            'internal_routes': 0, 'attack_chains': 0,
            'cve_confirmed': 0, 'cve_potential': 0,
            'rate_abuse_unrestricted': 0,
        }

        # Session
        self.session = requests.Session()
        retry_strategy = Retry(
            total=max_retries, backoff_factor=1.0,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=['GET', 'HEAD', 'POST'],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount('https://', adapter)
        self.session.mount('http://', adapter)
        self.session.headers.update({
            'User-Agent': UA_POOL[0],
            'Accept': 'text/html,application/xhtml+xml,application/xml;'
                      'q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
        })

        # Active verifier — v4.0: 50+ verifiers
        self.verifier = ActiveVerifierV2(self.session) if verify_live else None

        # v3.0: API Discovery, Notifier
        self.api_discovery = APIDiscoveryV2(self.session, self.rate_limiter, verbose)
        self.notifier = TeamNotifier(notify_url, self.session) if notify_url else None

        # v4.0: Offensive Recon modules
        self.wayback = WaybackMiner(self.session, self.rate_limiter, verbose)
        self.subtko = SubdomainTakeoverChecker(self.session, verbose)
        self.ssrf_prober = SSRFProber()
        self.idor_fuzzer = IDORFuzzer(self.session, self.rate_limiter, verbose)
        self.internal_api_enum = InternalAPIEnumerator()
        self.priv_esc = PrivilegeEscalationSimulator(self.session)
        self.attack_chains: List[Dict] = []

        # v5.0: New modules
        self.cve_lookup = CVELookup(self.session, verbose)
        self.rate_tester = RateAbuseTester(self.session, verbose) if verify_live else None
        self.batch_scanner = BatchScanner()

        # v6.0: Exposure detection modules (always declare, conditionally init)
        self.cors_detector = CORSDetector(self.session, self.rate_limiter, verbose) if cors_check else None
        self.redirect_detector = OpenRedirectDetector(self.session, self.rate_limiter, verbose) if open_redirect else None
        self.cloud_perm_tester = CloudPermissionTester(self.session, self.rate_limiter, verbose) if cloud_perms else None
        self.dom_xss_mapper = DOMXSSMapper(verbose) if dom_xss else None

        self.skip_libraries = [
            'jquery', 'bootstrap', 'angular.min', 'react.production',
            'vue.min', 'lodash', 'moment', 'axios', 'polyfill',
        ]

        self.patterns = self._build_patterns()

        # Output dedup tracking
        self._seen_source_maps = set()    # Don't print same map twice
        self._seen_scan_urls = set()      # Track scanned URLs for progress

        # v5.1.1: WAF adaptive intelligence (v5.1.2: oscillation fix)
        self._waf_hits_window = []        # Timestamps of recent WAF blocks
        self._waf_stealth_mode = False    # Whether stealth mode is active
        self._waf_original_workers = max_workers
        self._waf_original_rps = rate_limit
        self._waf_stealth_activated_at = 0  # Timestamp when stealth was last activated
        self._waf_cooldown_secs = 90        # Minimum seconds before recovery attempt
        self._waf_escalation = 0            # 0=normal, 1=stealth, 2=deep stealth
        self._waf_total_blocks = 0          # Lifetime WAF blocks for this scan

        # Merge custom rules
        if custom_rules:
            self.patterns.update(custom_rules)

    # ─────────────────────────────────────────────────────────────
    #  HTTP helpers
    # ─────────────────────────────────────────────────────────────

    def _get_headers(self):
        h = {}
        if self.ua_rotate:
            h['User-Agent'] = random.choice(UA_POOL)
        return h

    def _adapt_to_waf(self):
        """Detect WAF pressure and switch to stealth mode with cooldown."""
        now = time.time()
        # Keep only WAF hits from the last 30 seconds
        self._waf_hits_window = [t for t in self._waf_hits_window if now - t < 30]
        waf_rate = len(self._waf_hits_window)
        self._waf_total_blocks += 1

        if waf_rate >= 8 and not self._waf_stealth_mode:
            # Enter stealth mode
            self._waf_stealth_mode = True
            self._waf_stealth_activated_at = now
            self._waf_escalation = 1
            self.max_workers = max(2, self._waf_original_workers // 4)
            if self.rate_limiter.rps > 0:
                self.rate_limiter.rps = max(1.0, self.rate_limiter.rps / 3)
            else:
                self.rate_limiter.rps = 2.0
            self.probe_env = False
            self.probe_graphql = False
            self.probe_swagger = False
            print(f"\n{Colors.WARNING}  [SMART] WAF pressure detected ({waf_rate} blocks/30s) "
                  f"→ Stealth mode: {self.max_workers} workers, "
                  f"{self.rate_limiter.rps:.1f} req/s, noisy probes disabled{Colors.ENDC}")

        elif waf_rate >= 12 and self._waf_stealth_mode and self._waf_escalation < 2:
            # Escalate to deep stealth — WAF is still blocking even in stealth
            self._waf_escalation = 2
            self._waf_stealth_activated_at = now  # Reset cooldown
            self.max_workers = 1
            self.rate_limiter.rps = max(0.5, self.rate_limiter.rps / 2)
            print(f"\n{Colors.FAIL}  [SMART] WAF still blocking in stealth → Deep stealth: "
                  f"1 worker, {self.rate_limiter.rps:.1f} req/s{Colors.ENDC}")

        elif waf_rate <= 2 and self._waf_stealth_mode:
            # Check cooldown before recovering — prevent oscillation
            elapsed_stealth = now - self._waf_stealth_activated_at
            if elapsed_stealth < self._waf_cooldown_secs:
                return  # Too soon — stay in stealth

            # Gradual recovery based on total WAF pressure seen
            self._waf_stealth_mode = False
            if self._waf_total_blocks > 50:
                # Heavy WAF target — recover conservatively
                self.max_workers = max(2, self._waf_original_workers // 3)
                if self._waf_original_rps > 0:
                    self.rate_limiter.rps = max(2.0, self._waf_original_rps * 0.5)
                else:
                    self.rate_limiter.rps = 3.0
                print(f"\n{Colors.OKCYAN}  [SMART] WAF pressure eased → Cautious recovery: "
                      f"{self.max_workers} workers, {self.rate_limiter.rps:.1f} req/s "
                      f"(heavy WAF target){Colors.ENDC}")
            else:
                # Light WAF — recover to 75%
                self.max_workers = max(self.max_workers, int(self._waf_original_workers * 0.75))
                if self._waf_original_rps > 0:
                    self.rate_limiter.rps = self._waf_original_rps
                else:
                    self.rate_limiter.rps = 0
                print(f"\n{Colors.OKCYAN}  [SMART] WAF pressure eased → Resuming: "
                      f"{self.max_workers} workers{Colors.ENDC}")
            self._waf_escalation = 0

    def _resilient_get(self, url, timeout=12, is_page=False):
        self.rate_limiter.wait()
        self.stats['requests_made'] += 1

        # Skip URLs from domains already heavily blocked
        domain = urlparse(url).netloc
        blocked_count = sum(1 for bu in self.blocked_urls if domain in bu)
        if blocked_count >= 5:
            self.stats['requests_failed'] += 1
            return None

        # Reduce retries in stealth mode to avoid hammering WAF
        effective_retries = 1 if self._waf_stealth_mode else self.max_retries

        for attempt in range(effective_retries + 1):
            try:
                headers = self._get_headers()
                if is_page:
                    headers.update({'Sec-Fetch-Dest': 'document', 'Sec-Fetch-Mode': 'navigate'})
                else:
                    headers.update({
                        'Sec-Fetch-Dest': 'script', 'Sec-Fetch-Mode': 'no-cors',
                        'Referer': url.rsplit('/', 1)[0] + '/',
                    })
                resp = self.session.get(url, timeout=timeout, allow_redirects=True, headers=headers)
                if resp.status_code == 403:
                    self.stats['waf_blocked'] += 1
                    self.progress.increment('waf_blocked')
                    self._waf_hits_window.append(time.time())
                    self._adapt_to_waf()
                    if attempt < effective_retries:
                        self.stats['retries_used'] += 1
                        self.progress.increment('retries_used')
                        self.session.headers['User-Agent'] = random.choice(UA_POOL)
                        # Stealth: longer backoff with jitter
                        if self._waf_stealth_mode:
                            time.sleep((3 ** attempt) + random.uniform(2.0, 5.0))
                        else:
                            time.sleep((2 ** attempt) + random.uniform(0.5, 1.5))
                        continue
                    self.blocked_urls.add(url)
                    return None
                resp.raise_for_status()
                return resp
            except requests.exceptions.RequestException:
                self.stats['requests_failed'] += 1
                if attempt < effective_retries:
                    self.stats['retries_used'] += 1
                    self.progress.increment('retries_used')
                    time.sleep((2 ** attempt) + random.uniform(0.3, 1.0))
                    continue
        return None

    def _is_cdn_waf_source(self, url):
        path = urlparse(url).path.lower()
        return any(pat in path for pat in CDN_WAF_PATH_PATTERNS)

    def _is_in_scope(self, url):
        """Check if URL is within authorized scope domains."""
        if not self.scope_domains:
            return True
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        return any(host == d or host.endswith('.' + d) for d in self.scope_domains)

    # ─────────────────────────────────────────────────────────────
    #  Pattern definitions
    # ─────────────────────────────────────────────────────────────

    def _build_patterns(self):
        return {
            # ── Analytics ───────────────────────────────────────────
            'Segment Write Key': {
                'patterns': [
                    r'segment["\']?\s*[:\=]\s*["\']([A-Za-z0-9]{32})["\']',
                    r'SEGMENT_WRITE_KEY["\']?\s*[:\=]\s*["\']([A-Za-z0-9]{32})["\']',
                    r'writeKey["\']?\s*[:\=]\s*["\']([A-Za-z0-9]{32})["\']',
                ],
                'severity': 'MEDIUM', 'validate': self.validate_segment,
            },
            'Sentry DSN': {
                'patterns': [
                    r'https://([a-f0-9]{32})@([a-z0-9\-]+)\.ingest\.sentry\.io/([0-9]+)',
                ],
                'severity': 'MEDIUM', 'validate': self.validate_sentry,
            },
            'Split.io API Key': {
                'patterns': [r'split["\']?\s*[:\=]\s*["\']([a-z0-9]{30,45})["\']'],
                'severity': 'HIGH', 'validate': self.validate_split,
            },
            'Datadog RUM Token': {
                'patterns': [r'(pub[a-f0-9]{32})'],
                'severity': 'HIGH', 'validate': self.validate_datadog,
            },
            'Mixpanel Project Token': {
                'patterns': [
                    r'MIXPANEL_TOKEN["\']?\s*[:\=]\s*["\']([a-f0-9]{32})["\']',
                    r'mixpanel\.init\s*\(\s*["\']([a-f0-9]{32})["\']',
                ],
                'severity': 'MEDIUM', 'validate': self.validate_hex32,
                'context_required': True,
            },
            'Amplitude API Key': {
                'patterns': [
                    r'AMPLITUDE_API_KEY["\']?\s*[:\=]\s*["\']([a-f0-9]{32})["\']',
                    r'amplitude\.init\s*\(\s*["\']([a-f0-9]{32})["\']',
                ],
                'severity': 'MEDIUM', 'validate': self.validate_hex32,
            },
            'LogRocket App ID': {
                'patterns': [r'LogRocket\.init\s*\(\s*["\']([a-z0-9]+/[a-z0-9\-]+)["\']'],
                'severity': 'MEDIUM', 'validate': self.validate_logrocket,
            },
            'FullStory Org ID': {
                'patterns': [r'FULLSTORY_ORG_ID["\']?\s*[:\=]\s*["\']([A-Z0-9]{5,10})["\']'],
                'severity': 'MEDIUM', 'validate': None,
            },

            # ── Auth & Cloud ────────────────────────────────────────
            'Google API Key': {
                'patterns': [r'(AIza[0-9A-Za-z\-_]{35})'],
                'severity': 'HIGH', 'validate': self.validate_google_api,
                'case_sensitive': True,
            },
            'Firebase Config': {
                'patterns': [r'apiKey["\']?\s*:\s*["\'](AIza[0-9A-Za-z\-_]{35})["\']'],
                'severity': 'HIGH', 'validate': None, 'case_sensitive': True,
            },
            'AWS Access Key': {
                'patterns': [r'(AKIA[0-9A-Z]{16})'],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },
            'Auth0 Client ID': {
                'patterns': [r'AUTH0_CLIENT_ID["\']?\s*[:\=]\s*["\']([A-Za-z0-9]{32})["\']'],
                'severity': 'LOW', 'validate': None,
            },
            'Recaptcha Site Key': {
                'patterns': [r'(6L[a-zA-Z0-9_-]{38})'],
                'severity': 'LOW', 'validate': None,
            },

            # ── Communication ───────────────────────────────────────
            'Slack Token': {
                'patterns': [r'(xox[baprs]-[0-9a-zA-Z]{10,48})'],
                'severity': 'HIGH', 'validate': None, 'case_sensitive': True,
            },
            'Slack Webhook': {
                'patterns': [
                    r'(https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24})',
                    r'(https://hooks\.slack\.com/triggers/[A-Za-z0-9/_\-]+)',
                ],
                'severity': 'HIGH', 'validate': self.validate_slack_webhook,
            },
            'Intercom Token': {
                'patterns': [
                    r'INTERCOM_ACCESS_TOKEN["\']?\s*[:\=]\s*["\']([A-Za-z0-9=_\-]{20,})["\']',
                    r'intercomSettings\s*=\s*\{[^}]*app_id\s*:\s*["\']([a-z0-9]{8})["\']',
                ],
                'severity': 'HIGH', 'validate': self.validate_intercom,
            },
            'Zendesk Token': {
                'patterns': [
                    r'ZENDESK_API_TOKEN["\']?\s*[:\=]\s*["\']([A-Za-z0-9]{40})["\']',
                    r'ZENDESK_TOKEN["\']?\s*[:\=]\s*["\']([A-Za-z0-9]{40})["\']',
                ],
                'severity': 'HIGH', 'validate': self.validate_zendesk,
            },
            'HubSpot API Key': {
                'patterns': [
                    r'HUBSPOT_API_KEY["\']?\s*[:\=]\s*["\']([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["\']',
                    r'(pat-[a-z]{2}-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})',
                    r'//js\.hs-scripts\.com/([0-9]{6,9})\.js',
                ],
                'severity': 'HIGH', 'validate': self.validate_hubspot,
            },

            # ── Dev Keys ────────────────────────────────────────────
            'Notion API Key': {
                'patterns': [r'(secret_[A-Za-z0-9]{43})', r'(ntn_[A-Za-z0-9]{44,})'],
                'severity': 'CRITICAL', 'validate': self.validate_notion,
                'case_sensitive': True,
            },
            'Linear API Key': {
                'patterns': [r'(lin_api_[A-Za-z0-9]{40,})'],
                'severity': 'CRITICAL', 'validate': self.validate_linear,
                'case_sensitive': True,
            },
            'GitHub Token': {
                'patterns': [
                    r'(ghp_[0-9a-zA-Z]{36})', r'(github_pat_[0-9a-zA-Z_]{82})',
                    r'(gho_[0-9a-zA-Z]{36})', r'(ghu_[0-9a-zA-Z]{36})',
                    r'(ghs_[0-9a-zA-Z]{36})',
                ],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },
            'Stripe API Key': {
                'patterns': [
                    r'(sk_live_[0-9a-zA-Z]{24,})', r'(pk_live_[0-9a-zA-Z]{24,})',
                    r'(rk_live_[0-9a-zA-Z]{24,})',
                ],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },

            # ── Email & Messaging ───────────────────────────────────
            'SendGrid API Key': {
                'patterns': [r'(SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43})'],
                'severity': 'CRITICAL', 'validate': self.validate_sendgrid,
                'case_sensitive': True,
            },
            'Twilio Credentials': {
                'patterns': [
                    r'(AC[a-f0-9]{32})', r'(SK[a-f0-9]{32})',
                    r'TWILIO_AUTH_TOKEN["\']?\s*[:\=]\s*["\']([a-f0-9]{32})["\']',
                    r'TWILIO_ACCOUNT_SID["\']?\s*[:\=]\s*["\'](AC[a-f0-9]{32})["\']',
                ],
                'severity': 'CRITICAL', 'validate': self.validate_twilio,
                'case_sensitive': True,
            },
            'Mailgun API Key': {
                'patterns': [r'(key-[0-9a-zA-Z]{32})'],
                'severity': 'HIGH', 'validate': None,
            },

            # ── Misc ────────────────────────────────────────────────
            'Mapbox Token': {
                'patterns': [r'(pk\.[a-zA-Z0-9]{60,})'],
                'severity': 'MEDIUM', 'validate': None,
            },
            'JWT Token': {
                'patterns': [r'(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})'],
                'severity': 'HIGH', 'validate': None, 'case_sensitive': True,
            },
            'Algolia API Key': {
                'patterns': [r'[0-9a-f]{32}'],
                'severity': 'MEDIUM', 'validate': None, 'context_required': True,
            },

            # ── Private Keys ────────────────────────────────────────
            'Private Key': {
                'patterns': [
                    r'(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)',
                    r'(-----BEGIN CERTIFICATE-----)',
                ],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },

            # ── Cloud Buckets ───────────────────────────────────────
            'AWS S3 Bucket': {
                'patterns': [
                    r'(https?://[a-z0-9][a-z0-9\.\-]{1,61}[a-z0-9]\.s3[a-z0-9\-]*\.amazonaws\.com)',
                    r'(https?://s3[a-z0-9\-]*\.amazonaws\.com/[a-z0-9][a-z0-9\.\-]{1,61}[a-z0-9])',
                    r'arn:aws:s3:::([a-z0-9][a-z0-9\.\-]{1,61}[a-z0-9])',
                ],
                'severity': 'HIGH', 'validate': None,
            },
            'GCS Bucket': {
                'patterns': [
                    r'(https?://storage\.googleapis\.com/[a-z0-9][a-z0-9\.\-_]{1,61}[a-z0-9])',
                    r'(gs://[a-z0-9][a-z0-9\.\-_]{1,61}[a-z0-9])',
                ],
                'severity': 'HIGH', 'validate': None,
            },
            'Azure Blob': {
                'patterns': [
                    r'(https?://[a-z0-9]{3,24}\.blob\.core\.windows\.net/[a-z0-9][a-z0-9\-]{1,62})',
                ],
                'severity': 'HIGH', 'validate': None,
            },

            # ── NEW v2.8: Password & DB Connection Strings ──────────
            'Database Connection String': {
                'patterns': [
                    r'((?:postgres|postgresql|mysql|mariadb|mssql)://[^\s"\'<>]{10,200})',
                    r'(mongodb(?:\+srv)?://[^\s"\'<>]{10,200})',
                    r'(redis://[^\s"\'<>]{10,200})',
                    r'(amqp://[^\s"\'<>]{10,200})',
                    r'DATABASE_URL["\']?\s*[:\=]\s*["\']((?:postgres|mysql|mongodb|redis|mariadb)[^\s"\'<>]{10,200})["\']',
                    r'DB_CONNECTION["\']?\s*[:\=]\s*["\']((?:postgres|mysql|mongodb|redis)[^\s"\'<>]{10,200})["\']',
                ],
                'severity': 'CRITICAL', 'validate': self.validate_db_string,
                'require_validation': True,
            },
            'Hardcoded Password': {
                'patterns': [
                    r'(?:password|passwd|pass|pwd)["\']?\s*[:\=]\s*["\']((?!\{\{)[^\s"\']{8,128})["\']',
                    r'(?:PASSWORD|PASSWD|DB_PASS|DB_PASSWORD|ADMIN_PASS|ROOT_PASS|USER_PASS)["\']?\s*[:\=]\s*["\']([^\s"\']{8,128})["\']',
                    r'(?:secret_?key|auth_?secret|api_?secret)["\']?\s*[:\=]\s*["\']([^\s"\']{12,128})["\']',
                ],
                'severity': 'HIGH', 'validate': self.validate_password,
                'require_validation': True,
            },

            # ═══════════════════════════════════════════════════════
            #  v4.0 NEW: AI / ML Platform API Keys
            # ═══════════════════════════════════════════════════════
            'OpenAI API Key': {
                'patterns': [r'(sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})', r'(sk-proj-[A-Za-z0-9_\-]{40,})'],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },
            'Anthropic API Key': {
                'patterns': [r'(sk-ant-[A-Za-z0-9\-_]{80,})'],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },
            'HuggingFace Token': {
                'patterns': [r'(hf_[A-Za-z0-9]{34,})'],
                'severity': 'HIGH', 'validate': None, 'case_sensitive': True,
            },
            'Pinecone API Key': {
                'patterns': [r'PINECONE_API_KEY["\']?\s*[:\=]\s*["\']([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["\']'],
                'severity': 'HIGH', 'validate': None,
            },
            'Cohere API Key': {
                'patterns': [r'(co-[A-Za-z0-9]{40,})'],
                'severity': 'HIGH', 'validate': None, 'case_sensitive': True,
            },
            'Replicate API Token': {
                'patterns': [r'(r8_[A-Za-z0-9]{40,})'],
                'severity': 'HIGH', 'validate': None, 'case_sensitive': True,
            },

            # ═══════════════════════════════════════════════════════
            #  v4.0 NEW: Cloud Providers (expanded)
            # ═══════════════════════════════════════════════════════
            'Cloudflare API Token': {
                'patterns': [r'CF_API_TOKEN["\']?\s*[:\=]\s*["\']([A-Za-z0-9_\-]{40})["\']',
                             r'(v1\.0-[a-f0-9]{24}-[a-f0-9]{64})'],
                'severity': 'CRITICAL', 'validate': None,
            },
            'Cloudflare Global API Key': {
                'patterns': [r'CF_API_KEY["\']?\s*[:\=]\s*["\']([a-f0-9]{37})["\']'],
                'severity': 'CRITICAL', 'validate': None,
            },
            'Vercel Token': {
                'patterns': [r'VERCEL_TOKEN["\']?\s*[:\=]\s*["\']([A-Za-z0-9]{24})["\']',
                             r'(Bearer\s+[A-Za-z0-9]{24})'],
                'severity': 'HIGH', 'validate': None,
            },
            'Netlify Token': {
                'patterns': [r'NETLIFY_AUTH_TOKEN["\']?\s*[:\=]\s*["\']([A-Za-z0-9\-_]{40,})["\']'],
                'severity': 'HIGH', 'validate': None,
            },
            'DigitalOcean Token': {
                'patterns': [r'(dop_v1_[a-f0-9]{64})', r'DIGITALOCEAN_TOKEN["\']?\s*[:\=]\s*["\']([a-f0-9]{64})["\']'],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },
            'Heroku API Key': {
                'patterns': [r'HEROKU_API_KEY["\']?\s*[:\=]\s*["\']([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["\']'],
                'severity': 'CRITICAL', 'validate': None,
            },
            'Supabase Key': {
                'patterns': [r'(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_\-]{50,}\.[A-Za-z0-9_\-]{30,})',
                             r'SUPABASE_(?:ANON|SERVICE_ROLE)_KEY["\']?\s*[:\=]\s*["\']([A-Za-z0-9_\-\.]{100,})["\']'],
                'severity': 'HIGH', 'validate': None, 'case_sensitive': True,
            },
            'Terraform Cloud Token': {
                'patterns': [r'(atlasv1-[A-Za-z0-9\-_]{60,})'],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },
            'HashiCorp Vault Token': {
                'patterns': [r'(hvs\.[A-Za-z0-9\-_]{24,})', r'VAULT_TOKEN["\']?\s*[:\=]\s*["\']([^\s"\']{10,})["\']'],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },

            # ═══════════════════════════════════════════════════════
            #  v4.0 NEW: Payment / E-commerce
            # ═══════════════════════════════════════════════════════
            'PayPal Client Secret': {
                'patterns': [r'PAYPAL_(?:CLIENT_SECRET|SECRET)["\']?\s*[:\=]\s*["\']([A-Za-z0-9]{30,})["\']'],
                'severity': 'CRITICAL', 'validate': None,
            },
            'Shopify API Key': {
                'patterns': [r'(shpat_[a-f0-9]{32})', r'(shpca_[a-f0-9]{32})',
                             r'(shppa_[a-f0-9]{32})'],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },
            'Square Access Token': {
                'patterns': [r'(sq0atp-[A-Za-z0-9\-_]{22})', r'(EAAA[A-Za-z0-9]{60})'],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },

            # ═══════════════════════════════════════════════════════
            #  v4.0 NEW: CI/CD & DevOps
            # ═══════════════════════════════════════════════════════
            'GitLab Token': {
                'patterns': [r'(glpat-[A-Za-z0-9\-_]{20,})'],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },
            'Bitbucket App Password': {
                'patterns': [r'BITBUCKET_APP_PASSWORD["\']?\s*[:\=]\s*["\']([A-Za-z0-9]{18,})["\']'],
                'severity': 'HIGH', 'validate': None,
            },
            'CircleCI Token': {
                'patterns': [r'CIRCLECI_TOKEN["\']?\s*[:\=]\s*["\']([a-f0-9]{40})["\']'],
                'severity': 'CRITICAL', 'validate': None,
            },
            'Travis CI Token': {
                'patterns': [r'TRAVIS_TOKEN["\']?\s*[:\=]\s*["\']([A-Za-z0-9\-_]{20,})["\']'],
                'severity': 'HIGH', 'validate': None,
            },
            'npm Token': {
                'patterns': [r'(npm_[A-Za-z0-9]{36})', r'//registry\.npmjs\.org/:_authToken=([A-Za-z0-9\-_]{36,})'],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },
            'PyPI Token': {
                'patterns': [r'(pypi-[A-Za-z0-9\-_]{100,})'],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },
            'NuGet API Key': {
                'patterns': [r'(oy2[A-Za-z0-9]{43})'],
                'severity': 'HIGH', 'validate': None, 'case_sensitive': True,
            },
            'Docker Hub Token': {
                'patterns': [r'DOCKER_(?:PASSWORD|TOKEN|HUB_TOKEN)["\']?\s*[:\=]\s*["\']([A-Za-z0-9\-_]{30,})["\']'],
                'severity': 'CRITICAL', 'validate': None,
            },

            # ═══════════════════════════════════════════════════════
            #  v4.0 NEW: Monitoring / Analytics (expanded)
            # ═══════════════════════════════════════════════════════
            'New Relic API Key': {
                'patterns': [r'(NRAK-[A-Z0-9]{27})', r'NEW_RELIC_(?:LICENSE_KEY|API_KEY)["\']?\s*[:\=]\s*["\']([A-Za-z0-9]{40})["\']'],
                'severity': 'HIGH', 'validate': None, 'case_sensitive': True,
            },
            'Grafana API Key': {
                'patterns': [r'(eyJrIjoi[A-Za-z0-9+/=]{30,})', r'(glsa_[A-Za-z0-9]{32}_[a-f0-9]{8})'],
                'severity': 'HIGH', 'validate': None, 'case_sensitive': True,
            },
            'Elastic API Key': {
                'patterns': [r'ELASTIC_(?:API_KEY|CLOUD_AUTH)["\']?\s*[:\=]\s*["\']([A-Za-z0-9_\-:]{20,})["\']'],
                'severity': 'HIGH', 'validate': None,
            },
            'PagerDuty API Key': {
                'patterns': [r'PAGERDUTY_(?:API_KEY|TOKEN)["\']?\s*[:\=]\s*["\']([A-Za-z0-9+_\-]{20})["\']'],
                'severity': 'HIGH', 'validate': None,
            },
            'PostHog API Key': {
                'patterns': [r'(phc_[A-Za-z0-9]{30,})', r'POSTHOG_API_KEY["\']?\s*[:\=]\s*["\']([A-Za-z0-9_\-]{30,})["\']'],
                'severity': 'MEDIUM', 'validate': None, 'case_sensitive': True,
            },

            # ═══════════════════════════════════════════════════════
            #  v4.0 NEW: Identity / Auth (expanded)
            # ═══════════════════════════════════════════════════════
            'Okta API Token': {
                'patterns': [r'OKTA_(?:API_TOKEN|TOKEN)["\']?\s*[:\=]\s*["\']([A-Za-z0-9\-_]{42})["\']',
                             r'(?:okta|OKTA)["\']?\s*[:\=]\s*["\']?(00[A-Za-z0-9\-_]{40})["\']?'],
                'severity': 'CRITICAL', 'validate': None,
                'context_required': True,
            },
            'Firebase Auth': {
                'patterns': [r'FIREBASE_(?:AUTH_TOKEN|TOKEN|ADMIN_SDK)["\']?\s*[:\=]\s*["\']([A-Za-z0-9_\-\.]{50,})["\']'],
                'severity': 'CRITICAL', 'validate': None,
            },

            # ═══════════════════════════════════════════════════════
            #  v4.0 NEW: Database
            # ═══════════════════════════════════════════════════════
            'PlanetScale Password': {
                'patterns': [r'(pscale_pw_[A-Za-z0-9\-_]{32,})'],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },
            'CockroachDB Connection': {
                'patterns': [r'(cockroachdb://[^\s"\'<>]{10,200})', r'COCKROACH_URL["\']?\s*[:\=]\s*["\']([^\s"\'<>]{10,200})["\']'],
                'severity': 'CRITICAL', 'validate': None,
            },

            # ═══════════════════════════════════════════════════════
            #  v4.0 NEW: Collaboration / Productivity
            # ═══════════════════════════════════════════════════════
            'Airtable API Key': {
                'patterns': [r'(key[A-Za-z0-9]{14})', r'(pat[A-Za-z0-9]{14,}\.[a-f0-9]{64})'],
                'severity': 'HIGH', 'validate': None, 'case_sensitive': True,
                'context_required': True,
            },
            'Contentful Token': {
                'patterns': [r'CONTENTFUL_(?:ACCESS_TOKEN|DELIVERY_TOKEN|MANAGEMENT_TOKEN)["\']?\s*[:\=]\s*["\']([A-Za-z0-9\-_]{40,})["\']'],
                'severity': 'HIGH', 'validate': None,
            },
            'Discord Bot Token': {
                'patterns': [r'((?:MTA|MTE|MTI|OD|OT|Nj|Nz|ND|NT)[A-Za-z0-9]{23,}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,})'],
                'severity': 'CRITICAL', 'validate': None, 'case_sensitive': True,
            },

            # ═══════════════════════════════════════════════════════
            #  v4.0 NEW: Media / Social
            # ═══════════════════════════════════════════════════════
            'Twitch API Token': {
                'patterns': [r'TWITCH_(?:CLIENT_SECRET|API_TOKEN)["\']?\s*[:\=]\s*["\']([A-Za-z0-9]{30})["\']'],
                'severity': 'HIGH', 'validate': None,
            },
            'Spotify Client Secret': {
                'patterns': [r'SPOTIFY_(?:CLIENT_SECRET|SECRET)["\']?\s*[:\=]\s*["\']([a-f0-9]{32})["\']'],
                'severity': 'HIGH', 'validate': None,
            },
            'Twitter API Key': {
                'patterns': [r'TWITTER_(?:API_KEY|API_SECRET|BEARER_TOKEN)["\']?\s*[:\=]\s*["\']([A-Za-z0-9\-_]{25,})["\']'],
                'severity': 'HIGH', 'validate': None,
            },

            # ═══════════════════════════════════════════════════════
            #  v4.0 NEW: OAuth / Generic Tokens
            # ═══════════════════════════════════════════════════════
            'OAuth Access Token': {
                'patterns': [r'access_token["\']?\s*[:\=]\s*["\']([A-Za-z0-9\-_\.]{30,})["\']'],
                'severity': 'HIGH', 'validate': None, 'context_required': True,
            },
            'OAuth Refresh Token': {
                'patterns': [r'refresh_token["\']?\s*[:\=]\s*["\']([A-Za-z0-9\-_\.]{30,})["\']'],
                'severity': 'CRITICAL', 'validate': None, 'context_required': True,
            },
            'Generic Bearer Token': {
                'patterns': [r'Bearer\s+([A-Za-z0-9\-_\.]{40,200})'],
                'severity': 'HIGH', 'validate': None, 'case_sensitive': True,
                'context_required': True,
            },
        }

    # ═════════════════════════════════════════════════════════════
    #  Validators
    # ═════════════════════════════════════════════════════════════

    def validate_segment(self, k): return len(k) == 32 and k.isalnum()
    def validate_hex32(self, k): return len(k) == 32 and all(c in '0123456789abcdef' for c in k)
    def validate_sentry(self, dsn):
        return bool(re.match(r'https://([a-f0-9]{32})@([a-z0-9\-]+)\.ingest\.sentry\.io/([0-9]+)', dsn))
    def validate_split(self, k): return 30 <= len(k) <= 45 and k.isalnum() and k.islower()
    def validate_datadog(self, t):
        return t.startswith('pub') and len(t[3:]) == 32 and all(c in '0123456789abcdef' for c in t[3:])
    def validate_google_api(self, k): return k.startswith('AIza') and len(k) == 39
    def validate_logrocket(self, a):
        parts = a.split('/'); return len(parts) == 2 and all(p.replace('-', '').isalnum() for p in parts)
    def validate_notion(self, k):
        if k.startswith('secret_'): return len(k) == 50 and k[7:].isalnum()
        if k.startswith('ntn_'): return len(k) >= 48 and k[4:].isalnum()
        return False
    def validate_intercom(self, t):
        if len(t) == 8 and t.islower() and t.isalnum(): return True
        return len(t) >= 20 and t.replace('=', '').replace('-', '').replace('_', '').isalnum()
    def validate_zendesk(self, t): return (len(t) == 40 and t.isalnum()) or len(t) >= 20
    def validate_hubspot(self, v):
        if v.startswith('pat-'): return bool(re.match(r'^pat-[a-z]{2}-[a-f0-9\-]+$', v))
        if re.match(r'^[a-f0-9]{8}-', v): return True
        return v.isdigit() and 6 <= len(v) <= 9
    def validate_linear(self, k): return k.startswith('lin_api_') and len(k) >= 48
    def validate_slack_webhook(self, u): return u.startswith('https://hooks.slack.com/')
    def validate_twilio(self, v):
        if v.startswith('AC') and len(v) == 34: return all(c in '0123456789abcdef' for c in v[2:])
        if v.startswith('SK') and len(v) == 34: return all(c in '0123456789abcdef' for c in v[2:])
        return len(v) == 32 and v.isalnum()
    def validate_sendgrid(self, k):
        return bool(re.match(r'^SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}$', k))

    def validate_db_string(self, val):
        """Validate DB connection string has user:pass@host pattern."""
        return bool(re.match(r'^\w+(?:\+\w+)?://\S+:\S+@\S+', val))

    def validate_password(self, val):
        """Filter out template/placeholder passwords."""
        skip = {'password', 'changeme', 'example', 'xxxxxxxx', '********',
                'your_password', 'YOUR_PASSWORD', 'undefined', 'null', 'true', 'false',
                'process.env', '${', '{{', 'env(', '<password>', '[password]'}
        vl = val.lower().strip()
        if any(s in vl for s in skip):
            return False
        if len(set(val)) <= 2:
            return False
        return len(val) >= 8

    # ═════════════════════════════════════════════════════════════
    #  Entropy-enhanced confidence scoring
    # ═════════════════════════════════════════════════════════════

    def _score_confidence(self, secret_type, value, context):
        ctx_lower = context.lower()
        type_keywords = {
            'Segment Write Key': ['segment', 'writekey'],
            'Sentry DSN': ['sentry', 'dsn'],
            'Split.io API Key': ['split'],
            'Datadog RUM Token': ['datadog', 'rum'],
            'Mixpanel Project Token': ['mixpanel'],
            'Amplitude API Key': ['amplitude'],
            'LogRocket App ID': ['logrocket'],
            'FullStory Org ID': ['fullstory'],
            'Google API Key': ['google', 'firebase', 'apikey'],
            'AWS Access Key': ['aws', 'akia'],
            'Slack Token': ['slack', 'xox'],
            'Slack Webhook': ['slack', 'webhook'],
            'Intercom Token': ['intercom'],
            'Zendesk Token': ['zendesk'],
            'HubSpot API Key': ['hubspot', 'hs-scripts'],
            'Notion API Key': ['notion'],
            'Linear API Key': ['linear'],
            'GitHub Token': ['github'],
            'Stripe API Key': ['stripe'],
            'SendGrid API Key': ['sendgrid'],
            'Twilio Credentials': ['twilio'],
            'Mailgun API Key': ['mailgun'],
            'Mapbox Token': ['mapbox'],
            'JWT Token': ['jwt', 'bearer', 'authorization', 'token'],
            'Algolia API Key': ['algolia'],
            'Recaptcha Site Key': ['recaptcha', 'captcha'],
            'Auth0 Client ID': ['auth0'],
            'Private Key': ['key', 'private', 'cert'],
            'AWS S3 Bucket': ['s3', 'aws', 'bucket'],
            'GCS Bucket': ['gcs', 'google', 'storage'],
            'Azure Blob': ['azure', 'blob'],
            'Database Connection String': ['database', 'db_', 'postgres', 'mysql', 'mongo', 'redis'],
            'Hardcoded Password': ['password', 'passwd', 'secret', 'auth'],
            'High-Entropy Secret': ['key', 'secret', 'token', 'auth'],
        }
        keywords = type_keywords.get(secret_type, [])
        keyword_match = any(kw in ctx_lower for kw in keywords)

        entropy = shannon_entropy(value)

        # Strong format-validated types — HIGH confidence regardless
        strong = {
            'AWS Access Key', 'GitHub Token', 'Stripe API Key',
            'SendGrid API Key', 'Notion API Key', 'Linear API Key',
            'Slack Webhook', 'Private Key', 'Database Connection String',
        }
        if secret_type in strong:
            return 'HIGH'

        # Keyword match + good entropy = HIGH
        if keyword_match and entropy > 3.5:
            return 'HIGH'

        # Good entropy alone = MEDIUM
        if entropy > 4.0:
            return 'MEDIUM'

        # Keyword match but low entropy = still LOW (likely false positive)
        if keyword_match and entropy < 3.0:
            return 'LOW'

        # Env var assignment pattern
        env_match = re.search(
            r'(?:NEXT_PUBLIC_|REACT_APP_|VUE_APP_)?[A-Z_]{3,}(?:_KEY|_TOKEN|_SECRET|_DSN)',
            context
        )
        if env_match and entropy > 3.0:
            return 'MEDIUM'

        # Low entropy = LOW confidence (covers "Hardcoded Password entropy 2.5" case)
        if entropy < 3.0:
            return 'LOW'
        return 'LOW'

    # ═════════════════════════════════════════════════════════════
    #  Dedup
    # ═════════════════════════════════════════════════════════════

    def _is_submatch(self, new_type, new_value):
        for existing in self.found_secrets:
            if existing['type'] == new_type:
                continue
            if new_value in existing['value']:
                return True
        return False

    def should_skip_file(self, url):
        return any(lib in url.lower() for lib in self.skip_libraries)

    # ═════════════════════════════════════════════════════════════
    #  JS / asset extraction
    # ═════════════════════════════════════════════════════════════

    def extract_js_urls(self, html, base_url):
        js_urls = []
        for url in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
            full = urljoin(base_url, url)
            if not self.should_skip_file(full):
                js_urls.append(full)
        return js_urls

    def extract_webpack_chunks(self, content, base_url):
        chunks = []
        for path in re.findall(r'["\']([a-zA-Z0-9/_\-]+\.chunk\.js)["\']', content):
            full = urljoin(base_url, path)
            if full not in chunks:
                chunks.append(full)
        for ref in re.findall(r'["\'](?:static/js/|_next/static/chunks/)([a-zA-Z0-9._\-]+\.js)["\']', content):
            p = urlparse(base_url)
            for pfx in ['static/js/', '_next/static/chunks/']:
                full = f"{p.scheme}://{p.netloc}/{pfx}{ref}"
                if full not in chunks:
                    chunks.append(full)
        return chunks

    def extract_same_domain_links(self, html, base_url):
        links = []
        pb = urlparse(base_url)
        for href in re.findall(r'<a[^>]+href=["\']([^"\'#]+)["\']', html, re.I):
            full = urljoin(base_url, href)
            p = urlparse(full)
            if p.netloc == pb.netloc:
                clean = f"{p.scheme}://{p.netloc}{p.path}"
                if clean not in self.scanned_urls and clean not in links:
                    if self._is_in_scope(clean):
                        links.append(clean)
            elif p.netloc and p.scheme in ('http', 'https'):
                # v5.1.1: Track external domains for scope warning
                if not hasattr(self, '_external_domains'):
                    self._external_domains = set()
                self._external_domains.add(p.netloc)
        return links

    # ═════════════════════════════════════════════════════════════
    #  __NEXT_DATA__ / window.__ENV__
    # ═════════════════════════════════════════════════════════════

    def extract_embedded_configs(self, html, source):
        targets = []
        nd = re.search(r'<script\s+id="__NEXT_DATA__"[^>]*>(.*?)</script>', html, re.DOTALL | re.I)
        if nd:
            targets.append(('__NEXT_DATA__', nd.group(1)))
        for var in ['__ENV__', '__CONFIG__', '__APP_CONFIG__', '__RUNTIME_CONFIG__', 'env']:
            m = re.search(r'window\.' + re.escape(var) + r'\s*=\s*(\{.+?\});', html, re.DOTALL)
            if m:
                targets.append((var, m.group(1)))
        for label, raw in targets:
            try:
                data = json.loads(raw)
                flat = self._flatten_json(data)
                synth = '\n'.join(f'{k} = "{v}"' for k, v in flat.items() if isinstance(v, str) and len(v) >= 8)
                if synth:
                    if self.verbose:
                        print(f"{Colors.OKCYAN}  [*] Scanning {label}{Colors.ENDC}")
                    self.scan_content(synth, f"{source} ({label})")
            except (json.JSONDecodeError, TypeError):
                self.scan_content(raw, f"{source} ({label})")

    @staticmethod
    def _flatten_json(obj, prefix=''):
        items = {}
        if isinstance(obj, dict):
            for k, v in obj.items():
                items.update(SecretScanner._flatten_json(v, f"{prefix}.{k}" if prefix else k))
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                items.update(SecretScanner._flatten_json(v, f"{prefix}[{i}]"))
        else:
            items[prefix] = str(obj)
        return items

    # ═════════════════════════════════════════════════════════════
    #  HTTP Header Inspection
    # ═════════════════════════════════════════════════════════════

    HEADER_PATTERNS = [
        ('x-api-key', 'API Key in Header'),
        ('authorization', 'Auth Header Leak'),
        ('x-auth-token', 'Auth Token in Header'),
        ('x-access-token', 'Access Token in Header'),
        ('x-amz-security', 'AWS Security Token in Header'),
    ]

    def inspect_headers(self, response, source):
        for hdr_name, hdr_value in response.headers.items():
            hdr_lower = hdr_name.lower()
            for pat_name, label in self.HEADER_PATTERNS:
                if pat_name in hdr_lower:
                    val = hdr_value.strip()
                    if len(val) >= 8 and '<' not in val:
                        h = f"Header:{label}:{val}"
                        if h not in self.seen_secrets:
                            self.seen_secrets.add(h)
                            self.found_secrets.append({
                                'type': label, 'value': val,
                                'source': f"{source} (header: {hdr_name})",
                                'severity': 'HIGH', 'validated': False,
                                'confidence': 'HIGH', 'entropy': shannon_entropy(val),
                            })
                            print(f"{Colors.WARNING}[HIGH]{Colors.ENDC} "
                                  f"Found {label} in {source} header")

    # ═════════════════════════════════════════════════════════════
    #  Internal IP / URL leak detection
    # ═════════════════════════════════════════════════════════════

    INTERNAL_PATTERNS = [
        (r'(?:https?://)?(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?(?:/\S*)?', 'RFC1918 (10.x)'),
        (r'(?:https?://)?(?:172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?::\d+)?(?:/\S*)?', 'RFC1918 (172.16-31)'),
        (r'(?:https?://)?(?:192\.168\.\d{1,3}\.\d{1,3})(?::\d+)?(?:/\S*)?', 'RFC1918 (192.168)'),
        (r'(?:https?://)?localhost(?::\d+)(?:/\S*)?', 'Localhost'),
        (r'(?:https?://)?127\.0\.0\.1(?::\d+)?(?:/\S*)?', 'Loopback'),
        (r'https?://[a-z0-9\-]+\.(?:internal|local|corp|lan|intranet)(?::\d+)?(?:/\S*)?', 'Internal hostname'),
    ]

    def scan_internal_urls(self, content, source):
        for pattern, label in self.INTERNAL_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                val = match.group(0)
                h = f"Internal:{val}"
                if h not in self.seen_secrets:
                    self.seen_secrets.add(h)
                    self.stats['internal_ips_found'] += 1
                    self.discovered_internal_urls.append({'type': label, 'value': val, 'source': source})
                    if self.verbose:
                        print(f"{Colors.OKCYAN}[INFO]{Colors.ENDC} Internal URL ({label}): {val}")

    # ═════════════════════════════════════════════════════════════
    #  API endpoint discovery
    # ═════════════════════════════════════════════════════════════

    API_ENDPOINT_PATTERNS = [
        r'fetch\s*\(\s*["\'](/api/[^"\']+)["\']',
        r'axios\.\w+\s*\(\s*["\'](/api/[^"\']+)["\']',
        r'\.get\s*\(\s*["\'](https?://[^"\']*api[^"\']*)["\']',
        r'\.post\s*\(\s*["\'](https?://[^"\']*api[^"\']*)["\']',
        r'["\'](/api/v\d+/[^"\']+)["\']',
        r'endpoint["\']?\s*[:\=]\s*["\'](https?://[^"\']+)["\']',
        r'baseURL["\']?\s*[:\=]\s*["\'](https?://[^"\']+)["\']',
    ]

    def scan_api_endpoints(self, content, source):
        for pattern in self.API_ENDPOINT_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                ep = match.group(1)
                h = f"Endpoint:{ep}"
                if h not in self.seen_secrets:
                    self.seen_secrets.add(h)
                    self.stats['endpoints_discovered'] += 1
                    self.discovered_endpoints.append({'endpoint': ep, 'source': source})

    # ═════════════════════════════════════════════════════════════
    #  NEW v2.8: Generic high-entropy string detection
    # ═════════════════════════════════════════════════════════════

    HIGH_ENTROPY_KEYWORDS = [
        'key', 'secret', 'token', 'auth', 'password', 'passwd', 'credential',
        'api_key', 'apikey', 'access_key', 'private_key', 'client_secret',
        'app_secret', 'signing_key', 'encryption_key', 'bearer',
    ]

    def scan_high_entropy(self, content, source):
        """Catch unknown secrets: high-entropy strings near security keywords."""
        # Match KEY = "value" or KEY: "value" patterns
        pattern = re.compile(
            r'(?:' + '|'.join(self.HIGH_ENTROPY_KEYWORDS) + r')'
            r'["\']?\s*[:\=]\s*["\']([A-Za-z0-9\-_/+\.=]{20,128})["\']',
            re.IGNORECASE
        )

        for match in pattern.finditer(content):
            val = match.group(1)
            h = f"HighEntropy:{val}"
            if h in self.seen_secrets:
                continue

            # Calculate entropy
            ent = shannon_entropy(val)
            if ent < 4.0:
                continue  # Not random enough

            # Skip if already matched by a known pattern
            known_hash = None
            for st in self.found_secrets:
                if val in st['value'] or st['value'] in val:
                    known_hash = True
                    break
            if known_hash:
                continue

            # Skip placeholders
            vl = val.lower()
            if any(s in vl for s in ['example', 'placeholder', 'xxxxx', 'your_',
                                      'changeme', 'undefined', 'null', 'process.env']):
                continue

            self.seen_secrets.add(h)
            self.stats['high_entropy_found'] += 1

            ctx_s = max(0, match.start() - 100)
            ctx_e = min(len(content), match.end() + 100)
            context = content[ctx_s:ctx_e]

            # Identify the keyword
            keyword = 'unknown'
            for kw in self.HIGH_ENTROPY_KEYWORDS:
                if kw in context.lower():
                    keyword = kw
                    break

            finding = {
                'type': 'High-Entropy Secret',
                'value': val, 'source': source,
                'severity': 'MEDIUM', 'validated': False,
                'confidence': 'MEDIUM', 'entropy': ent,
                'keyword_hint': keyword,
            }
            self.found_secrets.append(finding)
            self.progress.increment('secrets_found')
            print(f"{Colors.OKCYAN}[MEDIUM]{Colors.ENDC} [conf:MEDIUM] "
                  f"[entropy:{ent}] High-entropy string near '{keyword}' in {source}")

    # ═════════════════════════════════════════════════════════════
    #  .env probing
    # ═════════════════════════════════════════════════════════════

    def probe_env_files(self, base_url):
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if self.verbose:
            print(f"{Colors.OKCYAN}  [*] Probing {len(ENV_FILE_PATHS)} env paths...{Colors.ENDC}")
        for path in ENV_FILE_PATHS:
            url = origin + path
            try:
                resp = self._resilient_get(url, timeout=8)
                if resp is None:
                    continue
                ct = resp.headers.get('Content-Type', '')
                if resp.status_code == 200 and 'html' not in ct.lower():
                    text = resp.text[:5000]
                    env_lines = re.findall(r'^[A-Z_]{2,}=.+', text, re.MULTILINE)
                    if len(env_lines) >= 2:
                        self.stats['env_files_found'] += 1
                        self.env_files_found.append({
                            'url': url, 'lines': len(env_lines),
                            'sample_keys': [l.split('=')[0] for l in env_lines[:5]],
                        })
                        print(f"{Colors.FAIL}[CRITICAL]{Colors.ENDC} "
                              f"[conf:HIGH] Exposed .env file: {url} ({len(env_lines)} vars)")
                        self.scan_content(text, f"{url} (.env)")
            except Exception:
                pass

    # ═════════════════════════════════════════════════════════════
    #  robots.txt / sitemap
    # ═════════════════════════════════════════════════════════════

    def parse_robots_sitemap(self, base_url):
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        extra = []
        try:
            resp = self._resilient_get(f"{origin}/robots.txt", timeout=8)
            if resp and resp.status_code == 200:
                for line in resp.text.splitlines():
                    m = re.match(r'^(?:Dis)?allow:\s*(\S+)', line, re.I)
                    if m:
                        path = m.group(1)
                        if path != '/' and '*' not in path:
                            full = origin + path
                            if full not in self.scanned_urls and self._is_in_scope(full):
                                extra.append(full)
                    m = re.match(r'^Sitemap:\s*(\S+)', line, re.I)
                    if m:
                        extra.extend(self._parse_sitemap(m.group(1)))
        except Exception:
            pass
        if not any('sitemap' in u.lower() for u in extra):
            extra.extend(self._parse_sitemap(f"{origin}/sitemap.xml"))
        return extra[:50]

    def _parse_sitemap(self, url):
        urls = []
        try:
            resp = self._resilient_get(url, timeout=8)
            if resp and resp.status_code == 200:
                urls = re.findall(r'<loc>\s*(.*?)\s*</loc>', resp.text, re.I)[:30]
        except Exception:
            pass
        return urls

    # ═════════════════════════════════════════════════════════════
    #  GraphQL introspection
    # ═════════════════════════════════════════════════════════════

    INTROSPECTION_QUERY = '{"query":"{ __schema { types { name } } }"}'

    def probe_graphql_endpoints(self, base_url):
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if self.verbose:
            print(f"{Colors.OKCYAN}  [*] Probing GraphQL endpoints...{Colors.ENDC}")
        for path in GRAPHQL_PATHS:
            url = origin + path
            try:
                headers = self._get_headers()
                headers['Content-Type'] = 'application/json'
                self.rate_limiter.wait()
                resp = self.session.post(url, data=self.INTROSPECTION_QUERY,
                                         headers=headers, timeout=8)
                self.stats['requests_made'] += 1
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if 'data' in data and '__schema' in (data.get('data') or {}):
                            types = data['data']['__schema'].get('types', [])
                            self.stats['graphql_found'] += 1
                            self.graphql_endpoints.append({'url': url, 'types_count': len(types)})
                            print(f"{Colors.FAIL}[CRITICAL]{Colors.ENDC} "
                                  f"[conf:HIGH] GraphQL introspection: {url}")
                    except (json.JSONDecodeError, TypeError):
                        pass
            except Exception:
                pass

    # ═════════════════════════════════════════════════════════════
    #  Core scanning
    # ═════════════════════════════════════════════════════════════

    def scan_content(self, content, source):
        if self._is_cdn_waf_source(source):
            return

        # ── AccuracyEngine: Cache content for context analysis ──
        self.content_cache[source] = content

        # ── AccuracyEngine: Pre-scan for encoded/obfuscated secrets [6][7] ──
        _, extra_findings = self.accuracy_engine.pre_scan_content(content, source)
        for ef in extra_findings:
            h = f"{ef['type']}:{ef['value']}"
            if h not in self.seen_secrets:
                self.seen_secrets.add(h)
                self.found_secrets.append(ef)
                self.progress.increment('secrets_found')
                sc = Colors.WARNING if ef['severity'] == 'HIGH' else Colors.OKCYAN
                print(f"{sc}[{ef['severity']}]{Colors.ENDC}"
                      f" [encoded] Found {ef['type']} in {source}")

        for secret_type, config in self.patterns.items():
            flags = re.MULTILINE if config.get('case_sensitive') else re.IGNORECASE | re.MULTILINE
            for pattern in config['patterns']:
                for match in re.finditer(pattern, content, flags):
                    if match.lastindex:
                        if match.lastindex == 1:
                            val = match.group(1)
                        elif match.lastindex == 3 and 'sentry' in secret_type.lower():
                            val = f"https://{match.group(1)}@{match.group(2)}.ingest.sentry.io/{match.group(3)}"
                        else:
                            val = match.group(1) if match.lastindex >= 1 else match.group(0)
                    else:
                        val = match.group(0)

                    if val in KNOWN_TEST_KEYS:
                        continue
                    h = f"{secret_type}:{val}"
                    if h in self.seen_secrets:
                        continue
                    self.seen_secrets.add(h)

                    # v4.0: Per-source cap — max 3 findings of same type per URL
                    source_type_key = f"{secret_type}@{source}"
                    source_type_count = sum(1 for f in self.found_secrets
                                            if f['type'] == secret_type and f['source'] == source)
                    if source_type_count >= 3:
                        continue

                    if self._is_submatch(secret_type, val):
                        continue

                    ctx_s = max(0, match.start() - 200)
                    ctx_e = min(len(content), match.end() + 200)
                    context = content[ctx_s:ctx_e]

                    if config.get('context_required'):
                        kw_map = {
                            'Algolia API Key': ['algolia'],
                            'Mixpanel Project Token': ['mixpanel'],
                            'Amplitude API Key': ['amplitude'],
                            'Okta API Token': ['okta'],
                            'Airtable API Key': ['airtable'],
                            'OAuth Access Token': ['oauth', 'access_token', 'bearer', 'authorization'],
                            'OAuth Refresh Token': ['oauth', 'refresh_token', 'refresh'],
                            'Generic Bearer Token': ['bearer', 'authorization', 'auth'],
                        }
                        kws = kw_map.get(secret_type, [secret_type.split()[0].lower()])
                        if not any(k in context.lower() for k in kws):
                            continue

                    confidence = self._score_confidence(secret_type, val, context)
                    entropy = shannon_entropy(val)

                    validated = False
                    if config.get('validate') and not self.no_validate:
                        try:
                            validated = config['validate'](val)
                        except Exception:
                            pass
                        # If validation is required and failed, skip
                        if config.get('require_validation') and not validated:
                            self.seen_secrets.discard(h)
                            continue

                    # JWT decode + security scoring (v2.9 enhanced)
                    jwt_info = None
                    if secret_type == 'JWT Token':
                        jwt_info = decode_jwt(val)
                        if jwt_info:
                            a = jwt_info.get('analysis', {})
                            vulns = a.get('vulnerabilities', [])
                            risk_grade = a.get('risk_grade', 'LOW')
                            if vulns or risk_grade in ('CRITICAL', 'HIGH'):
                                confidence = 'HIGH'
                                self.stats['jwt_critical'] += 1
                            if a.get('expired'):
                                confidence = 'MEDIUM' if confidence == 'HIGH' else confidence

                    finding = {
                        'type': secret_type, 'value': val,
                        'source': source, 'severity': config['severity'],
                        'validated': validated, 'confidence': confidence,
                        'entropy': entropy,
                    }
                    if jwt_info:
                        finding['jwt_decoded'] = jwt_info

                    # ── Active verification — v4.0 (50+ verifiers) ──
                    if self.verifier:
                        vresult = self.verifier.verify(secret_type, val)
                        if vresult:
                            finding['verified_live'] = vresult.get('live')
                            finding['verification_detail'] = vresult.get('detail', '')
                            if vresult.get('live') is True:
                                self.stats['secrets_verified_live'] += 1
                                self.progress.increment('verified')
                                # Auto-escalate severity
                                if config['severity'] != 'CRITICAL':
                                    finding['severity'] = 'CRITICAL'
                                    finding['severity_escalated'] = True
                                confidence = 'HIGH'
                                finding['confidence'] = 'HIGH'
                                print(f"{Colors.FAIL}  ⚡ VERIFIED LIVE: "
                                      f"{vresult.get('detail','')}{Colors.ENDC}")

                                # Google API scope check
                                if secret_type in ('Google API Key', 'Firebase Config'):
                                    scope = self.verifier.verify_google_scope(val)
                                    finding['google_api_scopes'] = scope
                                    self.google_scope_results.append({
                                        'key': val[:12] + '...', 'scopes': scope,
                                    })
                                    active_apis = [k for k, v in scope.items() if 'ACTIVE' in v]
                                    if active_apis:
                                        print(f"{Colors.FAIL}  🔓 Unrestricted APIs: "
                                              f"{', '.join(active_apis)}{Colors.ENDC}")
                            elif vresult.get('live') is False:
                                if self.verbose:
                                    print(f"{Colors.DIM}  ✗ Not live: "
                                          f"{vresult.get('detail','')}{Colors.ENDC}")

                    # Source map escalation
                    if '.map' in source and confidence == 'MEDIUM':
                        confidence = 'HIGH'
                        finding['confidence'] = 'HIGH'
                        finding['escalation_reason'] = 'Found in source map (not intended to be public)'

                    self.found_secrets.append(finding)
                    self.progress.increment('secrets_found')

                    sc = {
                        'CRITICAL': Colors.FAIL, 'HIGH': Colors.WARNING,
                        'MEDIUM': Colors.OKCYAN, 'LOW': Colors.OKBLUE,
                    }.get(finding['severity'], Colors.ENDC)
                    print(f"{sc}[{finding['severity']}]{Colors.ENDC}"
                          f" [conf:{confidence}] [entropy:{entropy}] "
                          f"Found {secret_type} in {source}")

        # Additional scans
        self.scan_internal_urls(content, source)
        self.scan_api_endpoints(content, source)
        self.scan_high_entropy(content, source)

    # ═════════════════════════════════════════════════════════════
    #  Source-map harvesting
    # ═════════════════════════════════════════════════════════════

    def try_source_map(self, js_url, js_content):
        sm = re.search(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)', js_content)
        if not sm:
            map_url = js_url + '.map'
        else:
            ref = sm.group(1)
            if ref.startswith('data:'):
                return
            map_url = urljoin(js_url, ref)
        if map_url in self._seen_source_maps:
            return  # Already processed this source map
        try:
            resp = self._resilient_get(map_url, timeout=8)
            if resp is None or resp.status_code != 200:
                return
            if len(resp.text) > 10_000_000:
                return
            self._seen_source_maps.add(map_url)
            self.stats['source_maps_found'] += 1
            if self.verbose:
                print(f"{Colors.OKCYAN}  [+] Source map: {map_url}{Colors.ENDC}")
            try:
                sm_data = resp.json()

                # ── v2.9: Deep source map analysis ──
                intel = SourceMapAnalyzer.analyze(sm_data, map_url)
                self.source_map_intel.append(intel)
                self.stats['sourcemap_files_found'] += intel['total_files']

                # Feed npm packages to supply chain
                if intel['npm_packages']:
                    self.supply_chain.add_npm_packages(intel['npm_packages'])

                if self.verbose and intel['frameworks']:
                    print(f"{Colors.OKCYAN}    Frameworks: "
                          f"{', '.join(intel['frameworks'])}{Colors.ENDC}")
                if self.verbose and intel['npm_packages']:
                    print(f"{Colors.OKCYAN}    npm packages: "
                          f"{len(intel['npm_packages'])} found{Colors.ENDC}")

                # Report secret-related comments
                for comment in intel.get('comments', []):
                    if comment['type'] == 'Secret Comment':
                        print(f"{Colors.WARNING}[HIGH]{Colors.ENDC} "
                              f"Secret comment in source map: "
                              f"{comment['file']} → {comment['text'][:60]}")

                for i, src in enumerate(sm_data.get('sourcesContent', [])):
                    if src and len(src) > 20:
                        sources = sm_data.get('sources', [])
                        fname = sources[i] if i < len(sources) else 'unknown'
                        self.scan_content(src, f"{map_url} → {fname}")
            except json.JSONDecodeError:
                self.scan_content(resp.text, f"{map_url} (raw)")
        except Exception:
            pass

    def _fetch_js(self, js_url):
        resp = self._resilient_get(js_url, timeout=10)
        if resp is None:
            return None
        self.progress.increment('js_scanned')
        return (js_url, resp.text)

    # ═════════════════════════════════════════════════════════════
    #  Scan URL
    # ═════════════════════════════════════════════════════════════

    def scan_url(self, url, depth=0):
        if url in self.scanned_urls:
            return
        if not self._is_in_scope(url):
            if self.verbose:
                print(f"{Colors.DIM}  [~] Out of scope: {url}{Colors.ENDC}")
            return
        self.scanned_urls.add(url)

        try:
            if self.verbose:
                print(f"{Colors.OKBLUE}{'  '*depth}[*] Scanning: {url}{Colors.ENDC}")

            response = self._resilient_get(url, timeout=12, is_page=True)
            if response is None:
                print(f"{Colors.FAIL}[!] Could not fetch {url}{Colors.ENDC}")
                return

            html_content = response.text
            self.inspect_headers(response, url)

            # v3.0: Security headers audit
            if depth == 0:
                self.headers_auditor.audit(dict(response.headers), url)

            # v2.9: Supply chain analysis
            self.supply_chain.analyze_script_tags(html_content, url)

            for script in re.findall(r'<script[^>]*>(.*?)</script>', html_content, re.DOTALL | re.I):
                if len(script.strip()) > 10:
                    self.scan_content(script, f"{url} (inline)")

            self.extract_embedded_configs(html_content, url)
            self.scan_content(html_content, url)

            # v3.0: Cloud native scanning
            if self.cloud_scanner:
                self.cloud_scanner.scan(html_content, url)

            # Skip probes on archive.org URLs (pointless + wastes time)
            is_archive_url = 'web.archive.org' in url or 'archive.org' in url

            if depth == 0 and not is_archive_url:
                self.parse_robots_sitemap(url)
            if depth == 0 and self.probe_env and not is_archive_url:
                self.probe_env_files(url)
            if depth == 0 and self.probe_graphql and not is_archive_url:
                self.probe_graphql_endpoints(url)
            # v3.0: Swagger/OpenAPI probing
            if depth == 0 and self.probe_swagger and not is_archive_url:
                self.api_discovery.probe_swagger(url, self._resilient_get)
            # v3.0: Enhanced GraphQL schema extraction
            if depth == 0 and self.probe_graphql and not is_archive_url:
                self.api_discovery.probe_graphql_schema(url, self._resilient_get)

            js_urls = self.extract_js_urls(html_content, url)
            if self.verbose:
                print(f"{Colors.OKBLUE}  [*] {len(js_urls)} external JS files{Colors.ENDC}")

            all_chunks = []
            with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
                futures = {pool.submit(self._fetch_js, u): u for u in js_urls}
                for future in as_completed(futures):
                    result = future.result()
                    if result is None:
                        continue
                    js_url, js_text = result
                    self.scan_content(js_text, js_url)
                    self.try_source_map(js_url, js_text)
                    self.supply_chain.analyze_js_content(js_text, js_url)
                    self.api_discovery.scan_grpc(js_text, js_url)
                    if self.cloud_scanner:
                        self.cloud_scanner.scan(js_text, js_url)
                    # v4.0: Offensive recon on JS
                    if self.enable_ssrf:
                        self.ssrf_prober.scan_for_ssrf(js_text, js_url)
                        self.ssrf_prober.check_metadata_leaks(js_text, js_url)
                    self.internal_api_enum.extract_routes(js_text, js_url)
                    if self.enable_fuzz_idor:
                        self.idor_fuzzer.find_candidates(js_text, js_url)
                    all_chunks.extend(self.extract_webpack_chunks(js_text, js_url))

            unique_chunks = list(set(all_chunks) - set(js_urls) - self.scanned_urls)
            if unique_chunks:
                self.stats['chunks_discovered'] += len(unique_chunks)
                for cu in unique_chunks[:30]:
                    r = self._fetch_js(cu)
                    if r:
                        self.scan_content(r[1], cu)
                        self.try_source_map(cu, r[1])

            if depth < self.crawl_depth:
                # v5.1.1: Early exit — detect low-value targets
                if self._should_reduce_crawl(url, html_content):
                    if self.verbose:
                        print(f"{Colors.WARNING}  [SMART] Low-value content detected — "
                              f"crawl depth reduced for {url}{Colors.ENDC}")
                else:
                    children = self.extract_same_domain_links(html_content, url)
                    for link in children[:20]:
                        self.scan_url(link, depth + 1)

            self.progress.update(urls_done=len(self.scanned_urls))

        except Exception as e:
            print(f"{Colors.FAIL}[!] Error scanning {url}: {e}{Colors.ENDC}")

    # ═════════════════════════════════════════════════════════════
    #  v5.1.1: Exploit Path Suggestion Engine + Exploitability Probability
    # ═════════════════════════════════════════════════════════════

    # Maps finding types to exploit suggestions and base probability
    EXPLOIT_PLAYBOOK = {
        'Google Maps API Key': {
            'prob': 40, 'steps': [
                'Check billing status via Places/Geocoding API calls',
                'Test DirectionsAPI for route enumeration',
                'Check if key has admin/owner scope restrictions',
            ]
        },
        'AWS Access Key': {
            'prob': 75, 'steps': [
                'Run: aws sts get-caller-identity --access-key-id <key>',
                'Enumerate IAM permissions with enumerate-iam.py',
                'Check S3 bucket access and EC2 describe-instances',
                'Look for privilege escalation paths (iam:PassRole)',
            ]
        },
        'Stripe Secret Key': {
            'prob': 85, 'steps': [
                'List customers: curl -u sk_live_xxx: https://api.stripe.com/v1/customers',
                'Check payment intents and charges',
                'Verify scope (restricted vs full)',
            ]
        },
        'GitHub Token': {
            'prob': 70, 'steps': [
                'Check token scopes: curl -H "Authorization: token xxx" https://api.github.com',
                'List private repos and org memberships',
                'Check for write access to repos (code injection risk)',
            ]
        },
        'Database URI': {
            'prob': 65, 'steps': [
                'Test connectivity from external network',
                'Check for default credentials or weak passwords',
                'Enumerate databases, tables, and user privileges',
            ]
        },
        'Private Key': {
            'prob': 60, 'steps': [
                'Identify key type (RSA, EC, Ed25519) and purpose (SSH, TLS, signing)',
                'Check for associated certificate or known_hosts',
                'Test authentication against discovered endpoints',
            ]
        },
        'JSON Web Token': {
            'prob': 55, 'steps': [
                'Test alg:none bypass (remove signature, set alg to none)',
                'Brute-force HMAC secret with jwt-cracker or hashcat',
                'Check for expired token reuse (session fixation)',
                'Modify claims (role/admin escalation)',
            ]
        },
        'Slack Token': {
            'prob': 65, 'steps': [
                'Test: curl -H "Authorization: Bearer xoxb-xxx" https://slack.com/api/auth.test',
                'List channels and message history',
                'Check for file access and admin permissions',
            ]
        },
        'Firebase Config': {
            'prob': 50, 'steps': [
                'Test Firestore rules: curl https://<project>.firebaseio.com/.json',
                'Check Firebase Auth user enumeration',
                'Test Cloud Functions for unauthenticated access',
            ]
        },
        'OpenAI API Key': {
            'prob': 60, 'steps': [
                'Check billing and usage: curl with Authorization header',
                'Test model access (GPT-4, DALL-E)',
                'Estimate financial exposure from rate limits',
            ]
        },
    }

    # Generic patterns for types not in the playbook
    GENERIC_EXPLOIT_PATTERNS = {
        'api': {'prob': 50, 'steps': ['Test API key scopes and permissions', 'Check rate limits and billing', 'Enumerate accessible endpoints']},
        'token': {'prob': 55, 'steps': ['Verify token validity and expiration', 'Test scope of access', 'Check for refresh token flow']},
        'password': {'prob': 60, 'steps': ['Test credential against login endpoints', 'Check for password reuse across services', 'Verify account access level']},
        'key': {'prob': 45, 'steps': ['Identify the service this key belongs to', 'Test key against known API endpoints', 'Check for rate limiting or billing']},
        'secret': {'prob': 55, 'steps': ['Identify the associated service', 'Test secret against auth endpoints', 'Check scope and permissions']},
        'bucket': {'prob': 65, 'steps': ['Test public read: aws s3 ls s3://<bucket>', 'Test write access with safe upload', 'Check for sensitive files (backups, configs)']},
    }

    def _get_exploit_suggestions(self, finding):
        """Generate exploit path suggestions and exploitability probability for a finding."""
        ftype = finding.get('type', '')
        sev = finding.get('severity', 'LOW')
        verified = finding.get('verified_live', False)
        confidence = finding.get('confidence_score', 50)

        # Check exact match in playbook
        result = None
        for key, playbook in self.EXPLOIT_PLAYBOOK.items():
            if key.lower() in ftype.lower():
                result = {'probability': playbook['prob'], 'next_steps': list(playbook['steps'])}
                break

        # Fall back to generic pattern matching
        if not result:
            ftype_lower = ftype.lower()
            for pattern, generic in self.GENERIC_EXPLOIT_PATTERNS.items():
                if pattern in ftype_lower:
                    result = {'probability': generic['prob'], 'next_steps': list(generic['steps'])}
                    break

        if not result:
            result = {'probability': 20, 'next_steps': ['Investigate the context and identify the associated service']}

        # Modifiers: adjust probability based on finding properties
        if verified is True:
            result['probability'] = min(99, result['probability'] + 25)
            result['next_steps'].insert(0, 'KEY IS LIVE — immediate exploitation possible')
        elif verified is False:
            result['probability'] = max(5, result['probability'] - 20)

        if confidence >= 85:
            result['probability'] = min(99, result['probability'] + 10)
        elif confidence < 40:
            result['probability'] = max(5, result['probability'] - 15)

        if sev == 'CRITICAL':
            result['probability'] = min(99, result['probability'] + 10)
        elif sev in ('LOW', 'INFO'):
            result['probability'] = max(5, result['probability'] - 10)

        # Context-specific boosts
        source = finding.get('source', '')
        if '.env' in source or 'config' in source.lower():
            result['probability'] = min(99, result['probability'] + 5)
        if 'staging' in source or 'dev' in source or 'test' in source:
            result['probability'] = min(99, result['probability'] + 5)

        return result

    # ═════════════════════════════════════════════════════════════
    #  v5.1.1: Early Exit Intelligence
    # ═════════════════════════════════════════════════════════════

    def _should_reduce_crawl(self, url, html_content):
        """Detect low-value targets and recommend reducing crawl depth.
        Returns True if this target is likely static/marketing content."""
        # Only evaluate after scanning enough pages
        if len(self.scanned_urls) < 8:
            return False

        # Check: no secrets found so far AND mostly static content
        if self.found_secrets:
            return False  # We're finding things, keep going

        # Indicators of low-value (static/marketing) content
        low_value_signals = 0
        content_lower = html_content.lower()

        # Marketing page indicators
        marketing_patterns = ['request a demo', 'get started', 'pricing',
                              'contact us', 'sign up free', 'schedule a call',
                              'trusted by', 'customer stories', 'read more']
        marketing_hits = sum(1 for p in marketing_patterns if p in content_lower)
        if marketing_hits >= 3:
            low_value_signals += 2

        # Very few JS files (static site)
        js_count = len(re.findall(r'<script[^>]*src=', html_content, re.I))
        if js_count <= 2:
            low_value_signals += 1

        # No inline scripts with meaningful code
        inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', html_content, re.DOTALL | re.I)
        meaningful_inline = sum(1 for s in inline_scripts if len(s.strip()) > 200)
        if meaningful_inline == 0:
            low_value_signals += 1

        # High WAF block rate (> 50% of requests blocked)
        total_req = self.stats['requests_made']
        if total_req > 20 and self.stats['waf_blocked'] / total_req > 0.4:
            low_value_signals += 1

        # Low entropy across scanned content
        if len(self.scanned_urls) >= 10 and self.stats.get('high_entropy_found', 0) == 0:
            low_value_signals += 1

        return low_value_signals >= 3

    # ═════════════════════════════════════════════════════════════
    #  Output — Terminal
    # ═════════════════════════════════════════════════════════════

    def print_details(self):
        for i, s in enumerate(self.found_secrets, 1):
            print("=" * 70)
            sev = s.get('severity', 'LOW')
            sc = {'CRITICAL': Colors.FAIL, 'HIGH': Colors.WARNING,
                  'MEDIUM': Colors.OKCYAN, 'LOW': Colors.OKBLUE,
                  'INFO': Colors.DIM}.get(sev, Colors.ENDC)
            conf_score = s.get('confidence_score', '?')
            risk_score = s.get('risk_score', '?')
            print(f"{sc}[{sev}]{Colors.ENDC} {s['type']}")
            print(f"  Confidence: {conf_score}/100  |  "
                  f"Risk: {risk_score}/100  |  "
                  f"Entropy: {s.get('entropy',0):.1f}")

            val = s['value']
            if len(val) > 80:
                val = val[:77] + "..."
            print(f"  Value: {val}")
            print(f"  Source: {s['source']}")

            # v2 Factor breakdown
            factors = s.get('score_factors')
            if factors:
                print(f"{Colors.DIM}  Factors: "
                      f"FMT:{factors.get('format_validity','-')} "
                      f"CTX:{factors.get('context_strength','-')} "
                      f"OWN:{factors.get('domain_ownership','-')} "
                      f"FILE:{factors.get('file_risk_weight','-')} "
                      f"ENT:{factors.get('entropy_range_fit','-')} "
                      f"LIVE:{factors.get('live_validation','-')}"
                      f"{Colors.ENDC}")

            if s.get('validated'):
                print(f"{Colors.OKGREEN}  + Format validated{Colors.ENDC}")
            if s.get('verified_live') is True:
                print(f"{Colors.FAIL}  ! VERIFIED LIVE: {s.get('verification_detail','')}{Colors.ENDC}")
            elif s.get('verified_live') is False:
                print(f"{Colors.DIM}  x Not live: {s.get('verification_detail','')}{Colors.ENDC}")
            if s.get('severity_downgraded'):
                print(f"{Colors.DIM}  v Severity downgraded by confidence score{Colors.ENDC}")
            if s.get('severity_escalated'):
                print(f"{Colors.WARNING}  ^ Severity escalated (verified live){Colors.ENDC}")
            if s.get('escalation_reason'):
                print(f"{Colors.WARNING}  ^ {s['escalation_reason']}{Colors.ENDC}")
            if s.get('keyword_hint'):
                print(f"  Keyword hint: {s['keyword_hint']}")
            if s.get('encoding'):
                print(f"  Encoding: {s['encoding']}")
            if s.get('multi_file'):
                src_count = len(s.get('all_sources', []))
                print(f"  Multi-file: found in {src_count} sources")
            if s.get('duplicate_count'):
                print(f"  Deduplicated: {s['duplicate_count']} duplicate(s) merged")
            if s.get('cross_repo'):
                cr = s['cross_repo']
                if cr.get('repo_count', 0) > 1:
                    print(f"{Colors.FAIL}  CROSS-REPO: found across {cr['repo_count']} targets "
                          f"(x{cr['boost_multiplier']:.1f} boost){Colors.ENDC}")
                    if cr.get('is_leaked_widely'):
                        print(f"{Colors.FAIL}  >> WIDELY LEAKED <<{Colors.ENDC}")
            if s.get('accuracy_notes'):
                for note in s['accuracy_notes']:
                    print(f"{Colors.DIM}  [{note}]{Colors.ENDC}")

            # Google scope
            if s.get('google_api_scopes'):
                print(f"{Colors.OKCYAN}  Google API Scopes:{Colors.ENDC}")
                for api, status in s['google_api_scopes'].items():
                    icon = '🔓' if 'ACTIVE' in status else '🔒'
                    print(f"    {icon} {api}: {status}")

            # JWT security analysis (v2.9 enhanced)
            jwt_info = s.get('jwt_decoded')
            if jwt_info:
                a = jwt_info.get('analysis', {})
                score = a.get('risk_score', 0)
                grade = a.get('risk_grade', '?')
                gc = {'CRITICAL': Colors.FAIL, 'HIGH': Colors.WARNING,
                      'MEDIUM': Colors.OKCYAN, 'LOW': Colors.OKGREEN}.get(grade, Colors.ENDC)
                print(f"{Colors.OKCYAN}  JWT Security Analysis:{Colors.ENDC}")
                print(f"    Algorithm: {a.get('algorithm')} "
                      f"({a.get('algorithm_rating','?')})")
                print(f"    {gc}Risk: {grade} (score: {score}/100){Colors.ENDC}")
                if a.get('missing_claims'):
                    print(f"    Missing claims: {', '.join(a['missing_claims'])}")
                if a.get('lifetime_days'):
                    print(f"    Lifetime: {a['lifetime_days']} days")
                if a.get('permissions'):
                    print(f"    Permissions: {', '.join(a['permissions'][:8])}")
                if a.get('pii_claims'):
                    for k, v in a['pii_claims'].items():
                        print(f"    {k}: {v}")
                for vuln in a.get('vulnerabilities', []):
                    print(f"{Colors.FAIL}    ⚠ {vuln}{Colors.ENDC}")
                if a.get('expired'):
                    print(f"{Colors.DIM}    Token expired since: "
                          f"{a.get('expired_since','?')}{Colors.ENDC}")

            # v5.1.1: Exploit path suggestions + exploitability probability
            suggestions = self._get_exploit_suggestions(s)
            if suggestions:
                prob = suggestions.get('probability', 0)
                prob_color = Colors.FAIL if prob >= 70 else (Colors.WARNING if prob >= 40 else Colors.OKCYAN)
                print(f"{prob_color}  ⚡ Exploit Probability: {prob}%{Colors.ENDC}")
                if suggestions.get('next_steps'):
                    print(f"{Colors.DIM}  Suggested Next Steps:{Colors.ENDC}")
                    for step in suggestions['next_steps'][:4]:
                        print(f"{Colors.DIM}    → {step}{Colors.ENDC}")
            print()

    def print_summary(self):
        self.progress.finish()
        print("\n" + "=" * 70)
        print(f"{Colors.BOLD}SCAN SUMMARY — v{__version__} by {__author__}{Colors.ENDC}")
        print("=" * 70)

        if not self.found_secrets:
            print(f"{Colors.OKGREEN}No high-confidence secrets detected.{Colors.ENDC}")
            print(f"{Colors.DIM}  Target appears hardened against passive secret exposure.{Colors.ENDC}")
            # Provide intelligent guidance based on what WAS found
            surface_hints = []
            if self.stats.get('header_issues', 0) > 0:
                surface_hints.append("Security header misconfigurations (CSP, CORS)")
            if self.stats.get('sri_missing', 0) > 0:
                surface_hints.append("Supply chain integrity (missing SRI)")
            if self.stats.get('swagger_specs', 0) > 0:
                surface_hints.append("Exposed API documentation (Swagger/OpenAPI)")
            if self.stats.get('waf_blocked', 0) > 10:
                surface_hints.append("WAF-protected endpoints (may hide deeper issues)")
            if not surface_hints:
                surface_hints = ["Application logic", "Auth flows", "Business logic vulnerabilities"]
            print(f"{Colors.DIM}  Primary attack surface likely:{Colors.ENDC}")
            for hint in surface_hints[:5]:
                print(f"{Colors.DIM}    → {hint}{Colors.ENDC}")
        else:
            print(f"Total findings: {len(self.found_secrets)}")
            by_sev = defaultdict(int)
            for s in self.found_secrets:
                by_sev[s['severity']] += 1
            print("\nBy Severity:")
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                if sev in by_sev:
                    c = {'CRITICAL': Colors.FAIL, 'HIGH': Colors.WARNING,
                         'MEDIUM': Colors.OKCYAN, 'LOW': Colors.OKBLUE}.get(sev, '')
                    print(f"  {c}{sev}: {by_sev[sev]}{Colors.ENDC}")

            # Verified live count
            live_count = sum(1 for s in self.found_secrets if s.get('verified_live') is True)
            if live_count:
                print(f"\n{Colors.FAIL}⚡ VERIFIED LIVE: {live_count} secret(s){Colors.ENDC}")

            print("\nBy Type:")
            by_type = defaultdict(int)
            for s in self.found_secrets:
                by_type[s['type']] += 1
            for t, c in sorted(by_type.items()):
                print(f"  {t}: {c}")

        if self.discovered_endpoints:
            print(f"\n{Colors.BOLD}API Endpoints: {len(self.discovered_endpoints)}{Colors.ENDC}")
            for ep in self.discovered_endpoints[:10]:
                print(f"  {ep['endpoint']}")
        if self.discovered_internal_urls:
            print(f"\n{Colors.BOLD}Internal URLs: {len(self.discovered_internal_urls)}{Colors.ENDC}")
            for iu in self.discovered_internal_urls[:10]:
                print(f"  [{iu['type']}] {iu['value']}")
        if self.env_files_found:
            print(f"\n{Colors.FAIL}⚠ .env Files: {len(self.env_files_found)}{Colors.ENDC}")
            for ef in self.env_files_found:
                print(f"  {ef['url']} ({ef['lines']} vars)")
        if self.graphql_endpoints:
            print(f"\n{Colors.FAIL}⚠ GraphQL: {len(self.graphql_endpoints)}{Colors.ENDC}")
            for gql in self.graphql_endpoints:
                print(f"  {gql['url']}")
        if self.google_scope_results:
            print(f"\n{Colors.FAIL}⚠ Google API Scopes:{Colors.ENDC}")
            for gs in self.google_scope_results:
                active = [k for k, v in gs['scopes'].items() if 'ACTIVE' in v]
                if active:
                    print(f"  Key {gs['key']}: {', '.join(active)}")

        print(f"\n{Colors.DIM}Network Stats:{Colors.ENDC}")
        for k, v in self.stats.items():
            if v > 0:
                print(f"  {k.replace('_', ' ').title()}: {v}")
        print(f"  URLs Scanned: {len(self.scanned_urls)}")

        # WAF intelligence summary
        waf_blocks = self.stats.get('waf_blocked', 0)
        total_req = self.stats.get('requests_made', 0)
        retries = self.stats.get('retries_used', 0)
        if waf_blocks > 5 and total_req > 0:
            block_rate = waf_blocks / total_req * 100
            wasted = retries + self.stats.get('requests_failed', 0)
            print(f"\n{Colors.DIM}  WAF Intelligence:{Colors.ENDC}")
            print(f"    Block rate: {block_rate:.0f}% ({waf_blocks}/{total_req} requests)")
            if wasted > 0:
                efficiency = max(0, (total_req - wasted) / total_req * 100)
                print(f"    Scan efficiency: {efficiency:.0f}% ({wasted} wasted requests)")
            if self._waf_total_blocks > 50:
                print(f"    {Colors.WARNING}→ Heavy WAF target. Consider: -w 3 -r 3 --ua-rotate{Colors.ENDC}")
            elif self._waf_total_blocks > 20:
                print(f"    {Colors.DIM}→ Moderate WAF. Adaptive stealth handled it.{Colors.ENDC}")

        # v5.1.1: Auto-scope warning — show external domains discovered but not scanned
        ext_domains = getattr(self, '_external_domains', set())
        if ext_domains:
            # Filter out common CDN/tracking/social that aren't interesting
            noise = {'facebook.com', 'twitter.com', 'linkedin.com', 'youtube.com',
                     'google.com', 'googleapis.com', 'gstatic.com', 'cloudflare.com',
                     'fonts.googleapis.com', 'www.w3.org', 'schema.org', 'cdn.jsdelivr.net',
                     'cdnjs.cloudflare.com', 'unpkg.com', 'maxcdn.bootstrapcdn.com'}
            interesting = sorted([d for d in ext_domains
                                  if not any(d.endswith(n) or d == n for n in noise)])[:8]
            if interesting:
                print(f"\n{Colors.WARNING}  ⚠ External domains discovered (not scanned):{Colors.ENDC}")
                for d in interesting:
                    print(f"{Colors.DIM}    → {d}{Colors.ENDC}")
                if self.scope_domains:
                    print(f"{Colors.DIM}    (scope restricted to: {', '.join(self.scope_domains[:5])}){Colors.ENDC}")
                else:
                    print(f"{Colors.DIM}    Tip: use --smart for subdomain recon or add targets manually{Colors.ENDC}")

        # ── v2.9: Source Map Intelligence ──
        if self.source_map_intel:
            print(f"\n{Colors.BOLD}📂 Source Map Intelligence:{Colors.ENDC}")
            for sm in self.source_map_intel:
                print(f"  {sm['url']}")
                print(f"    Files: {sm['total_files']} · Lines: {sm['total_lines']:,}")
                if sm['frameworks']:
                    print(f"    Frameworks: {', '.join(sm['frameworks'])}")
                if sm['npm_packages']:
                    print(f"    npm packages: {len(sm['npm_packages'])} "
                          f"({', '.join(sm['npm_packages'][:8])})")
                if sm['comments']:
                    print(f"    Dev comments: {len(sm['comments'])} "
                          f"(TODO/FIXME/secrets)")

        # ── v2.9: Supply Chain ──
        sc_summary = self.supply_chain.get_summary()
        if sc_summary['total_scripts'] > 0:
            print(f"\n{Colors.BOLD}🔗 Supply Chain Analysis:{Colors.ENDC}")
            print(f"  Total scripts: {sc_summary['total_scripts']} "
                  f"({sc_summary['external_scripts']} external)")
            if sc_summary['cdn_origins']:
                print(f"  CDN origins: {', '.join(sc_summary['cdn_origins'][:8])}")
            print(f"  Libraries detected: {sc_summary['libraries_detected']}")
            if sc_summary['npm_packages_from_sourcemaps']:
                print(f"  npm packages (from source maps): "
                      f"{len(sc_summary['npm_packages_from_sourcemaps'])}")

            if sc_summary['vulnerable_libraries'] > 0:
                print(f"\n{Colors.FAIL}  ⚠ VULNERABLE LIBRARIES: "
                      f"{sc_summary['vulnerable_libraries']}{Colors.ENDC}")
                seen = set()
                for v in sc_summary['vulnerabilities']:
                    key = f"{v['library']}@{v['version']}"
                    if key not in seen:
                        seen.add(key)
                        sc_color = {'CRITICAL': Colors.FAIL, 'HIGH': Colors.WARNING,
                                    'MEDIUM': Colors.OKCYAN}.get(v['severity'], Colors.ENDC)
                        print(f"    {sc_color}[{v['severity']}]{Colors.ENDC} "
                              f"{v['library']}@{v['version']} — {v['detail']}")

            if sc_summary['sri_missing'] > 0:
                print(f"\n{Colors.WARNING}  ⚠ Missing SRI: "
                      f"{sc_summary['sri_missing']} external script(s){Colors.ENDC}")
                for sri in sc_summary['sri_issues'][:5]:
                    print(f"    {sri['host']}: {sri['url'][:80]}")

        # ── v3.0: Security Headers (deduplicated) ──
        if self.headers_auditor.findings:
            # Deduplicate: group by (severity, header, issue)
            seen_headers = {}
            for f in self.headers_auditor.findings:
                key = (f['severity'], f['header'], f['issue'])
                if key not in seen_headers:
                    seen_headers[key] = {'count': 1, 'detail': f['detail']}
                else:
                    seen_headers[key]['count'] += 1
            total_unique = len(seen_headers)
            total_raw = len(self.headers_auditor.findings)
            print(f"\n{Colors.BOLD}🛡 Security Headers: "
                  f"{total_unique} unique issue(s) (from {total_raw} checks){Colors.ENDC}")
            for (sev, header, issue), info in sorted(
                seen_headers.items(), key=lambda x: {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}.get(x[0][0], 3)
            ):
                sc = {'HIGH': Colors.WARNING, 'MEDIUM': Colors.OKCYAN,
                      'LOW': Colors.OKBLUE}.get(sev, Colors.ENDC)
                count_str = f" (x{info['count']})" if info['count'] > 1 else ""
                print(f"  {sc}[{sev}]{Colors.ENDC} {header}: "
                      f"{issue} — {info['detail']}{count_str}")

        # ── v3.0: API Discovery ──
        api_sum = self.api_discovery.get_summary()
        if api_sum['swagger_specs']:
            print(f"\n{Colors.FAIL}⚠ Swagger/OpenAPI Specs: "
                  f"{len(api_sum['swagger_specs'])}{Colors.ENDC}")
            for s in api_sum['swagger_specs']:
                print(f"  {s['url']} — {s['title']} v{s['version']} "
                      f"({s['endpoints']} endpoints)")
        if api_sum['graphql_schemas']:
            print(f"\n{Colors.FAIL}⚠ GraphQL Schemas: "
                  f"{len(api_sum['graphql_schemas'])}{Colors.ENDC}")
            for s in api_sum['graphql_schemas']:
                mut = f" · {len(s['mutations'])} mutations" if s['mutations'] else ''
                print(f"  {s['url']} — {s['types']} types{mut}")
        if api_sum['grpc_endpoints']:
            print(f"\n{Colors.OKCYAN}gRPC/Protobuf: "
                  f"{len(api_sum['grpc_endpoints'])}{Colors.ENDC}")

        # ── v3.0: Cloud Native ──
        if self.cloud_scanner and self.cloud_scanner.findings:
            print(f"\n{Colors.FAIL}☁ Cloud Native Findings: "
                  f"{len(self.cloud_scanner.findings)}{Colors.ENDC}")
            for cf in self.cloud_scanner.findings[:10]:
                sc = {'CRITICAL': Colors.FAIL, 'HIGH': Colors.WARNING}.get(
                    cf['severity'], Colors.OKCYAN)
                print(f"  {sc}[{cf['severity']}]{Colors.ENDC} {cf['type']} "
                      f"in {cf['source'][:60]}")

        # ── v3.0: FP filtering stats ──
        if self.fp_removed:
            print(f"\n{Colors.DIM}False positives filtered: "
                  f"{len(self.fp_removed)}{Colors.ENDC}")

        # ── v5.0: CVE Analysis ──
        self.cve_lookup.print_results()

        # ── v5.0: Rate Abuse Analysis ──
        if self.rate_tester:
            self.rate_tester.print_results()

    # ═════════════════════════════════════════════════════════════
    #  Output — JSON
    # ═════════════════════════════════════════════════════════════

    def export_json(self, filename):
        output = {
            'tool': f'Arcanis v{__version__}',
            'author': __author__,
            'scan_time': datetime.now(timezone.utc).isoformat(),
            'urls_scanned': len(self.scanned_urls),
            'total_findings': len(self.found_secrets),
            'network_stats': self.stats,
            'findings': self.found_secrets,
            'api_endpoints': self.discovered_endpoints,
            'internal_urls': self.discovered_internal_urls,
            'env_files': self.env_files_found,
            'graphql_endpoints': self.graphql_endpoints,
            'google_scope_results': self.google_scope_results,
            'source_map_intel': self.source_map_intel,
            'supply_chain': self.supply_chain.get_summary(),
            'security_headers': self.headers_auditor.findings,
            'api_discovery': self.api_discovery.get_summary(),
            'cloud_findings': self.cloud_scanner.findings if self.cloud_scanner else [],
            'false_positives_removed': len(self.fp_removed),
            'attack_chains': self.attack_chains,
            'ssrf_vectors': self.ssrf_prober.vectors,
            'idor_candidates': self.idor_fuzzer.idor_candidates,
            'internal_routes': self.internal_api_enum.routes,
            'subtko_findings': self.subtko.findings,
            'wayback_urls': self.wayback.archived_urls,
            'privilege_escalation': self.priv_esc.results,
            'cve_analysis': self.cve_lookup.get_summary(),
            'rate_abuse': self.rate_tester.get_summary() if self.rate_tester else {},
            'accuracy_engine': self.accuracy_engine.get_stats(),
        }
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2, default=str)
        print(f"{Colors.OKGREEN}[+] JSON: {filename}{Colors.ENDC}")

    # ═════════════════════════════════════════════════════════════
    #  Output — HTML
    # ═════════════════════════════════════════════════════════════

    def export_html(self, filename):
        sev_c = {'CRITICAL': '#dc3545', 'HIGH': '#fd7e14', 'MEDIUM': '#0dcaf0', 'LOW': '#0d6efd', 'INFO': '#adb5bd'}
        conf_c = {'HIGH': '#198754', 'MEDIUM': '#ffc107', 'LOW': '#6c757d'}

        rows = []
        # v5.1.1: Deduplicate findings by value in HTML report
        seen_values = {}  # value -> index in found_secrets (first occurrence)
        dedup_sources = {}  # value -> list of additional sources
        for i, s in enumerate(self.found_secrets):
            val_key = f"{s.get('type','')}:{s.get('value','')}"
            if val_key in seen_values:
                if val_key not in dedup_sources:
                    dedup_sources[val_key] = []
                dedup_sources[val_key].append(s.get('source', ''))
                continue
            seen_values[val_key] = i

        row_num = 0
        for i, s in enumerate(self.found_secrets, 0):
            val_key = f"{s.get('type','')}:{s.get('value','')}"
            if val_key in seen_values and seen_values[val_key] != i:
                continue  # Skip duplicates, already handled by first occurrence
            row_num += 1
            val = html_lib.escape(s['value'])
            if len(val) > 80:
                val = val[:77] + "..."
            src = html_lib.escape(s['source'])
            sev = s['severity']
            conf = s.get('confidence', '?')
            conf_score = s.get('confidence_score', '?')
            risk_score = s.get('risk_score', '?')
            ent = s.get('entropy', 0)
            v_fmt = '+' if s.get('validated') else ''
            v_live = ''
            if s.get('verified_live') is True:
                v_live = '<br><span style="color:#dc3545;font-weight:bold">! LIVE</span>'
            elif s.get('verified_live') is False:
                v_live = '<br><span style="color:#6c757d">x Dead</span>'
            extra = ''
            # v2 Factor breakdown
            factors = s.get('score_factors', {})
            if factors:
                extra += (f"<br><small style='color:#555'>FMT:{factors.get('format_validity','-')} "
                          f"CTX:{factors.get('context_strength','-')} "
                          f"OWN:{factors.get('domain_ownership','-')} "
                          f"FILE:{factors.get('file_risk_weight','-')} "
                          f"ENT:{factors.get('entropy_range_fit','-')} "
                          f"LIVE:{factors.get('live_validation','-')}</small>")
            if s.get('severity_downgraded'):
                extra += '<br><small style="color:#6c757d">v severity downgraded by confidence</small>'
            if s.get('jwt_decoded'):
                a = s['jwt_decoded'].get('analysis', {})
                grade = a.get('risk_grade', '?')
                score = a.get('risk_score', 0)
                gc = {'CRITICAL':'#dc3545','HIGH':'#fd7e14','MEDIUM':'#0dcaf0','LOW':'#198754'}.get(grade,'#6c757d')
                extra += (f"<br><small>JWT: {a.get('algorithm','?')} - "
                          f"<span style='color:{gc}'>{grade} ({score}/100)</span></small>")
                vulns = a.get('vulnerabilities', [])
                if vulns:
                    extra += f"<br><small style='color:#dc3545'>! {vulns[0][:60]}</small>"
                if a.get('permissions'):
                    extra += f"<br><small>perms: {', '.join(a['permissions'][:4])}</small>"
            if s.get('keyword_hint'):
                extra += f"<br><small>hint: {s['keyword_hint']}</small>"
            if s.get('accuracy_notes'):
                for note in s['accuracy_notes'][:3]:
                    extra += f"<br><small style='color:#6c757d'>[{html_lib.escape(note)}]</small>"
            if s.get('multi_file'):
                extra += f"<br><small>Multi-file: {len(s.get('all_sources', []))} sources</small>"
            # v5.1.1: Exploit suggestions in HTML
            suggestions = self._get_exploit_suggestions(s)
            if suggestions:
                prob = suggestions.get('probability', 0)
                pc = '#dc3545' if prob >= 70 else ('#fd7e14' if prob >= 40 else '#0dcaf0')
                extra += f"<br><small style='color:{pc}'>⚡ Exploit probability: {prob}%</small>"
                if suggestions.get('next_steps'):
                    extra += "<br><small style='color:#8b949e'>→ " + \
                             "</small><br><small style='color:#8b949e'>→ ".join(
                                 html_lib.escape(step) for step in suggestions['next_steps'][:3]) + "</small>"
            # v5.1.1: Show additional sources for deduped findings
            additional_sources = dedup_sources.get(val_key, [])
            if additional_sources:
                extra += f"<br><small style='color:#0dcaf0'>Also found in {len(additional_sources)} other source(s):</small>"
                for asrc in additional_sources[:3]:
                    extra += f"<br><small style='color:#6c757d'>  + {html_lib.escape(asrc[:60])}</small>"
                if len(additional_sources) > 3:
                    extra += f"<br><small style='color:#6c757d'>  + {len(additional_sources)-3} more...</small>"
            rows.append(f"""<tr>
                <td>{row_num}</td>
                <td><span class="badge" style="background:{sev_c.get(sev,'#6c757d')}">{sev}</span></td>
                <td><span class="badge" style="background:{conf_c.get(conf,'#6c757d')}">{conf_score}</span><br><small>risk:{risk_score}</small></td>
                <td>{html_lib.escape(s['type'])}{extra}</td>
                <td class="mono">{val}</td>
                <td>{ent:.1f}</td>
                <td class="src">{src}</td>
                <td style="text-align:center">{v_fmt}{v_live}</td>
            </tr>""")

        by_sev = defaultdict(int)
        for s in self.found_secrets:
            by_sev[s['severity']] += 1
        badges = ' '.join(
            f'<span class="badge" style="background:{sev_c.get(k,"#6c757d")}">{k}: {v}</span>'
            for k in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] if (v := by_sev.get(k))
        )
        live_count = sum(1 for s in self.found_secrets if s.get('verified_live') is True)
        if live_count:
            badges += f' <span class="badge" style="background:#dc3545">⚡ LIVE: {live_count}</span>'

        disc_html = ''
        if self.env_files_found:
            disc_html += '<h2 style="color:#dc3545">⚠ Exposed .env Files</h2><ul>'
            for ef in self.env_files_found:
                disc_html += f'<li><code>{html_lib.escape(ef["url"])}</code> — {ef["lines"]} vars</li>'
            disc_html += '</ul>'
        if self.graphql_endpoints:
            disc_html += '<h2 style="color:#dc3545">⚠ GraphQL Introspection</h2><ul>'
            for gql in self.graphql_endpoints:
                disc_html += f'<li><code>{html_lib.escape(gql["url"])}</code></li>'
            disc_html += '</ul>'
        if self.google_scope_results:
            disc_html += '<h2 style="color:#dc3545">⚠ Google API Key Scopes</h2>'
            for gs in self.google_scope_results:
                disc_html += f'<p>Key: <code>{html_lib.escape(gs["key"])}</code></p><ul>'
                for api, status in gs['scopes'].items():
                    icon = '🔓' if 'ACTIVE' in status else '🔒'
                    disc_html += f'<li>{icon} {html_lib.escape(api)}: {html_lib.escape(status)}</li>'
                disc_html += '</ul>'
        if self.discovered_internal_urls:
            disc_html += f'<h2>Internal URLs ({len(self.discovered_internal_urls)})</h2><ul>'
            for iu in self.discovered_internal_urls[:15]:
                disc_html += f'<li>[{html_lib.escape(iu["type"])}] <code>{html_lib.escape(iu["value"])}</code></li>'
            disc_html += '</ul>'
        if self.discovered_endpoints:
            disc_html += f'<h2>API Endpoints ({len(self.discovered_endpoints)})</h2><ul>'
            for ep in self.discovered_endpoints[:15]:
                disc_html += f'<li><code>{html_lib.escape(ep["endpoint"])}</code></li>'
            disc_html += '</ul>'

        # ── v2.9: Source Map Intelligence ──
        if self.source_map_intel:
            disc_html += '<h2>📂 Source Map Intelligence</h2>'
            for sm in self.source_map_intel:
                disc_html += (f'<p><code>{html_lib.escape(sm["url"])}</code> — '
                              f'{sm["total_files"]} files · {sm["total_lines"]:,} lines</p>')
                if sm['frameworks']:
                    disc_html += f'<p>Frameworks: <strong>{", ".join(sm["frameworks"])}</strong></p>'
                if sm['npm_packages']:
                    disc_html += f'<p>npm: {", ".join(sm["npm_packages"][:15])}</p>'

        # ── v2.9: Supply Chain ──
        sc_summary = self.supply_chain.get_summary()
        if sc_summary['total_scripts'] > 0:
            disc_html += f'<h2>🔗 Supply Chain ({sc_summary["total_scripts"]} scripts)</h2>'
            # Script inventory table
            ext_count = sc_summary['external_scripts']
            int_count = sc_summary['total_scripts'] - ext_count
            libs_count = sc_summary['libraries_detected']
            disc_html += (f'<p>Total: {sc_summary["total_scripts"]} scripts '
                          f'({ext_count} external, {int_count} internal) · '
                          f'Libraries detected: {libs_count}</p>')
            if sc_summary['inventory']:
                disc_html += ('<table style="width:100%;border-collapse:collapse;margin:8px 0">'
                              '<tr style="background:#1a1a2e;color:#8b949e;font-size:12px">'
                              '<th style="padding:6px 8px;text-align:left">Script URL</th>'
                              '<th style="padding:6px 8px;text-align:center">Type</th>'
                              '<th style="padding:6px 8px;text-align:center">Library</th>'
                              '<th style="padding:6px 8px;text-align:center">SRI</th></tr>')
                for script in sc_summary['inventory']:
                    s_url = html_lib.escape(script['url'])
                    # Truncate long URLs for display
                    s_url_display = html_lib.escape(script['url'][:80] + ('...' if len(script['url']) > 80 else ''))
                    s_type = '<span style="color:#f59e0b">external</span>' if script['is_external'] else '<span style="color:#64748b">internal</span>'
                    s_lib = html_lib.escape(f"{script['library']}@{script['version']}") if script.get('library') else '<span style="color:#334155">—</span>'
                    s_sri = '<span style="color:#10b981">✓</span>' if script.get('has_sri') else ('<span style="color:#ef4444">✗</span>' if script['is_external'] else '<span style="color:#334155">—</span>')
                    disc_html += (f'<tr style="border-bottom:1px solid #1e293b;font-size:11px">'
                                  f'<td style="padding:4px 8px"><code style="font-size:11px">{s_url_display}</code></td>'
                                  f'<td style="padding:4px 8px;text-align:center">{s_type}</td>'
                                  f'<td style="padding:4px 8px;text-align:center">{s_lib}</td>'
                                  f'<td style="padding:4px 8px;text-align:center">{s_sri}</td></tr>')
                disc_html += '</table>'
            if sc_summary['vulnerable_libraries'] > 0:
                disc_html += '<h3 style="color:#dc3545">⚠ Vulnerable Libraries</h3><ul>'
                seen = set()
                for v in sc_summary['vulnerabilities']:
                    key = f"{v['library']}@{v['version']}"
                    if key not in seen:
                        seen.add(key)
                        vc = {'CRITICAL':'#dc3545','HIGH':'#fd7e14','MEDIUM':'#0dcaf0'}.get(v['severity'],'#6c757d')
                        disc_html += (f'<li><span class="badge" style="background:{vc}">'
                                      f'{v["severity"]}</span> '
                                      f'<strong>{html_lib.escape(v["library"])}@{html_lib.escape(v["version"])}'
                                      f'</strong> — {html_lib.escape(v["detail"])}</li>')
                disc_html += '</ul>'
            if sc_summary['sri_missing'] > 0:
                disc_html += (f'<p style="color:#fd7e14">⚠ {sc_summary["sri_missing"]} '
                              f'external scripts missing SRI integrity attribute</p>')
            if sc_summary['cdn_origins']:
                disc_html += f'<p>CDN origins: {", ".join(html_lib.escape(o) for o in sc_summary["cdn_origins"][:10])}</p>'

        # v3.0: Security Headers (deduplicated)
        if self.headers_auditor.findings:
            seen_hdr = {}
            for f in self.headers_auditor.findings:
                key = (f['severity'], f['header'], f['issue'])
                if key not in seen_hdr:
                    seen_hdr[key] = {'count': 1, 'detail': f['detail']}
                else:
                    seen_hdr[key]['count'] += 1
            disc_html += f'<h2>🛡 Security Headers ({len(seen_hdr)} unique issues)</h2><ul>'
            for (sev, header, issue), info in sorted(
                seen_hdr.items(), key=lambda x: {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}.get(x[0][0], 3)
            ):
                hc = {'HIGH':'#fd7e14','MEDIUM':'#0dcaf0','LOW':'#0d6efd'}.get(sev,'#6c757d')
                count_str = f" (x{info['count']})" if info['count'] > 1 else ""
                disc_html += (f'<li><span class="badge" style="background:{hc}">{sev}</span> '
                              f'<strong>{html_lib.escape(header)}</strong>: '
                              f'{html_lib.escape(issue)} — {html_lib.escape(info["detail"])}{count_str}</li>')
            disc_html += '</ul>'

        # v3.0: API Discovery
        api_sum = self.api_discovery.get_summary()
        if api_sum['swagger_specs']:
            disc_html += '<h2 style="color:#dc3545">⚠ Swagger/OpenAPI Specs</h2><ul>'
            for s in api_sum['swagger_specs']:
                disc_html += (f'<li><code>{html_lib.escape(s["url"])}</code> — '
                              f'{html_lib.escape(s["title"])} ({s["endpoints"]} endpoints)</li>')
            disc_html += '</ul>'
        if api_sum['graphql_schemas']:
            disc_html += '<h2 style="color:#dc3545">⚠ GraphQL Schemas</h2><ul>'
            for s in api_sum['graphql_schemas']:
                mut = f' · {len(s["mutations"])} mutations' if s['mutations'] else ''
                disc_html += f'<li><code>{html_lib.escape(s["url"])}</code> — {s["types"]} types{mut}</li>'
            disc_html += '</ul>'

        # v3.0: Cloud Native
        if self.cloud_scanner and self.cloud_scanner.findings:
            disc_html += f'<h2 style="color:#dc3545">☁ Cloud Native ({len(self.cloud_scanner.findings)})</h2><ul>'
            for cf in self.cloud_scanner.findings[:10]:
                cc = {'CRITICAL':'#dc3545','HIGH':'#fd7e14'}.get(cf['severity'],'#0dcaf0')
                disc_html += (f'<li><span class="badge" style="background:{cc}">{cf["severity"]}</span> '
                              f'{html_lib.escape(cf["type"])} in <code>{html_lib.escape(cf["source"][:60])}</code></li>')
            disc_html += '</ul>'

        now = datetime.now(timezone.utc)
        html_out = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Secret Scanner v{__version__} Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0d1117;color:#c9d1d9;padding:24px}}
h1{{color:#58a6ff;margin-bottom:4px;font-size:1.6rem}}
h2{{color:#58a6ff;margin:16px 0 8px;font-size:1.1rem}}
.author{{color:#f0883e;font-size:0.85rem;margin-bottom:4px}}
.subtitle{{color:#8b949e;margin-bottom:20px;font-size:0.9rem}}
.badge{{display:inline-block;padding:3px 10px;border-radius:12px;color:#fff;font-size:0.75rem;font-weight:600;margin-right:6px}}
table{{width:100%;border-collapse:collapse;font-size:0.85rem}}
th{{background:#161b22;color:#58a6ff;padding:10px 8px;text-align:left;border-bottom:2px solid #30363d;position:sticky;top:0}}
td{{padding:8px;border-bottom:1px solid #21262d;vertical-align:top}}
tr:hover td{{background:#161b22}}
.mono{{font-family:'SF Mono','Fira Code',monospace;font-size:0.8rem;word-break:break-all;color:#f0883e}}
.src{{font-size:0.78rem;color:#8b949e;word-break:break-all}}
ul{{margin:8px 0 16px 24px;font-size:0.85rem}}
li{{margin-bottom:4px}}
code{{background:#161b22;padding:2px 6px;border-radius:4px;font-size:0.82rem}}
.net{{background:#161b22;border-radius:8px;padding:16px;margin-bottom:20px;font-size:0.82rem}}
.net span{{margin-right:18px}}
.footer{{margin-top:24px;color:#484f58;font-size:0.75rem;text-align:center}}
</style></head><body>
<h1>🔍 Arcanis v{__version__} — Report</h1>
<div class="author">by {__author__}</div>
<div class="subtitle">Generated: {now.strftime('%Y-%m-%d %H:%M:%S UTC')} · URLs: {len(self.scanned_urls)} · Findings: {len(self.found_secrets)}</div>
<div class="net"><strong>Network:</strong>
<span>Requests: {self.stats['requests_made']}</span>
<span>Failed: {self.stats['requests_failed']}</span>
<span>WAF blocked: {self.stats['waf_blocked']}</span>
<span>Source maps: {self.stats['source_maps_found']}</span>
<span>Verified live: {self.stats['secrets_verified_live']}</span>
<span>Supply chain vulns: {self.stats['supply_chain_vulns']}</span>
<span>SRI missing: {self.stats['sri_missing']}</span></div>
<div style="margin-bottom:16px">{badges}</div>
{disc_html}
<table><thead><tr><th>#</th><th>Sev</th><th>Conf</th><th>Type</th><th>Value</th><th>Entropy</th><th>Source</th><th>Status</th></tr></thead>
<tbody>{''.join(rows) if rows else '<tr><td colspan="8" style="text-align:center;padding:20px;color:#64748b">No high-confidence secrets detected — target appears hardened</td></tr>'}</tbody></table>
<div class="footer">Arcanis v{__version__} by {__author__} — For Authorized Bug Bounty Testing Only</div>
</body></html>"""

        with open(filename, 'w') as f:
            f.write(html_out)
        print(f"{Colors.OKGREEN}[+] HTML: {filename}{Colors.ENDC}")


# ═══════════════════════════════════════════════════════════════════
#  Banner & Main
# ═══════════════════════════════════════════════════════════════════

def print_banner():
    v = f"v{__version__}"
    a = __author__
    import re

    # 256-color ANSI for gradient effect (cyan → blue → purple)
    c1 = '\033[38;5;87m'    # bright cyan
    c2 = '\033[38;5;75m'    # sky blue  
    c3 = '\033[38;5;111m'   # light blue
    c4 = '\033[38;5;141m'   # lavender
    c5 = '\033[38;5;135m'   # purple
    cf = '\033[38;5;240m'   # frame gray
    cw = '\033[38;5;255m'   # bright white
    cy = '\033[38;5;220m'   # gold
    cd = '\033[38;5;245m'   # dim text
    ch = '\033[38;5;60m'    # hex gray
    cr = '\033[38;5;203m'   # warning coral
    B = Colors.BOLD
    R = Colors.ENDC
    W = 72

    def vl(s):
        return len(re.sub(r'\033\[[0-9;]*m', '', s))

    def fr(content=""):
        """Frame a line: ║ content padded to W ║"""
        pad = ' ' * max(0, W - vl(content))
        return f"  {cf}║{R}{content}{pad}{cf}║{R}"

    # ARCANIS in hex = 41 52 43 41 4E 49 53
    hex_sig = f"{ch}41 52 43 41 4E 49 53{R}"

    # Logo lines (ANSI Regular font, gradient colored)
    L = [
        f"{c1}{B} █████  ██████   ██████  █████  ███    ██ ██ ███████ {R}",
        f"{c2}{B}██   ██ ██   ██ ██      ██   ██ ████   ██ ██ ██      {R}",
        f"{c3}{B}███████ ██████  ██      ███████ ██ ██  ██ ██ ███████ {R}",
        f"{c4}{B}██   ██ ██   ██ ██      ██   ██ ██  ██ ██ ██      ██{R}",
        f"{c5}{B}██   ██ ██   ██  ██████ ██   ██ ██   ████ ██ ███████{R}",
    ]

    top = f"  {cf}╔{'═' * W}╗{R}"
    bot = f"  {cf}╚{'═' * W}╝{R}"
    sep = f"  {cf}║ {ch}{'─' * (W - 2)}{R} {cf}║{R}"

    print()
    print(top)
    print(fr())
    for line in L:
        print(fr(f"       {line}"))
    print(fr())
    print(sep)
    print(fr(f"   {ch}0x{R}{hex_sig}"))
    print(sep)
    print(fr())
    ce = '\033[38;5;79m'  # community teal
    print(fr(f"   {ce}◆{R} {cw}{B}{v}{R}                  {ce}◆{R} {ce}COMMUNITY EDITION{R}"))
    print(fr(f"   {ce}◆{R} {cw}{a}{R}        {ce}◆{R} {cd}13 modules · scoring{R}"))
    print(fr())
    print(fr(f"   {c1}▸{R} {cw}Find secrets. Score them 0-100. Free forever.{R}"))
    print(fr(f"   {c1}▸{R} {cd}Upgrade to Pro for live verification + exploit paths{R}"))
    print(fr())
    print(fr(f"   {cr}⚠{R}  {cd}For authorized security testing only.{R}"))
    print(fr())
    print(bot)
    print()


def main():
    parser = argparse.ArgumentParser(
        description=f'Arcanis v{__version__} — High-Signal Secret & API Exposure Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Author: {__author__}

Examples:
  %(prog)s https://example.com
  %(prog)s https://example.com --verify --probe-env --probe-graphql --probe-swagger
  %(prog)s https://example.com --depth 2 --workers 10 --ua-rotate --verify --scan-cloud
  %(prog)s https://example.com --scope scope.txt --rate-limit 10 --notify https://hooks.slack.com/...
  %(prog)s https://example.com --rules custom.yaml --sarif results.sarif --baseline prev.json
  %(prog)s https://example.com --verify --cve-lookup --rate-abuse --report html
  %(prog)s -L targets.txt --verify --depth 2 -o results.json --report both
  %(prog)s -L - --verify < targets.txt
  %(prog)s -f targets.txt -o results.json --html report.html --sarif ci.sarif
  %(prog)s --generate-github-action
        """
    )
    parser.add_argument('urls', nargs='*', help='URLs to scan')
    parser.add_argument('--key', help='License key (ARC-XXXX-XXXX-...)')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-o', '--output', help='JSON output file')
    parser.add_argument('--html', help='HTML report file')
    parser.add_argument('--sarif', help='SARIF output file (for CI/CD)')
    parser.add_argument('--no-validate', action='store_true')
    parser.add_argument('-f', '--file', action='store_true', help='Read URLs from file')
    parser.add_argument('--depth', type=int, default=0, help='Crawl depth')
    parser.add_argument('--workers', type=int, default=5, help='Concurrent workers')
    parser.add_argument('--retries', type=int, default=3, help='Max retries')
    parser.add_argument('--ua-rotate', action='store_true')
    parser.add_argument('--probe-env', action='store_true', help='Probe for .env files')
    parser.add_argument('--probe-graphql', action='store_true', help='Probe GraphQL endpoints')
    parser.add_argument('--probe-swagger', action='store_true', help='Probe Swagger/OpenAPI specs')
    parser.add_argument('--verify', action='store_true', help='Active API verification (15 verifiers)')
    parser.add_argument('--rate-limit', type=float, default=0, help='Requests per second (0=unlimited)')
    parser.add_argument('--scope', help='Scope file (one domain per line)')
    parser.add_argument('--rules', help='Custom rules file (YAML or JSON)')
    parser.add_argument('--no-progress', action='store_true')
    parser.add_argument('--scan-cloud', action='store_true', help='Cloud native scanning (AWS/K8s/GCP)')
    parser.add_argument('--notify', help='Webhook URL (Slack/Discord/Teams)')
    parser.add_argument('--baseline', help='Baseline JSON for diff detection')
    # v4.0: Offensive Recon
    parser.add_argument('--wayback', action='store_true', help='Mine Wayback Machine for historical JS/HTML')
    parser.add_argument('--subtko', action='store_true', help='Check for dangling DNS / unclaimed subdomains')
    parser.add_argument('--ssrf-probe', action='store_true', help='Check for exposed internal endpoints')
    parser.add_argument('--fuzz-idor', action='store_true', help='Check for access control misconfigurations')
    parser.add_argument('--attack-chains', action='store_true', help='Map risk impact chains with exploitability scoring')
    # v5.0: New features
    parser.add_argument('-L', '--target-list', help='File with target URLs (one per line), use - for stdin')
    parser.add_argument('--report', choices=['html', 'pdf', 'both'], help='Generate visual report (html/pdf/both)')
    parser.add_argument('--rate-abuse', action='store_true', help='Check rate limit protection on verified keys (safe mode)')
    parser.add_argument('--cve-lookup', action='store_true', help='CVE lookup for source map npm packages')
    parser.add_argument('--resume', action='store_true', help='Resume interrupted batch scan')
    # Phase 1: Recon & Infrastructure
    parser.add_argument('--recon', action='store_true', help='Run subdomain recon (CT logs + DNS + risk scoring)')
    parser.add_argument('--recon-only', action='store_true', help='Only run recon, do not scan')
    parser.add_argument('--recon-top', type=int, default=0, help='Scan only top N high-risk subdomains')
    parser.add_argument('--db', action='store_true', help='Enable SQLite persistence (incremental scanning)')
    parser.add_argument('--db-stats', action='store_true', help='Show database statistics and exit')
    parser.add_argument('--db-history', action='store_true', help='Show scan history and exit')
    parser.add_argument('--incremental', action='store_true', help='Skip unchanged URLs (requires --db)')
    parser.add_argument('--diff', action='store_true', help='Show delta vs previous scan (requires --db)')
    # v6.0: Exposure scanning
    parser.add_argument('--cors-check', action='store_true', help='Test for CORS misconfigurations')
    parser.add_argument('--open-redirect', action='store_true', help='Test for open redirect vulnerabilities')
    parser.add_argument('--dom-xss', action='store_true', help='Map DOM XSS sources and sinks in JS')
    parser.add_argument('--dep-confusion', action='store_true', help='Check npm packages for dependency confusion')
    parser.add_argument('--jwt-exploit', action='store_true', help='Deep JWT exploitation testing')
    parser.add_argument('--cloud-perms', action='store_true', help='Test cloud resource permissions (S3/GCS/Firebase)')
    parser.add_argument('--full', action='store_true', help='Enable ALL scanning modules (noisy — prefer --smart)')
    parser.add_argument('--smart', action='store_true',
                        help='Intelligence-driven scanning: auto-selects modules per target based on asset type')
    # CI/CD generators
    parser.add_argument('--generate-github-action', action='store_true',
                        help='Generate GitHub Actions workflow')
    parser.add_argument('--generate-gitlab-ci', action='store_true',
                        help='Generate GitLab CI pipeline')
    parser.add_argument('--generate-pre-commit', action='store_true',
                        help='Generate pre-commit hook script')

    args = parser.parse_args()

    # ── --smart flag: intelligence-driven (NOT --full) ──
    if args.smart:
        args.recon = True
        args.db = True
        # Community: --smart does NOT auto-enable --verify
        # (verify is a Pro feature, gated below)
        # Don't enable any exposure modules globally —
        # SmartRouter will enable them per-target

    # ── --full flag: enable everything (noisy fallback) ──
    if args.full:
        # Community: verify/attack-chains/cve/wayback/rate-abuse gated below
        args.probe_env = True
        args.probe_graphql = True
        args.probe_swagger = True
        args.scan_cloud = True
        args.subtko = True
        args.ssrf_probe = True
        args.fuzz_idor = True
        args.recon = True
        args.db = True
        args.cors_check = True
        args.open_redirect = True
        args.dom_xss = True
        args.dep_confusion = True
        args.jwt_exploit = True
        args.cloud_perms = True

    # ── Database utility commands (no scan needed) ──
    if args.db_stats:
        try:
            db = ArcanisDB()
            stats = db.get_stats()
            print(f"\n  Arcanis Database Statistics")
            print(f"  {'=' * 35}")
            print(f"  Total scans:       {stats['total_scans']}")
            print(f"  Total subdomains:  {stats['total_subdomains']}")
            print(f"  Alive subdomains:  {stats['alive_subdomains']}")
            print(f"  Unique domains:    {stats['unique_domains']}")
            print(f"  Total findings:    {stats['total_findings']}")
            print(f"  Active findings:   {stats['active_findings']}")
            print(f"  DB location:       {db.db_path}")
            db.close()
        except Exception as e:
            print(f"  Error: {e}")
        return

    if args.db_history:
        try:
            db = ArcanisDB()
            history = db.get_scan_history(limit=20)
            print(f"\n  Recent Scans (last 20)")
            print(f"  {'=' * 60}")
            for scan in history:
                dur = f"{scan['duration_seconds']:.1f}s" if scan['duration_seconds'] else "?"
                print(f"  #{scan['id']:4d}  {scan['target'][:40]:40s}  "
                      f"findings:{scan['findings_count']:3d}  {dur}")
            db.close()
        except Exception as e:
            print(f"  Error: {e}")
        return

    # ── CI/CD generators (no scan needed) ──
    if args.generate_github_action:
        CICDIntegration.generate_github_action()
        return
    if args.generate_gitlab_ci:
        CICDIntegration.generate_gitlab_ci()
        return
    if args.generate_pre_commit:
        CICDIntegration.generate_pre_commit_hook()
        return

    if not args.urls and not getattr(args, 'key', None) and not args.target_list:
        parser.print_help()
        return

    print_banner()

    # ── Community Edition: no key needed ──
    if getattr(args, 'key', None):
        print(f"\n  {Colors.OKCYAN}This is the Community Edition — no license key needed!{Colors.ENDC}")
        print(f"  {Colors.DIM}If you purchased a Pro key, download the Pro edition at arcanis.sh{Colors.ENDC}\n")
        return

    # License gate — must pass to scan
    license_info = _license_gate(args)

    # ══ Community Edition: Feature Gating ══
    _PRO_MSG = f"\n  {Colors.WARNING}⚡ PRO FEATURE{Colors.ENDC} — Upgrade at {Colors.OKCYAN}https://arcanis.sh{Colors.ENDC} to unlock this.\n"
    _gated = []

    if getattr(args, 'verify', False):
        args.verify = False
        _gated.append('--verify (live API verification)')

    if getattr(args, 'attack_chains', False):
        args.attack_chains = False
        _gated.append('--attack-chains (exploit path mapping)')

    if getattr(args, 'cve_lookup', False):
        args.cve_lookup = False
        _gated.append('--cve-lookup (CVE cross-reference)')

    if getattr(args, 'rate_abuse', False):
        args.rate_abuse = False
        _gated.append('--rate-abuse (rate limit testing)')

    if getattr(args, 'wayback', False):
        args.wayback = False
        _gated.append('--wayback (Wayback Machine mining)')

    if getattr(args, 'sarif', None):
        args.sarif = None
        _gated.append('--sarif (CI/CD SARIF output)')

    if getattr(args, 'baseline', None):
        args.baseline = None
        _gated.append('--baseline (CI/CD diff)')

    if getattr(args, 'report', None) in ('pdf', 'both'):
        if args.report == 'both':
            args.report = 'html'  # Allow HTML, block PDF
            _gated.append('--report pdf (PDF report)')
        else:
            args.report = None
            _gated.append('--report pdf (PDF report)')

    if getattr(args, 'target_list', None):
        args.target_list = None
        _gated.append('-L / --target-list (batch scanning)')
        print(f"  {Colors.WARNING}⚡ Batch scanning is a Pro feature.{Colors.ENDC}")
        print(f"  {Colors.DIM}Pass up to 3 targets as arguments instead:{Colors.ENDC}")
        print(f"  {Colors.DIM}  arcanis https://a.com https://b.com https://c.com --smart{Colors.ENDC}\n")

    if _gated:
        print(f"  {Colors.WARNING}⚡ Pro features disabled in Community Edition:{Colors.ENDC}")
        for g in _gated:
            print(f"     {Colors.DIM}→ {g}{Colors.ENDC}")
        print(f"  {Colors.DIM}Upgrade at https://arcanis.sh to unlock all features.{Colors.ENDC}\n")

    # ── Strict target validation ──
    def validate_target(url: str) -> Optional[str]:
        """Validate and clean a target URL. Returns cleaned URL or None."""
        url = url.strip()
        if not url or url.startswith('#'):
            return None
        # Reject empty strings, whitespace, control chars
        if not url or len(url) < 4:
            return None
        if any(c in url for c in ['\n', '\r', '\t', ' ']):
            return None
        # Auto-prepend https:// if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        # Validate URL structure
        try:
            parsed = urlparse(url)
            if not parsed.netloc or '.' not in parsed.netloc:
                if args.verbose:
                    print(f"{Colors.WARNING}  [!] Rejected invalid target: {url}{Colors.ENDC}")
                return None
            # Reject localhost/internal by default (unless --scope allows it)
            if parsed.netloc in ('localhost', '127.0.0.1', '0.0.0.0'):
                if args.verbose:
                    print(f"{Colors.WARNING}  [!] Rejected localhost target: {url}{Colors.ENDC}")
                return None
        except Exception:
            return None
        return url

    # Load scope domains
    scope_domains = []
    if args.scope:
        try:
            with open(args.scope) as f:
                scope_domains = [l.strip().lower() for l in f if l.strip() and not l.startswith('#')]
            print(f"{Colors.OKGREEN}[+] Scope: {len(scope_domains)} domains{Colors.ENDC}")
        except FileNotFoundError:
            print(f"{Colors.FAIL}[!] Scope file not found: {args.scope}{Colors.ENDC}")
            return

    # Load custom rules
    custom_rules = None
    if args.rules:
        custom_rules = load_custom_rules(args.rules)

    # Initialize database if requested
    db = ArcanisDB() if args.db else None

    scanner = SecretScanner(
        verbose=args.verbose, max_workers=args.workers,
        crawl_depth=args.depth, no_validate=args.no_validate,
        max_retries=args.retries, ua_rotate=args.ua_rotate,
        probe_env=args.probe_env, probe_graphql=args.probe_graphql,
        show_progress=not args.no_progress, verify_live=args.verify,
        rate_limit=args.rate_limit, scope_domains=scope_domains,
        custom_rules=custom_rules, notify_url=args.notify,
        baseline_path=args.baseline, probe_swagger=args.probe_swagger,
        scan_cloud=args.scan_cloud,
        wayback=args.wayback, subtko=args.subtko,
        ssrf_probe=args.ssrf_probe, fuzz_idor=args.fuzz_idor,
        cors_check=args.cors_check, open_redirect=args.open_redirect,
        dom_xss=args.dom_xss, dep_confusion=args.dep_confusion,
        jwt_exploit=args.jwt_exploit, cloud_perms=args.cloud_perms,
    )

    urls_to_scan = []
    if args.target_list:
        # v5.0: Multi-target batch scanning
        raw_targets = BatchScanner.load_targets(args.target_list)
        urls_to_scan = [u for u in (validate_target(t) for t in raw_targets) if u]
        if not urls_to_scan:
            print(f"{Colors.FAIL}[!] No valid targets loaded from {args.target_list}{Colors.ENDC}")
            return
        rejected = len(raw_targets) - len(urls_to_scan)
        print(f"[*] Batch mode: {len(urls_to_scan)} valid targets loaded", end='')
        if rejected > 0:
            print(f" ({rejected} rejected)")
        else:
            print()
        print()
    elif args.file or (len(args.urls) == 1 and args.urls[0].endswith('.txt')):
        try:
            with open(args.urls[0]) as f:
                raw_lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]
            urls_to_scan = [u for u in (validate_target(t) for t in raw_lines) if u]
            print(f"[*] Loaded {len(urls_to_scan)} valid URLs\n")
        except FileNotFoundError:
            print(f"{Colors.FAIL}[!] File not found{Colors.ENDC}")
            return
    else:
        # CLI args — validate each target
        for raw_url in args.urls:
            cleaned = validate_target(raw_url)
            if cleaned:
                urls_to_scan.append(cleaned)
            elif args.verbose:
                print(f"{Colors.WARNING}[!] Skipping invalid target: '{raw_url}'{Colors.ENDC}")

    if not urls_to_scan:
        print(f"{Colors.FAIL}[!] No valid targets to scan{Colors.ENDC}")
        return

    # Community Edition: cap at 3 targets
    _FREE_TARGET_LIMIT = 3
    if len(urls_to_scan) > _FREE_TARGET_LIMIT:
        print(f"{Colors.WARNING}  ⚡ Community Edition: max {_FREE_TARGET_LIMIT} targets per scan.{Colors.ENDC}")
        print(f"  {Colors.DIM}Scanning first {_FREE_TARGET_LIMIT} of {len(urls_to_scan)} targets.{Colors.ENDC}")
        print(f"  {Colors.DIM}Upgrade at https://arcanis.sh for unlimited targets.{Colors.ENDC}\n")
        urls_to_scan = urls_to_scan[:_FREE_TARGET_LIMIT]

    print(f"[*] Targets: {len(urls_to_scan)}")
    if args.depth:
        print(f"[*] Crawl depth: {args.depth}")
    print(f"[*] Workers: {args.workers} · Retries: {args.retries}")
    if args.ua_rotate:
        print(f"[*] UA rotation: ON")
    if args.verify:
        print(f"[*] Active verification: ON (50+ API verifiers)")
    if args.rate_limit:
        print(f"[*] Rate limit: {args.rate_limit} req/s")
    if args.probe_env:
        print(f"[*] .env probing: ON")
    if args.probe_graphql:
        print(f"[*] GraphQL probing: ON")
    if args.probe_swagger:
        print(f"[*] Swagger/OpenAPI probing: ON")
    if args.scan_cloud:
        print(f"[*] Cloud native scanning: ON")
    if args.wayback:
        print(f"[*] Wayback Machine mining: ON")
    if args.subtko:
        print(f"[*] Dangling DNS check: ON")
    if args.ssrf_probe:
        print(f"[*] Internal endpoint check: ON")
    if args.fuzz_idor:
        print(f"[*] Access control check: ON")
    if hasattr(args, 'attack_chains') and args.attack_chains:
        print(f"[*] Attack chain analysis: ON")
    if args.cve_lookup:
        print(f"[*] CVE auto-lookup: ON")
    if args.rate_abuse:
        print(f"[*] Rate limit analysis: ON (safe mode — max {RateAbuseTester.SAFE_MODE_MAX_PROBES} probes/key)")
    if args.notify:
        print(f"[*] Notifications: {args.notify[:50]}...")
    if args.baseline:
        print(f"[*] Baseline: {args.baseline}")
    if args.recon or args.recon_only:
        print(f"[*] Subdomain recon: ON (CT logs + DNS + risk scoring)")
    if args.db:
        print(f"[*] SQLite persistence: ON (~/.arcanis/arcanis.db)")
    if args.incremental:
        print(f"[*] Incremental mode: ON (skip unchanged URLs)")
    if args.cors_check:
        print(f"[*] CORS check: ON")
    if args.open_redirect:
        print(f"[*] Open redirect check: ON")
    if args.dom_xss:
        print(f"[*] DOM XSS mapping: ON")
    if args.dep_confusion:
        print(f"[*] Dependency confusion check: ON")
    if args.jwt_exploit:
        print(f"[*] JWT exploitation: ON")
    if args.cloud_perms:
        print(f"[*] Cloud permission testing: ON")
    if args.smart:
        print(f"[*] {Colors.OKGREEN}SMART MODE: ON — modules selected per target{Colors.ENDC}")
    print()

    # ── Phase 1: Subdomain Recon ──
    scan_id = None
    recon_urls = []
    if args.recon or args.recon_only:
        # Extract domain from first target
        first_target = urls_to_scan[0] if urls_to_scan else ''
        target_domain = urlparse(first_target).netloc if first_target else ''
        if target_domain:
            recon = ReconOrchestrator(
                session=scanner.session, db=db, verbose=args.verbose,
                rate_limit=args.rate_limit, max_workers=args.workers,
            )
            discovered = recon.discover(target_domain)

            if discovered:
                # Get URLs to scan (prioritized by risk)
                top_n = args.recon_top if args.recon_top > 0 else None
                recon_urls = recon.get_scan_urls(top_n=top_n)

                if args.recon_only:
                    # Store results and exit
                    if db:
                        db.close()
                    print(f"\n{Colors.OKGREEN}[+] Recon complete. "
                          f"Found {len(discovered)} live subdomains.{Colors.ENDC}")
                    if db:
                        print(f"    Results saved to ~/.arcanis/arcanis.db")
                        print(f"    Run with --db-stats to see database overview")
                    return

                # Add recon URLs to scan queue (avoid duplicates)
                existing = set(urls_to_scan)
                for ru in recon_urls:
                    if ru not in existing:
                        urls_to_scan.append(ru)
                        existing.add(ru)

                if recon_urls:
                    print(f"{Colors.OKGREEN}[+] Added {len(recon_urls)} subdomain URLs "
                          f"to scan queue{Colors.ENDC}\n")

    # ── Smart Router: Build per-target scan plan ──
    smart_plan = []
    if args.smart and urls_to_scan:
        target_domain = urlparse(urls_to_scan[0]).netloc if urls_to_scan else ''
        # Build plan from recon data if available, else from URL list
        if recon_urls and hasattr(recon, 'subdomains') and recon.subdomains:
            smart_plan = SmartRouter.plan(recon.subdomains, target_domain, args.verbose)
        else:
            # Classify from URLs alone (no recon data)
            fake_targets = [{'subdomain': urlparse(u).netloc, 'risk_score': 50} for u in urls_to_scan]
            smart_plan = SmartRouter.plan(fake_targets, target_domain, args.verbose)

    # ── DB: Register scan ──
    if db:
        config = {
            'depth': args.depth, 'workers': args.workers,
            'verify': args.verify, 'recon': args.recon,
            'smart': args.smart,
        }
        target_str = urls_to_scan[0] if urls_to_scan else 'unknown'
        scan_id = db.start_scan(target_str, config)

    scanner.progress.set_total(len(urls_to_scan))
    start = time.time()

    for url in urls_to_scan:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        # Smart routing: dynamically enable/disable modules per target
        if args.smart and smart_plan:
            active_modules = SmartRouter.get_modules_for_url(url, smart_plan)
            scanner.probe_env = 'probe_env' in active_modules
            scanner.probe_graphql = 'probe_graphql' in active_modules
            scanner.probe_swagger = 'probe_swagger' in active_modules
            scanner.enable_ssrf = 'ssrf_probe' in active_modules
            scanner.enable_fuzz_idor = 'fuzz_idor' in active_modules
            scanner.enable_cors = 'cors_check' in active_modules
            scanner.enable_redirect = 'open_redirect' in active_modules
            scanner.enable_dom_xss = 'dom_xss' in active_modules
            scanner.enable_cloud_perms = 'cloud_perms' in active_modules
            scanner.enable_jwt_exploit = 'jwt_exploit' in active_modules
            scanner.enable_dep_confusion = 'dep_confusion' in active_modules
            # Lazy-init exposure modules only when needed (use getattr for safety)
            if scanner.enable_cors and not getattr(scanner, 'cors_detector', None):
                scanner.cors_detector = CORSDetector(scanner.session, scanner.rate_limiter, scanner.verbose)
            if scanner.enable_redirect and not getattr(scanner, 'redirect_detector', None):
                scanner.redirect_detector = OpenRedirectDetector(scanner.session, scanner.rate_limiter, scanner.verbose)
            if scanner.enable_dom_xss and not getattr(scanner, 'dom_xss_mapper', None):
                scanner.dom_xss_mapper = DOMXSSMapper(scanner.verbose)
            if scanner.enable_cloud_perms and not getattr(scanner, 'cloud_perm_tester', None):
                scanner.cloud_perm_tester = CloudPermissionTester(scanner.session, scanner.rate_limiter, scanner.verbose)

        scanner.scan_url(url, depth=0)

    elapsed = time.time() - start
    scanner.progress.finish()

    # v3.0: Apply false positive filter (enhanced with entropy thresholds)
    kept, removed = FalsePositiveFilter.filter_findings(scanner.found_secrets)
    scanner.fp_removed = removed
    scanner.found_secrets = kept
    scanner.stats['fp_filtered'] = len(removed)

    # v5.0: Apply AccuracyEngine (8 intelligence upgrades)
    if scanner.found_secrets:
        pre_count = len(scanner.found_secrets)
        scanner.found_secrets = scanner.accuracy_engine.process_findings(
            scanner.found_secrets, scanner.content_cache
        )
        acc_stats = scanner.accuracy_engine.get_stats()
        env_profile = acc_stats.get('environment_profile', 'default')
        if env_profile != 'default':
            print(f"\n{Colors.OKCYAN}[*] Environment detected: {env_profile} "
                  f"(weights auto-adjusted){Colors.ENDC}")
        if acc_stats.get('upgrades_applied'):
            upgrades_summary = ', '.join(
                f"{k}: {v}" for k, v in acc_stats['upgrades_applied'].items()
                if v and k != 'dynamic_weights'
            )
            if upgrades_summary:
                print(f"{Colors.OKCYAN}[*] Accuracy Engine: {upgrades_summary}{Colors.ENDC}")
            deduped = acc_stats['upgrades_applied'].get('smart_dedup', 0)
            if deduped:
                print(f"{Colors.DIM}    Smart dedup removed {deduped} duplicate(s){Colors.ENDC}")
        cal_count = acc_stats.get('calibration_entries', 0)
        if cal_count:
            print(f"{Colors.DIM}    Calibration: {cal_count} findings logged to ~/.arcanis/calibration.json{Colors.ENDC}")

    if removed:
        print(f"\n{Colors.DIM}[*] Filtered {len(removed)} false positive(s):{Colors.ENDC}")
        # Categorize removals
        reasons = {}
        for fp in removed:
            reason = fp.get('fp_reason', 'Unknown')
            # Simplify reason for display
            if 'Entropy too low' in reason:
                cat = 'Low entropy'
            elif 'Placeholder' in reason:
                cat = 'Placeholder pattern'
            elif 'Test/example' in reason:
                cat = 'Test/example file'
            elif 'Documentation' in reason:
                cat = 'Documentation source'
            elif 'external CDN' in reason:
                cat = 'External CDN'
            elif 'Duplicate' in reason:
                cat = 'Duplicate'
            elif 'Too short' in reason:
                cat = 'Too short'
            else:
                cat = 'Other'
            reasons[cat] = reasons.get(cat, 0) + 1
        for cat, count in sorted(reasons.items(), key=lambda x: -x[1]):
            print(f"{Colors.DIM}    {cat}: {count}{Colors.ENDC}")

    # v4.0: Wayback Machine mining
    if args.wayback and urls_to_scan:
        domain = urlparse(urls_to_scan[0]).netloc
        print(f"\n{Colors.OKCYAN}[*] Mining Wayback Machine for {domain} (target-scoped)...{Colors.ENDC}")
        wb_urls = scanner.wayback.mine(domain, max_results=50)
        scanner.stats['wayback_urls'] = len(wb_urls)
        if wb_urls:
            print(f"{Colors.OKGREEN}[+] Found {len(wb_urls)} in-scope archived URLs"
                  f" ({scanner.wayback.filtered_count} off-scope dropped){Colors.ENDC}")
            for wb_url in wb_urls[:20]:
                scanner.scan_url(wb_url, depth=0)

    # v4.0: Subdomain takeover check
    if args.subtko and urls_to_scan:
        domain = urlparse(urls_to_scan[0]).netloc
        print(f"\n{Colors.OKCYAN}[*] Checking subdomain takeover for {domain}...{Colors.ENDC}")
        scanner.subtko.check_cname(domain)
        scanner.stats['subtko_findings'] = len(scanner.subtko.findings)

    # v4.0: Collect recon stats
    scanner.stats['ssrf_vectors'] = len(scanner.ssrf_prober.vectors)
    scanner.stats['idor_candidates'] = len(scanner.idor_fuzzer.idor_candidates)
    scanner.stats['internal_routes'] = len(scanner.internal_api_enum.routes)

    # v4.0: Attack chain analysis
    if hasattr(args, 'attack_chains') and args.attack_chains:
        scanner.attack_chains = AttackChainBuilder.build_chains(scanner.found_secrets)
        scanner.stats['attack_chains'] = len(scanner.attack_chains)

    # v5.0: CVE auto-lookup from source map packages
    if args.cve_lookup and scanner.source_map_intel:
        print(f"\n{Colors.OKCYAN}[*] Running CVE lookup for source map packages...{Colors.ENDC}")
        all_pkgs = set()
        for sm in scanner.source_map_intel:
            all_pkgs.update(sm.get('npm_packages', []))
        sc_pkgs = scanner.supply_chain.npm_packages
        all_pkgs.update(sc_pkgs)
        if all_pkgs:
            scanner.cve_lookup.lookup_packages(sorted(all_pkgs), scanner.source_map_intel)
            cve_sum = scanner.cve_lookup.get_summary()
            scanner.stats['cve_confirmed'] = cve_sum['confirmed_vulnerable']
            scanner.stats['cve_potential'] = cve_sum['potential']
            print(f"{Colors.OKGREEN}[+] CVE lookup: {cve_sum['confirmed_vulnerable']} confirmed, "
                  f"{cve_sum['potential']} potential{Colors.ENDC}")

    # v5.0: API rate abuse testing
    if args.rate_abuse and scanner.rate_tester:
        print(f"\n{Colors.OKCYAN}[*] Checking rate limit protection on verified keys...{Colors.ENDC}")
        scanner.rate_tester.test_findings(scanner.found_secrets)
        rate_sum = scanner.rate_tester.get_summary()
        scanner.stats['rate_abuse_unrestricted'] = rate_sum['unrestricted']

    # v3.0: Baseline diff
    if args.baseline:
        new_findings, resolved = CICDIntegration.diff_baseline(
            scanner.found_secrets, args.baseline)
        print(f"\n{Colors.BOLD}📊 Baseline Diff:{Colors.ENDC}")
        print(f"  New findings: {len(new_findings)}")
        print(f"  Resolved: {len(resolved)}")
        if new_findings:
            print(f"\n{Colors.WARNING}New findings:{Colors.ENDC}")
            for f in new_findings[:10]:
                print(f"  + [{f['severity']}] {f['type']} in {f['source'][:60]}")
        if resolved:
            print(f"\n{Colors.OKGREEN}Resolved:{Colors.ENDC}")
            for f in resolved[:10]:
                print(f"  - [{f['severity']}] {f['type']}")

    # Collect supply chain stats
    sc_sum = scanner.supply_chain.get_summary()
    scanner.stats['supply_chain_vulns'] = sc_sum['vulnerable_libraries']
    scanner.stats['sri_missing'] = sc_sum['sri_missing']
    scanner.stats['header_issues'] = len(scanner.headers_auditor.findings)
    scanner.stats['swagger_specs'] = len(scanner.api_discovery.swagger_specs)
    if scanner.cloud_scanner:
        scanner.stats['cloud_findings'] = len(scanner.cloud_scanner.findings)

    if scanner.found_secrets:
        print(f"\n{Colors.OKGREEN}[+] {len(scanner.found_secrets)} "
              f"secret(s) in {elapsed:.1f}s!{Colors.ENDC}")
        scanner.print_details()
    else:
        print(f"\n{Colors.OKBLUE}[*] No high-confidence secrets detected ({elapsed:.1f}s){Colors.ENDC}")

    scanner.print_summary()

    # v4.0: Attack chain display
    if scanner.attack_chains:
        AttackChainBuilder.print_chains(scanner.attack_chains)

    # v4.0: Offensive recon summary
    recon_items = []
    if scanner.ssrf_prober.vectors:
        recon_items.append(f"Internal endpoints: {len(scanner.ssrf_prober.vectors)}")
    if scanner.idor_fuzzer.idor_candidates:
        recon_items.append(f"IDOR candidates: {len(scanner.idor_fuzzer.idor_candidates)}")
    if scanner.internal_api_enum.routes:
        recon_items.append(f"Internal routes: {len(scanner.internal_api_enum.routes)}")
    if scanner.subtko.findings:
        recon_items.append(f"SubTKO findings: {len(scanner.subtko.findings)}")
    if scanner.wayback.archived_urls:
        recon_items.append(f"Wayback URLs: {len(scanner.wayback.archived_urls)}")
    if recon_items:
        print(f"\n{Colors.BOLD}Extended Recon:{Colors.ENDC}")
        for item in recon_items:
            print(f"  {item}")
    if scanner.internal_api_enum.routes:
        crit_routes = [r for r in scanner.internal_api_enum.routes if r['severity'] in ('CRITICAL', 'HIGH')]
        if crit_routes:
            print(f"\n{Colors.FAIL}High-value internal routes:{Colors.ENDC}")
            for r in crit_routes[:10]:
                print(f"  [{r['severity']}] {r['route']}  ({r['source'][:50]})")

    # ── v6.0: Exposure module results ──
    exposure_items = []

    # CORS results
    if getattr(scanner, 'cors_detector', None) and scanner.cors_detector.findings:
        cors_sum = scanner.cors_detector.get_summary()
        exposure_items.append(f"CORS misconfigs: {cors_sum['total']} ({cors_sum['critical']} critical)")
        if not args.verbose:
            for f in scanner.cors_detector.findings[:5]:
                print(f"  {Colors.FAIL}[CORS] [{f['severity']}]{Colors.ENDC} {f['detail']}")

    # Open redirect results
    if getattr(scanner, 'redirect_detector', None) and scanner.redirect_detector.findings:
        exposure_items.append(f"Open redirects: {len(scanner.redirect_detector.findings)}")

    # DOM XSS results
    if getattr(scanner, 'dom_xss_mapper', None) and scanner.dom_xss_mapper.findings:
        xss_crit = sum(1 for f in scanner.dom_xss_mapper.findings if f['severity'] == 'CRITICAL')
        exposure_items.append(f"DOM XSS vectors: {len(scanner.dom_xss_mapper.findings)} ({xss_crit} critical)")

    # Cloud permissions
    if getattr(scanner, 'cloud_perm_tester', None) and scanner.cloud_perm_tester.findings:
        exposure_items.append(f"Cloud misconfigs: {len(scanner.cloud_perm_tester.findings)}")

    if exposure_items:
        print(f"\n{Colors.BOLD}Exposure Analysis:{Colors.ENDC}")
        for item in exposure_items:
            print(f"  {item}")

    # v6.0: Dependency confusion (runs post-scan using source map data)
    if args.dep_confusion and scanner.source_map_intel:
        dep_scanner = DependencyConfusionScanner(scanner.session, scanner.rate_limiter, args.verbose)
        target_domain = urlparse(urls_to_scan[0]).netloc if urls_to_scan else ''
        dep_scanner.check_from_source_maps(scanner.source_map_intel, target_domain)
        if dep_scanner.findings:
            print(f"\n{Colors.FAIL}[!] Dependency Confusion: "
                  f"{len(dep_scanner.findings)} vulnerable package(s){Colors.ENDC}")
            for f in dep_scanner.findings[:5]:
                print(f"  [{f['severity']}] {f['detail']}")

    # v6.0: JWT exploitation (runs post-scan on discovered JWTs)
    if args.jwt_exploit and scanner.found_secrets:
        jwt_tester = JWTExploitTester(scanner.session, scanner.rate_limiter, args.verbose)
        jwt_findings = [f for f in scanner.found_secrets if 'JWT' in f.get('type', '').upper()
                        or f.get('type', '') == 'JSON Web Token']
        for jf in jwt_findings:
            jwt_tester.test_token(jf.get('value', ''), jf.get('source', ''))
        if jwt_tester.findings:
            print(f"\n{Colors.FAIL}[!] JWT Exploitation: "
                  f"{len(jwt_tester.findings)} finding(s){Colors.ENDC}")
            for f in jwt_tester.findings[:5]:
                print(f"  [{f['severity']}] {f['detail']}")

    # v6.0: Cloud permission testing (runs post-scan on discovered cloud resources)
    if args.cloud_perms and scanner.found_secrets:
        if not getattr(scanner, 'cloud_perm_tester', None):
            scanner.cloud_perm_tester = CloudPermissionTester(
                scanner.session, scanner.rate_limiter, args.verbose)
        scanner.cloud_perm_tester.test_from_findings(scanner.found_secrets)
        if scanner.cloud_perm_tester.findings:
            print(f"\n{Colors.FAIL}[!] Cloud Permissions: "
                  f"{len(scanner.cloud_perm_tester.findings)} misconfig(s){Colors.ENDC}")
            for f in scanner.cloud_perm_tester.findings[:5]:
                print(f"  [{f['severity']}] {f['detail']}")

    # v5.1.1: Top targets worth manual testing (v5.1.2: fixed empty modules)
    if args.smart and smart_plan:
        ranked = sorted(smart_plan, key=lambda x: x.get('risk_score', 0), reverse=True)
        top_targets = [t for t in ranked if t.get('risk_score', 0) >= 30][:5]
        if top_targets:
            print(f"\n{Colors.BOLD}🎯 TOP TARGETS WORTH MANUAL TESTING:{Colors.ENDC}")
            for i, t in enumerate(top_targets, 1):
                rs = t.get('risk_score', 0)
                rc = Colors.FAIL if rs >= 70 else (Colors.WARNING if rs >= 50 else Colors.OKCYAN)
                sub = t.get('subdomain', t.get('url', '?'))
                atype = t.get('smart_type', t.get('asset_type', 'unknown')).upper().replace('_', ' ')
                # Get modules from smart plan — try smart_modules first, then modules
                mods = t.get('smart_modules', t.get('modules', []))
                # Filter out always-on modules for cleaner display
                display_mods = [m for m in mods if m not in ('secret_scan', 'verify')][:5]
                if not display_mods:
                    # Recommend manual testing modules based on asset type
                    display_mods = ['manual: cors, headers, auth bypass']
                modules_str = ', '.join(display_mods)
                print(f"  {rc}{i}. {sub} (Score {rs}) [{atype}]{Colors.ENDC}")
                print(f"     {Colors.DIM}Modules: {modules_str}{Colors.ENDC}")

    # ── DB: Save findings and finalize ──
    if db and scan_id:
        for finding in scanner.found_secrets:
            db.save_finding(scan_id, finding)
        db.finish_scan(scan_id, len(scanner.scanned_urls),
                       len(scanner.found_secrets), elapsed)
        db_stats = db.get_stats()
        print(f"\n{Colors.DIM}[DB] Scan #{scan_id} saved | "
              f"Total: {db_stats['total_findings']} findings across "
              f"{db_stats['total_scans']} scans{Colors.ENDC}")

        # v5.1.1: Differential scan — compare with previous scan
        if hasattr(args, 'diff') and args.diff:
            target_domain = urlparse(urls_to_scan[0]).netloc if urls_to_scan else ''
            prev = db.get_previous_scan_data(target_domain)
            if prev and prev.get('scan_id') and prev['scan_id'] != scan_id:
                print(f"\n{Colors.BOLD}📊 DIFFERENTIAL SCAN (vs scan #{prev['scan_id']}):{Colors.ENDC}")
                # New findings
                current_hashes = set()
                for f in scanner.found_secrets:
                    h = hashlib.sha256(f"{f.get('type','')}:{f.get('value','')}".encode()).hexdigest()[:16]
                    current_hashes.add(h)
                new_finding_hashes = current_hashes - prev['finding_hashes']
                resolved_hashes = prev['finding_hashes'] - current_hashes
                if new_finding_hashes:
                    print(f"  {Colors.WARNING}New findings: {len(new_finding_hashes)}{Colors.ENDC}")
                    for f in scanner.found_secrets:
                        h = hashlib.sha256(f"{f.get('type','')}:{f.get('value','')}".encode()).hexdigest()[:16]
                        if h in new_finding_hashes:
                            print(f"    {Colors.WARNING}+ [{f.get('severity','?')}] {f['type']} in {f.get('source','?')[:50]}{Colors.ENDC}")
                if resolved_hashes:
                    print(f"  {Colors.OKGREEN}Resolved: {len(resolved_hashes)} finding(s) no longer detected{Colors.ENDC}")

                # New subdomains
                if hasattr(scanner, 'scanned_urls'):
                    current_urls = scanner.scanned_urls
                    prev_url_set = set(prev.get('url_hashes', {}).keys())
                    new_urls = current_urls - prev_url_set
                    if new_urls:
                        print(f"  {Colors.OKCYAN}New endpoints: {len(new_urls)}{Colors.ENDC}")
                        for u in sorted(new_urls)[:5]:
                            print(f"    + {u[:70]}")

                # Header/SRI changes
                current_header_count = len(scanner.headers_auditor.findings)
                current_sri = scanner.supply_chain.get_summary()['sri_missing']
                print(f"  {Colors.DIM}URLs scanned: {len(scanner.scanned_urls)} "
                      f"(prev: {len(prev.get('urls', []))}){Colors.ENDC}")
                if not new_finding_hashes and not resolved_hashes:
                    print(f"  {Colors.DIM}No finding changes detected{Colors.ENDC}")
            elif db_stats['total_scans'] <= 1:
                print(f"\n{Colors.DIM}[DIFF] First scan — no previous data to compare{Colors.ENDC}")

        db.close()

    if args.output:
        scanner.export_json(args.output)
    if args.html:
        scanner.export_html(args.html)
    if args.sarif:
        export_sarif(scanner.found_secrets, scanner.stats, args.sarif)

    # v5.0: Enhanced report generation
    if args.report:
        report_base = args.output.replace('.json', '') if args.output else 'scan_report'
        if args.report in ('html', 'both'):
            html_report = f"{report_base}_v5.html"
            # Use existing HTML export enhanced with v5.0 data
            scanner.export_html(html_report)
        if args.report in ('pdf', 'both'):
            html_for_pdf = f"{report_base}_v5.html"
            if not Path(html_for_pdf).exists():
                scanner.export_html(html_for_pdf)
            pdf_path = f"{report_base}_v5.pdf"
            ReportGenerator.generate_pdf(html_for_pdf, pdf_path)

    # v3.0: Webhook notification
    if scanner.notifier:
        target = urls_to_scan[0] if urls_to_scan else 'unknown'
        scanner.notifier.send_alert(scanner.found_secrets, scanner.stats, target)


def _print_upgrade_banner():
    """Show upgrade prompt after scan completes."""
    B = Colors.BOLD
    C = Colors.OKCYAN
    Y = Colors.WARNING
    D = Colors.DIM
    R = Colors.ENDC
    print(f"""
{Y}╔══════════════════════════════════════════════════════════════╗{R}
{Y}║{R}  {B}Upgrade to Arcanis Pro{R} — unlock the full pipeline:          {Y}║{R}
{Y}║{R}                                                              {Y}║{R}
{Y}║{R}  {C}✓{R} --verify     50+ live API verifiers (prove keys work)    {Y}║{R}
{Y}║{R}  {C}✓{R} --attack-chains   Exploit paths + bounty tier scoring   {Y}║{R}
{Y}║{R}  {C}✓{R} --cve-lookup      CVE cross-ref for npm packages       {Y}║{R}
{Y}║{R}  {C}✓{R} --wayback         Mine historical JS from Wayback       {Y}║{R}
{Y}║{R}  {C}✓{R} --sarif           CI/CD integration (GitHub, GitLab)    {Y}║{R}
{Y}║{R}  {C}✓{R} --report pdf      Submit-ready PDF reports              {Y}║{R}
{Y}║{R}  {C}✓{R} -L targets.txt    Unlimited batch scanning              {Y}║{R}
{Y}║{R}                                                              {Y}║{R}
{Y}║{R}  {D}Plans from $19/mo · Lifetime $199 · https://arcanis.sh{R}    {Y}║{R}
{Y}╚══════════════════════════════════════════════════════════════╝{R}
""")


# Patch main to show upgrade banner after scan
_original_main = main

def main():
    _original_main()
    _print_upgrade_banner()


if __name__ == '__main__':
    main()
