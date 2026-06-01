"""Secrets scanner - detects API keys, tokens, credentials, and high-entropy secrets.

Detection methods:
  - regex: Pattern matching for known secret formats (API keys, tokens, etc.)
  - entropy: Shannon entropy scoring for unknown high-entropy strings
  - hybrid: Regex + entropy cross-verification for higher confidence

Each finding includes: detection method, confidence score (0-1), and remediation hints.
"""

from __future__ import annotations

import math
import os
import re
from typing import Dict, List, Optional, Set, Tuple

from ..models import DetectionMethod, Finding, Severity


# ──────────────────────────────────────────────────────────────────────
# Entropy-based detection
# ──────────────────────────────────────────────────────────────────────

def shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string.

    Higher entropy indicates more randomness, which is characteristic of
    secrets, keys, and tokens. Typical entropy ranges:
      0-2.0: Low entropy (common words, code)
      2.0-3.5: Medium entropy (base64-like strings)
      3.5+: High entropy (random keys, high-entropy secrets)
    """
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for char in set(data):
        count = data.count(char)
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


# High-entropy patterns that are likely false positives (UUIDs, hashes from deps)
LOW_RISK_HIGH_ENTROPY_PATTERNS: List[re.Pattern] = [
    re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I),  # UUID
    re.compile(r"^[0-9a-f]{32}$", re.I),  # MD5 hash
    re.compile(r"^[0-9a-f]{40}$", re.I),  # SHA1 hash
    re.compile(r"^[0-9a-f]{64}$", re.I),  # SHA256 hash
    re.compile(r"^[0-9]+$"),              # Numeric-only
    re.compile(r"^[a-zA-Z]+$"),           # Alpha-only
    re.compile(r"^[a-f0-9]+$", re.I),     # Hex-only
]

# Variable names that might contain high-entropy strings
ENTROPY_TARGET_NAMES: List[re.Pattern] = [
    re.compile(r"(?i)(?:secret|token|key|password|passwd|pwd|cert|credential"
               r"|auth|api[_-]?key|access[_-]?key|private[_-]?key"
               r"|encryption[_-]?key|signing[_-]?key|session[_-]?secret"
               r"|jwt[_-]?secret|hash[_-]?salt|pepper)"),
]


def is_low_risk_high_entropy(value: str) -> bool:
    """Check if a high-entropy string matches known low-risk patterns."""
    for pattern in LOW_RISK_HIGH_ENTROPY_PATTERNS:
        if pattern.match(value.strip()):
            return True
    return False


# ──────────────────────────────────────────────────────────────────────
# Regex-based secret patterns
# ──────────────────────────────────────────────────────────────────────

SECRET_PATTERNS: List[Dict] = [
    # ─── Cloud Provider Credentials ───────────────────────────────────────
    {
        "name": "aws-access-key",
        "pattern": re.compile(r"(?<![A-Za-z0-9/+=])AKIA[0-9A-Z]{16}(?![A-Za-z0-9/+=])"),
        "severity": Severity.HIGH,
        "message": "AWS Access Key ID detected. This can grant access to AWS resources.",
        "confidence": 0.9,
        "remediation": "Rotate the key immediately. Use IAM roles or temporary credentials via STS instead of long-lived keys.",
    },
    {
        "name": "aws-secret-key",
        "pattern": re.compile(
            r"(?i)(?:aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret[_-]?key)"
            r"\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})"
        ),
        "severity": Severity.HIGH,
        "message": "AWS Secret Access Key detected. This can compromise AWS accounts.",
        "confidence": 0.95,
        "remediation": "Revoke the key immediately. Use AWS Secrets Manager or environment variables for credential management.",
    },
    {
        "name": "aws-session-token",
        "pattern": re.compile(
            r"(?i)(?:aws[_-]?session[_-]?token|session[_-]?token)"
            r"\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{100,})"
        ),
        "severity": Severity.HIGH,
        "message": "AWS Session Token detected. Temporary AWS credentials should not be committed.",
        "confidence": 0.85,
        "remediation": "Remove from source control. Use short-lived STS tokens or instance profiles instead.",
    },
    {
        "name": "gcp-service-account",
        "pattern": re.compile(r'"type"\s*:\s*"service_account"'),
        "severity": Severity.HIGH,
        "message": "GCP service account key file detected. Service account keys can grant access to Google Cloud resources.",
        "confidence": 0.95,
        "remediation": "Use Workload Identity Federation instead of service account keys. If a key is needed, rotate it and store it in Secret Manager.",
    },
    {
        "name": "gcp-api-key",
        "pattern": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "severity": Severity.MEDIUM,
        "message": "Google API key detected. Keys in source code can be abused and quota can be exhausted.",
        "confidence": 0.8,
        "remediation": "Restrict the API key by application, IP, or referrer in the GCP Console. Use environment variables.",
    },
    {
        "name": "azure-connection-string",
        "pattern": re.compile(
            r"(?i)(?:DefaultEndpointsProtocol|AccountName|AccountKey|SharedAccessSignature)"
            r"\s*=\s*[^;\s]+"
        ),
        "severity": Severity.HIGH,
        "message": "Azure connection string detected. Connection strings can grant access to Azure storage accounts.",
        "confidence": 0.85,
        "remediation": "Use Managed Identity or Azure Key Vault to access storage accounts without connection strings.",
    },
    {
        "name": "azure-client-secret",
        "pattern": re.compile(
            r"(?i)(?:azure[_-]?client[_-]?secret|client[_-]?secret)"
            r"\s*[:=]\s*['\"][A-Za-z0-9\-_./=+]{20,}['\"]"
        ),
        "severity": Severity.HIGH,
        "message": "Azure client secret detected. Client secrets can authenticate Azure AD applications.",
        "confidence": 0.85,
        "remediation": "Use Managed Identity or certificate-based authentication instead of client secrets.",
    },
    {
        "name": "digitalocean-token",
        "pattern": re.compile(r"(?i)(?:digitalocean[_-]?token|dop_v1_[a-f0-9]{64})"),
        "severity": Severity.HIGH,
        "message": "DigitalOcean personal access token detected. This can grant full API access to DigitalOcean accounts.",
        "confidence": 0.9,
        "remediation": "Regenerate the token immediately. Use API tokens read-only where possible.",
    },
    {
        "name": "heroku-api-key",
        "pattern": re.compile(
            r"(?i)(?:heroku[_-]?api[_-]?key|HEROKU[_-]?API[_-]?KEY)"
            r"\s*[:=]\s*['\"][A-Za-z0-9-]{36}['\"]"
        ),
        "severity": Severity.HIGH,
        "message": "Heroku API key detected. This can grant access to Heroku accounts and apps.",
        "confidence": 0.9,
        "remediation": "Regenerate the API key in Heroku Dashboard. Use config vars for app-specific credentials.",
    },

    # ─── Private Keys & Certificates ─────────────────────────────────────
    {
        "name": "private-key",
        "pattern": re.compile(
            r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|SSH2) PRIVATE KEY(?: BLOCK)?-----"
        ),
        "severity": Severity.HIGH,
        "message": "Private key detected. Private keys should never be committed to repositories.",
        "confidence": 1.0,
        "remediation": "Remove the key from the repository immediately. Use SSH agent or hardware security modules for key management.",
    },
    {
        "name": "pgp-private-key-block",
        "pattern": re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
        "severity": Severity.HIGH,
        "message": "PGP private key block detected. PGP private keys should never be committed.",
        "confidence": 1.0,
        "remediation": "Revoke and regenerate the PGP key immediately. Store private keys in a secure vault.",
    },
    {
        "name": "certificate-key",
        "pattern": re.compile(r"-----BEGIN CERTIFICATE-----"),
        "severity": Severity.MEDIUM,
        "message": "Certificate file detected. Certificates may contain sensitive information.",
        "confidence": 0.7,
        "remediation": "Consider using a certificate management solution. Store certificates in environment variables or a vault.",
    },

    # ─── SaaS & Platform API Keys ────────────────────────────────────────
    {
        "name": "stripe-live-key",
        "pattern": re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
        "severity": Severity.HIGH,
        "message": "Stripe live secret key detected. This can be used to charge real credit cards and access payment data.",
        "confidence": 0.99,
        "remediation": "Roll the key immediately in Stripe Dashboard. Use Stripe CLI or environment variables for key management.",
    },
    {
        "name": "stripe-test-key",
        "pattern": re.compile(r"(?:sk_test_|pk_test_)[0-9a-zA-Z]{24,}"),
        "severity": Severity.MEDIUM,
        "message": "Stripe test key detected. Test keys should not be committed to production repositories.",
        "confidence": 0.9,
        "remediation": "Use environment variables for Stripe keys. Differentiate test and production keys in deployment configs.",
    },
    {
        "name": "stripe-webhook-secret",
        "pattern": re.compile(r"whsec_[0-9a-zA-Z]{24,}"),
        "severity": Severity.HIGH,
        "message": "Stripe webhook secret detected. This can be used to verify and replay webhook events.",
        "confidence": 0.95,
        "remediation": "Roll the webhook secret in Stripe Dashboard. Store it in a secrets manager or environment variables.",
    },
    {
        "name": "slack-bot-token",
        "pattern": re.compile(r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}"),
        "severity": Severity.HIGH,
        "message": "Slack bot token detected. This can grant access to Slack workspace conversations and data.",
        "confidence": 0.95,
        "remediation": "Regenerate the bot token in Slack API dashboard. Restrict bot scopes to minimum required.",
    },
    {
        "name": "slack-webhook-url",
        "pattern": re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24,}"),
        "severity": Severity.HIGH,
        "message": "Slack webhook URL detected. Webhooks can be abused to send messages to Slack channels.",
        "confidence": 0.95,
        "remediation": "Delete and recreate the webhook in Slack. Incoming webhook URLs cannot be partially rolled.",
    },
    {
        "name": "github-token",
        "pattern": re.compile(r"ghp_[A-Za-z0-9]{36}"),
        "severity": Severity.HIGH,
        "message": "GitHub personal access token detected. This can grant access to repositories and organizations.",
        "confidence": 0.95,
        "remediation": "Revoke the token immediately in GitHub Settings. Use fine-grained tokens with minimal permissions.",
    },
    {
        "name": "github-old-token",
        "pattern": re.compile(r"gh[osu]_[A-Za-z0-9]{36}"),
        "severity": Severity.HIGH,
        "message": "GitHub OAuth/SSH token detected. This can grant access to GitHub resources.",
        "confidence": 0.9,
        "remediation": "Revoke the token in GitHub Settings. Use GitHub App tokens or OAuth app tokens with limited scopes.",
    },
    {
        "name": "gitlab-token",
        "pattern": re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"),
        "severity": Severity.HIGH,
        "message": "GitLab personal access token detected. This can grant access to GitLab repositories and CI/CD pipelines.",
        "confidence": 0.95,
        "remediation": "Revoke the token in GitLab Settings. Use project-level tokens or CI/CD variables instead.",
    },
    {
        "name": "npm-token",
        "pattern": re.compile(r"npm_[A-Za-z0-9]{36}"),
        "severity": Severity.HIGH,
        "message": "npm access token detected. This can grant access to npm packages and organizations.",
        "confidence": 0.95,
        "remediation": "Revoke the token on npmjs.com. Use granular automation tokens with limited scope.",
    },
    {
        "name": "twilio-account-sid",
        "pattern": re.compile(r"AC[a-z0-9]{32}"),
        "severity": Severity.HIGH,
        "message": "Twilio Account SID detected. This can grant API access to Twilio accounts.",
        "confidence": 0.9,
        "remediation": "Never commit Account SIDs. Use environment variables and restrict API key permissions.",
    },
    {
        "name": "twilio-auth-token",
        "pattern": re.compile(
            r"(?i)(?:twilio[_-]?auth[_-]?token|TWILIO[_-]?AUTH[_-]?TOKEN)"
            r"\s*[:=]\s*['\"]?[a-z0-9]{32}"
        ),
        "severity": Severity.HIGH,
        "message": "Twilio auth token detected. This can fully compromise Twilio accounts and phone numbers.",
        "confidence": 0.95,
        "remediation": "Roll the auth token in Twilio Console immediately. Rotate regularly and store in a secrets manager.",
    },
    {
        "name": "docker-hub-token",
        "pattern": re.compile(r"dckr_pat_[A-Za-z0-9\-_]{20,}"),
        "severity": Severity.HIGH,
        "message": "Docker Hub personal access token detected. This can grant access to Docker Hub repositories.",
        "confidence": 0.95,
        "remediation": "Delete and recreate the token in Docker Hub settings. Use read-only tokens where possible.",
    },
    {
        "name": "sendgrid-api-key",
        "pattern": re.compile(r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"),
        "severity": Severity.HIGH,
        "message": "SendGrid API key detected. This can be used to send emails from the SendGrid account.",
        "confidence": 0.95,
        "remediation": "Revoke the key in SendGrid Dashboard. Create API keys with sub-user scoping for least privilege.",
    },
    {
        "name": "jwt-token",
        "pattern": re.compile(
            r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
        ),
        "severity": Severity.MEDIUM,
        "message": "JWT token detected. Tokens in source code pose a security risk as they can authenticate API requests.",
        "confidence": 0.7,
        "remediation": "Revoke the token if it's a refresh/access token. Never commit tokens — use environment variables or OAuth flows.",
    },

    # ─── Social Media & Communication ────────────────────────────────────
    {
        "name": "discord-bot-token",
        "pattern": re.compile(r"[MN][A-Za-z0-9\-_]{23}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27}"),
        "severity": Severity.HIGH,
        "message": "Discord bot or OAuth token detected. This can grant access to Discord servers and messages.",
        "confidence": 0.9,
        "remediation": "Regenerate the bot token in Discord Developer Portal. Restrict bot permissions to minimum required.",
    },
    {
        "name": "discord-webhook",
        "pattern": re.compile(r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+"),
        "severity": Severity.HIGH,
        "message": "Discord webhook URL detected. Webhooks can be abused to send messages to Discord channels.",
        "confidence": 0.95,
        "remediation": "Delete and recreate the webhook in Discord server settings. Webhook URLs cannot be partially revoked.",
    },
    {
        "name": "telegram-bot-token",
        "pattern": re.compile(r"[0-9]{8,10}:[A-Za-z0-9\-_]{35}"),
        "severity": Severity.MEDIUM,
        "message": "Potential Telegram bot token detected. Bot tokens can control Telegram bots and access chat data.",
        "confidence": 0.75,
        "remediation": "Revoke the token via @BotFather and generate a new one. Never store bot tokens in source code.",
    },

    # ─── Database & Infrastructure ───────────────────────────────────────
    {
        "name": "connection-string",
        "pattern": re.compile(
            r"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\\+srv)?|redis|amqp|rabbitmq)"
            r"://[^\s:]+:[^\s@]+@"
        ),
        "severity": Severity.HIGH,
        "message": "Database connection string with embedded credentials detected. Connection strings with passwords should use environment variables or a vault.",
        "confidence": 0.95,
        "remediation": "Use environment variables for connection strings. Consider AWS Secrets Manager, HashiCorp Vault, or Kubernetes Secrets.",
    },
    {
        "name": "redis-url",
        "pattern": re.compile(r"redis://:[^\s@]+@[a-zA-Z0-9.\-]+:\d+"),
        "severity": Severity.MEDIUM,
        "message": "Redis connection string with password detected. Redis URLs with passwords in source code are a security risk.",
        "confidence": 0.9,
        "remediation": "Store Redis credentials in environment variables. Use Redis ACLs for access control.",
    },

    # ─── General Credentials Patterns ────────────────────────────────────
    {
        "name": "generic-api-key",
        "pattern": re.compile(
            r"(?i)(?:api[_-]?key|api[_-]?secret|app[_-]?key|app[_-]?secret"
            r"|consumer[_-]?key|consumer[_-]?secret|auth[_-]?token"
            r"|access[_-]?token|secret[_-]?token|bearer[_-]?token)"
            r"\s*[:=]\s*['\"]?([A-Za-z0-9_\-./=+]{16,})"
        ),
        "severity": Severity.MEDIUM,
        "message": "API key or secret token detected in source code. Consider using environment variables or a secret management service.",
        "confidence": 0.75,
        "remediation": "Move credentials to environment variables or a secrets manager. Never commit API keys to repositories.",
    },
    {
        "name": "password-in-code",
        "pattern": re.compile(
            r"(?i)(?:password|passwd|pwd|db_password|db_passwd)"
            r"\s*[:=]\s*['\"]?([A-Za-z0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>?]{8,})"
        ),
        "severity": Severity.MEDIUM,
        "message": "Hardcoded password detected. Passwords should use environment variables, a vault service, or a secrets manager.",
        "confidence": 0.7,
        "remediation": "Use environment variables, HashiCorp Vault, or a cloud secrets manager. Rotate passwords immediately.",
    },
    {
        "name": "generic-secret",
        "pattern": re.compile(
            r"(?i)(?:secret|token|private_key|secret_key|encryption_key)"
            r"\s*[:=]\s*['\"]?([A-Za-z0-9_\-./=+]{20,})"
        ),
        "severity": Severity.LOW,
        "message": "Potential secret, token, or key detected. Verify this is not a hardcoded credential.",
        "confidence": 0.4,
        "remediation": "Review the value to ensure it's not a credential. If it is, move it to environment variables.",
    },

    # ─── Infrastructure & DevOps ─────────────────────────────────────────
    {
        "name": "pulumi-access-token",
        "pattern": re.compile(r"pul-[a-f0-9]{40}"),
        "severity": Severity.HIGH,
        "message": "Pulumi access token detected. This can grant access to Pulumi infrastructure state and management.",
        "confidence": 0.95,
        "remediation": "Revoke the token in Pulumi Cloud. Use Pulumi ESC for environment secret management.",
    },
    {
        "name": "snyk-token",
        "pattern": re.compile(r"(?i)(?:snyk[_-]?token|SNYK[_-]?TOKEN)\s*[:=]\s*['\"]?[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"),
        "severity": Severity.HIGH,
        "message": "Snyk API token detected. This can grant access to Snyk vulnerability data and project settings.",
        "confidence": 0.9,
        "remediation": "Revoke and recreate the token in Snyk Dashboard. Use service accounts for CI/CD integration.",
    },
    {
        "name": "datadog-api-key",
        "pattern": re.compile(r"(?i)(?:datadog[_-]?api[_-]?key|DD[_-]?API[_-]?KEY)\s*[:=]\s*['\"]?[a-f0-9]{32}"),
        "severity": Severity.MEDIUM,
        "message": "Datadog API key detected. API keys can be used to send and retrieve data from Datadog accounts.",
        "confidence": 0.85,
        "remediation": "Rotate the key in Datadog Account Settings. Use application keys tied to specific service accounts.",
    },
    {
        "name": "new-relic-key",
        "pattern": re.compile(r"(?i)(?:new[_-]?relic[_-]?license[_-]?key|NR[_-]?LICENSE[_-]?KEY)\s*[:=]\s*['\"]?[a-f0-9]{40}"),
        "severity": Severity.MEDIUM,
        "message": "New Relic license key detected. License keys can be used to send data to New Relic accounts.",
        "confidence": 0.85,
        "remediation": "Rotate the key in New Relic. Use environment variables for configuration.",
    },

    # ─── Payment & Fintech ───────────────────────────────────────────────
    {
        "name": "square-access-token",
        "pattern": re.compile(r"(?i)(?:square[_-]?access[_-]?token|EAAA[A-Za-z0-9]{40,})"),
        "severity": Severity.HIGH,
        "message": "Square access token detected. This can grant access to Square payment data and merchant accounts.",
        "confidence": 0.85,
        "remediation": "Revoke the token in Square Developer Dashboard. Use OAuth for production authentication.",
    },
    {
        "name": "paypal-secret",
        "pattern": re.compile(
            r"(?i)(?:paypal[_-]?(?:client[_-]?)?secret|PAYPAL[_-]?CLIENT[_-]?SECRET)"
            r"\s*[:=]\s*['\"]?[A-Za-z0-9\-_]{20,}"
        ),
        "severity": Severity.HIGH,
        "message": "PayPal client secret detected. This can authenticate PayPal API requests and access payment data.",
        "confidence": 0.85,
        "remediation": "Revoke the API credentials in PayPal Developer Dashboard. Use environment variables or a secrets manager.",
    },
]


# ──────────────────────────────────────────────────────────────────────
# Whitelist: strings that look like secrets but are safe
# ──────────────────────────────────────────────────────────────────────

WHITELIST_PATTERNS: List[re.Pattern] = [
    # Example/test values
    re.compile(r"AKIAIOSFODNN7EXAMPLE", re.I),
    re.compile(r"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    re.compile(r"EXAMPLE", re.I),
    re.compile(r"your[_-]?(?:key|token|secret|password|api)", re.I),
    # Placeholder patterns
    re.compile(r"<[A-Z0-9_]+>"),
    re.compile(r"\[[A-Z0-9_]+\]"),
    re.compile(r"\{\{[A-Z0-9_]+\}\}"),
    re.compile(r"\$\{[A-Z0-9_]*\b(?:KEY|SECRET|TOKEN|PASSWORD)\b\}"),
    # Documentation references
    re.compile(r"^(?:#|//|--|;)\s*(?:TODO|FIXME|HACK|XXX)", re.I),
    re.compile(r"(?:example|sample|demo|test|placeholder|your)", re.I),
]

# Variable names that, when assigned, are likely not secrets
NON_SECRET_VAR_NAMES: List[re.Pattern] = [
    re.compile(r"(?i)^(?:host|port|user|name|email|path|dir|url|uri|version|debug|log_level|region|zone)$"),
    re.compile(r"(?i)^(?:username|hostname|dbname|db_host|db_port|db_name|app_name)$"),
]


# ──────────────────────────────────────────────────────────────────────
# Helper functions
# ──────────────────────────────────────────────────────────────────────

def is_whitelisted(value: str) -> bool:
    """Check if a matched value should be whitelisted (likely false positive)."""
    for pattern in WHITELIST_PATTERNS:
        if pattern.search(value):
            return True
    return False


def is_likely_comment_or_log(line: str) -> bool:
    """Check if a line is likely a comment, log message, or docstring reference."""
    stripped = line.strip()
    if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("/*"):
        return True
    if '"""' in stripped or "'''" in stripped:
        return True
    # Check if it's inside a multi-line string
    return False


def entropy_scan(value: str, var_name: str = "") -> Tuple[float, float]:
    """Scan a string value for entropy-based secret detection.

    Returns:
        Tuple of (entropy_score, confidence_adjustment).
        entropy_score > 3.5 suggests a high-entropy secret.
        confidence_adjustment is a multiplier (0.0-1.0).
    """
    entropy = shannon_entropy(value)

    # Skip short strings
    if len(value) < 12:
        return entropy, 0.0

    # Skip known low-risk high-entropy strings
    if is_low_risk_high_entropy(value):
        return entropy, 0.1

    # Base confidence from entropy level
    if entropy >= 4.5:
        confidence = 0.6  # Very high entropy — likely a secret
    elif entropy >= 3.5:
        confidence = 0.4  # Medium-high entropy — possible secret
    elif entropy >= 2.5:
        confidence = 0.2  # Moderate entropy — low confidence
    else:
        return entropy, 0.0  # Low entropy — not a secret

    # Boost confidence if variable name suggests it's a credential
    if var_name:
        for pattern in ENTROPY_TARGET_NAMES:
            if pattern.search(var_name):
                confidence = min(1.0, confidence + 0.3)
                break

    # Boost confidence for longer strings
    if len(value) >= 40:
        confidence = min(1.0, confidence + 0.15)
    elif len(value) >= 30:
        confidence = min(1.0, confidence + 0.1)

    # Check for mixed case, digits, and special chars
    has_upper = any(c.isupper() for c in value)
    has_lower = any(c.islower() for c in value)
    has_digit = any(c.isdigit() for c in value)
    has_special = any(not c.isalnum() for c in value)

    char_variety = sum([has_upper, has_lower, has_digit, has_special])
    if char_variety >= 4:
        confidence = min(1.0, confidence + 0.15)

    return entropy, confidence


# ──────────────────────────────────────────────────────────────────────
# Main scanning functions
# ──────────────────────────────────────────────────────────────────────

def scan_file(file_path: str, repo_root: str) -> List[Finding]:
    """Scan a single file for secrets using regex + entropy detection.

    Detection pipeline:
      1. Regex pattern matching (known secret formats)
      2. Entropy scoring for strings in credential-named variables
      3. Whitelist filtering (remove known false positives)
      4. Context-aware filtering (skip comments, logs)

    Args:
        file_path: Absolute path to the file to scan.
        repo_root: Root path of the repository.

    Returns:
        A list of findings for detected secrets.
    """
    findings: List[Finding] = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except (IOError, OSError):
        return findings

    rel_path = os.path.relpath(file_path, repo_root)

    for line_num, line in enumerate(lines, start=1):
        stripped_line = line.strip()

        # Skip comments, docstrings, and log messages
        if is_likely_comment_or_log(line):
            continue

        # ─── Phase 1: Regex pattern matching ──────────────────────────
        for rule in SECRET_PATTERNS:
            match = rule["pattern"].search(line)
            if not match:
                continue

            matched_text = match.group(0).strip()

            # Whitelist check
            if is_whitelisted(matched_text):
                continue

            # Truncate if too long
            snippet = matched_text[:80]

            finding = Finding(
                file_path=rel_path,
                line_number=line_num,
                issue_type="secret",
                severity=rule["severity"],
                message=rule["message"],
                rule_id=f"SEC-{rule['name']}",
                confidence=rule["confidence"],
                snippet=snippet,
                detection_method="regex",
                remediation_hint=rule.get("remediation", ""),
            )
            findings.append(finding)

            # For generic patterns, cross-verify with entropy to refine confidence
            if rule["name"] in ("generic-api-key", "generic-secret", "password-in-code"):
                entropy, entropy_conf = entropy_scan(matched_text)
                if entropy_conf > 0:
                    # Hybrid confidence: max of regex and entropy confidence
                    finding.confidence = max(finding.confidence, entropy_conf)
                    finding.detection_method = "hybrid"

        # ─── Phase 2: Entropy scanning ────────────────────────────────
        # Check variable assignments for high-entropy strings
        # Pattern: VAR_NAME = "string_value" or VAR_NAME: "string_value"
        assign_match = re.match(
            r"(?i)\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*['\"]([^'\"]{12,})['\"]",
            stripped_line,
        )
        if assign_match:
            var_name = assign_match.group(1)
            value = assign_match.group(2)

            # Skip non-secret variable names
            is_secret_var = any(p.search(var_name) for p in ENTROPY_TARGET_NAMES)
            is_non_secret = any(p.match(var_name) for p in NON_SECRET_VAR_NAMES)
            if is_non_secret and not is_secret_var:
                continue

            # Check if already detected by regex (avoid duplicate)
            already_found = any(
                f.line_number == line_num and f.file_path == rel_path
                for f in findings
            )
            if already_found:
                continue

            entropy, entropy_conf = entropy_scan(value, var_name)
            if entropy_conf >= 0.4:
                # Check whitelist before creating entropy finding
                if is_whitelisted(value):
                    continue
                suffix = " (high entropy)" if entropy >= 4.0 else ""
                finding = Finding(
                    file_path=rel_path,
                    line_number=line_num,
                    issue_type="secret",
                    severity=Severity.LOW if entropy_conf < 0.5 else Severity.MEDIUM,
                    message=f"High-entropy string detected in variable '{var_name}'{suffix}. This may be a credential or secret.",
                    rule_id="SEC-ENTROPY",
                    confidence=round(entropy_conf, 2),
                    snippet=value[:80],
                    detection_method="entropy",
                    remediation_hint="Verify this value is not a credential. If it is, use environment variables or a secrets manager.",
                )
                findings.append(finding)

    return findings


def scan(repo_root: str) -> List[Finding]:
    """Scan an entire repository for secrets.

    Args:
        repo_root: Root path of the repository to scan.

    Returns:
        A list of findings for detected secrets across all files.
    """
    # This function is kept for backward compatibility.
    # The engine.py orchestrator calls scan_file() directly with discovered files.
    from .file_discovery import discover_files

    findings: List[Finding] = []
    files = discover_files(repo_root)

    for rel_path in files:
        full_path = os.path.join(repo_root, rel_path)
        findings.extend(scan_file(full_path, repo_root))

    return findings
