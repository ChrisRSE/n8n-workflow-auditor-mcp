"""Credential hygiene rules: CRED001–CRED004."""

import re
from datetime import UTC
from typing import Any

from .base import Finding, Rule, Severity

# ---------------------------------------------------------------------------
# CRED001 helpers
# ---------------------------------------------------------------------------

# Known API-key prefixes that are unambiguous secrets
_KNOWN_SECRET_PREFIXES: list[str] = [
    "sk-",  # OpenAI / Stripe
    "sk-proj-",  # OpenAI project keys
    "ghp_",  # GitHub personal access token
    "gho_",  # GitHub OAuth token
    "ghu_",  # GitHub user-to-server token
    "ghs_",  # GitHub server-to-server token
    "ghr_",  # GitHub refresh token
    "xoxb-",  # Slack bot token
    "xoxp-",  # Slack user token
    "xoxa-",  # Slack app token
    "xoxs-",  # Slack socket token
    "AKIA",  # AWS access key ID
    "AIza",  # Google API key
    "ya29.",  # Google OAuth2 access token
    "eyJ",  # JWT (base64 header {"alg":...) — catches hardcoded JWTs
    "SG.",  # SendGrid API key
    "AC",  # Twilio Account SID (followed by 32 hex chars)
    "SK",  # Twilio API key SID
]

# Parameter names that strongly suggest the value is a secret
_SECRET_PARAM_NAMES: set[str] = {
    "password",
    "secret",
    "apikey",
    "api_key",
    "accesstoken",
    "access_token",
    "privatekey",
    "private_key",
    "clientsecret",
    "client_secret",
    "authtoken",
    "auth_token",
    "bearertoken",
    "bearer_token",
    "secretkey",
    "secret_key",
    "webhook_secret",
    "webhooksecret",
}

# Regex: 20+ char alphanumeric strings that look like opaque tokens
_HIGH_ENTROPY_RE = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")


_AUTH_HEADER_PREFIXES = ("Bearer ", "Token ", "Basic ", "ApiKey ", "bot ")


def _strip_auth_header_prefix(value: str) -> str:
    """Remove common HTTP auth header scheme words before checking for secret prefixes."""
    for prefix in _AUTH_HEADER_PREFIXES:
        if value.startswith(prefix):
            return value[len(prefix) :]
    return value


def _looks_like_secret_by_prefix(value: str) -> bool:
    candidate = _strip_auth_header_prefix(value)
    return any(candidate.startswith(prefix) for prefix in _KNOWN_SECRET_PREFIXES)


def _is_expression(value: str) -> bool:
    """n8n expression — not a hardcoded literal."""
    stripped = value.strip()
    return stripped.startswith("={{") or stripped.startswith("{{")


def _collect_params(obj: Any, path: str = "") -> list[tuple[str, Any]]:
    """Recursively yield (dot-path, value) pairs from a nested parameters dict."""
    results: list[tuple[str, Any]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            results.extend(_collect_params(v, f"{path}.{k}" if path else k))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            results.extend(_collect_params(item, f"{path}[{i}]"))
    else:
        results.append((path, obj))
    return results


# ---------------------------------------------------------------------------
# CRED004 helpers — over-permissive Google OAuth scope detection
# ---------------------------------------------------------------------------

# Maps n8n node type → the narrow credential type that should be used.
# If the node uses the broad "googleApi" instead, flag CRED004.
_GOOGLE_NODE_PREFERRED_CRED: dict[str, str] = {
    "n8n-nodes-base.googleSheets": "googleSheetsOAuth2Api",
    "n8n-nodes-base.gmail": "gmailOAuth2",
    "n8n-nodes-base.googleCalendar": "googleCalendarOAuth2Api",
    "n8n-nodes-base.googleDrive": "googleDriveOAuth2Api",
    "n8n-nodes-base.googleDocs": "googleDocsOAuth2Api",
    "n8n-nodes-base.googleSlides": "googleSlidesOAuth2Api",
    "n8n-nodes-base.googleBigQuery": "googleBigQueryOAuth2Api",
    "n8n-nodes-base.googleAnalytics": "googleAnalyticsOAuth2Api",
}

_BROAD_GOOGLE_CRED_TYPES: set[str] = {"googleApi", "googleOAuth2Api"}


# ---------------------------------------------------------------------------
# Rule implementations
# ---------------------------------------------------------------------------


class CredentialHardcoded(Rule):
    """CRED001 — Hardcoded credentials in node parameters.

    Scans literal string values in node parameters for known secret patterns.
    n8n expression syntax ({{ ... }}) is excluded (see DECISION-001).
    """

    rule_id = "CRED001"

    def check(self, workflow: dict) -> list[Finding]:
        findings: list[Finding] = []
        for node in workflow.get("nodes", []):
            node_id = node.get("id", "")
            node_name = node.get("name", "")
            params = node.get("parameters", {})

            for param_path, value in _collect_params(params):
                if not isinstance(value, str) or not value.strip():
                    continue
                if _is_expression(value):
                    continue

                param_key_lower = param_path.split(".")[-1].lower()
                flagged = False
                reason = ""

                candidate = _strip_auth_header_prefix(value)
                if _looks_like_secret_by_prefix(value):
                    flagged = True
                    reason = "value matches a known API key prefix"
                elif param_key_lower in _SECRET_PARAM_NAMES and len(value) >= 8:
                    flagged = True
                    reason = f"parameter name '{param_key_lower}' suggests a secret"

                if flagged:
                    # Redact most of the value; use the stripped candidate so the prefix is visible
                    display = candidate[:6] + "***" if len(candidate) > 6 else "***"
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=Severity.CRITICAL,
                            node_id=node_id,
                            node_name=node_name,
                            message=(
                                f"Node '{node_name}' has a hardcoded credential in "
                                f"parameter '{param_path}'."
                            ),
                            evidence=f"Parameter path: {param_path} | Value starts with: {display} | Reason: {reason}",
                        )
                    )
        return findings


class CredentialOAuthExpiry(Rule):
    """CRED002 — OAuth credential referenced; expiry cannot be verified statically.

    When a workflow is exported without embedded credential data, OAuth token
    validity cannot be checked.  This rule flags all OAuth credential references
    so the user knows to verify them out-of-band.  When ``oauthTokenData`` is
    present in the exported credential, an expired ``expirationDate`` is flagged
    as CRITICAL instead.
    """

    rule_id = "CRED002"

    _OAUTH_CRED_SUFFIXES = ("OAuth2Api", "OAuth2", "OAuthApi", "OAuthCredentials")

    def _is_oauth_type(self, cred_type: str) -> bool:
        return any(cred_type.endswith(suffix) for suffix in self._OAUTH_CRED_SUFFIXES)

    def check(self, workflow: dict) -> list[Finding]:
        findings: list[Finding] = []
        for node in workflow.get("nodes", []):
            node_id = node.get("id", "")
            node_name = node.get("name", "")
            creds = node.get("credentials", {})
            if not isinstance(creds, dict):
                continue

            for cred_type, cred_ref in creds.items():
                if not self._is_oauth_type(cred_type):
                    continue

                cred_name = (
                    cred_ref.get("name", cred_type) if isinstance(cred_ref, dict) else cred_type
                )

                # If credential data is embedded (unusual but possible in some exports)
                token_data = (
                    cred_ref.get("oauthTokenData", {}) if isinstance(cred_ref, dict) else {}
                )
                expiry = token_data.get("expiration_date") or token_data.get("expirationDate")

                if expiry:
                    # Only import datetime when needed
                    from datetime import datetime

                    try:
                        if isinstance(expiry, int | float):
                            exp_dt = datetime.fromtimestamp(expiry / 1000, tz=UTC)
                        else:
                            exp_dt = datetime.fromisoformat(str(expiry).replace("Z", "+00:00"))

                        now = datetime.now(tz=UTC)
                        if exp_dt < now:
                            findings.append(
                                Finding(
                                    rule_id=self.rule_id,
                                    severity=Severity.CRITICAL,
                                    node_id=node_id,
                                    node_name=node_name,
                                    message=(
                                        f"Node '{node_name}' uses OAuth credential '{cred_name}' "
                                        f"whose token has expired."
                                    ),
                                    evidence=f"Credential type: {cred_type} | Expiry: {exp_dt.isoformat()}",
                                )
                            )
                            continue
                    except (ValueError, TypeError, OSError):
                        pass

                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=Severity.INFO,
                        node_id=node_id,
                        node_name=node_name,
                        message=(
                            f"Node '{node_name}' uses OAuth credential '{cred_name}'. "
                            f"Token validity cannot be verified from static workflow JSON."
                        ),
                        evidence=f"Credential type: {cred_type} | Credential name: {cred_name}",
                    )
                )
        return findings


class CredentialNotConfigured(Rule):
    """CRED003 — Credential referenced but not configured.

    A node's ``credentials`` block lists a credential with a missing or
    empty ``id``, suggesting the credential was never set up in this n8n
    environment.
    """

    rule_id = "CRED003"

    def check(self, workflow: dict) -> list[Finding]:
        findings: list[Finding] = []
        for node in workflow.get("nodes", []):
            node_id = node.get("id", "")
            node_name = node.get("name", "")
            creds = node.get("credentials", {})
            if not isinstance(creds, dict):
                continue

            for cred_type, cred_ref in creds.items():
                if not isinstance(cred_ref, dict):
                    continue

                cred_id = cred_ref.get("id")
                cred_name = cred_ref.get("name", cred_type)

                if not cred_id or str(cred_id).strip() == "":
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=Severity.HIGH,
                            node_id=node_id,
                            node_name=node_name,
                            message=(
                                f"Node '{node_name}' references credential '{cred_name}' "
                                f"({cred_type}) but the credential has no ID — it may not be configured."
                            ),
                            evidence=f"Credential type: {cred_type} | Credential ref: {cred_ref}",
                        )
                    )
        return findings


class CredentialOverPermissiveScope(Rule):
    """CRED004 — Over-permissive API scope.

    Detects Google service nodes that use the broad ``googleApi`` credential
    type instead of the narrower service-specific OAuth2 credential.
    """

    rule_id = "CRED004"

    def check(self, workflow: dict) -> list[Finding]:
        findings: list[Finding] = []
        for node in workflow.get("nodes", []):
            node_type = node.get("type", "")
            preferred = _GOOGLE_NODE_PREFERRED_CRED.get(node_type)
            if not preferred:
                continue

            node_id = node.get("id", "")
            node_name = node.get("name", "")
            creds = node.get("credentials", {})
            if not isinstance(creds, dict):
                continue

            for cred_type in creds:
                if cred_type in _BROAD_GOOGLE_CRED_TYPES:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=Severity.MEDIUM,
                            node_id=node_id,
                            node_name=node_name,
                            message=(
                                f"Node '{node_name}' ({node_type}) uses the broad credential type "
                                f"'{cred_type}'. Prefer the narrower '{preferred}' to limit scope."
                            ),
                            evidence=(
                                f"Node type: {node_type} | "
                                f"Current credential: {cred_type} | "
                                f"Recommended: {preferred}"
                            ),
                        )
                    )
        return findings
