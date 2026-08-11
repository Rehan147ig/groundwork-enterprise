"""Demo/console user assertion minting (HS256 JWT).

Only for local development and first-party console flows; production
integrations receive end-user assertions from the enterprise OIDC
provider instead. Uses only the standard library (hmac + base64).
"""

import base64
import hashlib
import hmac
import json
import time


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def mint_user_assertion(
    hs_secret: str,
    subject: str,
    tenant_id: str,
    roles=None,
    ttl_seconds: int = 300,
) -> str:
    """Mint an HS256 JWT signed with the runtime's GROUNDWORK_JWT_HS_SECRET.

    Mirrors the TypeScript ``mintUserAssertion`` helper claim-for-claim.
    """
    if roles is None:
        roles = ["console-admin"]
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload = {
        "sub": subject,
        "iss": "groundwork-console",
        "aud": "groundwork-query-runtime",
        "tenant_id": tenant_id,
        "roles": roles,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    signing_input = "%s.%s" % (
        _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8")),
        _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8")),
    )
    signature = hmac.new(
        hs_secret.encode("utf-8"),
        signing_input.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return "%s.%s" % (signing_input, _b64url(signature))
