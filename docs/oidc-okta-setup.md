# Okta OIDC Setup Guide

This guide covers configuring Okta as the OIDC identity provider for the
Groundwork console and runtime. The runtime validates every end-user
identity assertion against the Okta JWKS directly — the console never
mints identities.

## 1. Create the OIDC Application

1. Sign in to the Okta Admin Console → **Applications** → **Applications** →
   **Create App Integration**.
2. Sign-in method: **OIDC - OpenID Connect**.
3. Application type: **Web Application**.
4. **App integration name**: `Groundwork Console`.
5. **Grant type**: **Authorization Code** (PKCE enabled by default).
6. **Sign-in redirect URIs**: `https://<console-host>/api/auth/callback/oidc`.
   For local development: `http://localhost:3000/api/auth/callback/oidc`.
7. **Sign-out redirect URIs**: optional; the console host.
8. **Controlled access**: **Allow everyone in your organization** (or a
   group assignment policy).
9. Click **Save**. Record the **Client ID** and **Client secret** (the
   client secret is shown once).

## 2. Configure the Authorization Server (Issuer)

Groundwork expects a standard OIDC issuer. The default Okta
authorization server is:

```
https://<your-org>.okta.com/oauth2/default
```

Issuer discovery (`/.well-known/openid-configuration`) is automatic;
Groundwork validates the `iss` claim exactly.

## 3. Map the Roles Claim

Okta does not emit roles on the ID token by default. Two options:

### Option A: Okta Groups Claim (recommended)

1. **Security** → **API** → your authorization server →
   **Claims** → **Add Claim**.
2. Name: `groups`.
3. Include in token type: **ID Token** (and Access Token if desired).
4. Value type: **Groups** → filter: `Matches regex` → `.*` (all groups).
5. Claim name in token: `roles` (Groundwork reads the `roles` claim by
   default) — or configure `GROUNDWORK_OIDC_ADMIN_ROLES_CLAIM=groups`.

### Option B: Static app roles claim

1. **Security** → **API** → your authorization server →
   **Claims** → **Add Claim**.
2. Name: `roles`, include in **ID Token**.
3. Value type: **Expression**, expression: `appuser.roles`
   (requires a profile attribute) or a static array such as
   `["security-admin"]` scoped by a group policy.

Assign groups that should be admin to the `security-admin` Okta group
and emit it via the groups claim; then map:

```powershell
$env:GROUNDWORK_OIDC_ADMIN_ROLES_CLAIM = "roles"
$env:GROUNDWORK_OIDC_ADMIN_ROLES       = "security-admin"
```

## 4. Runtime Configuration

```powershell
# Runtime (services/query-runtime)
$env:GROUNDWORK_OIDC_ISSUER        = "https://<your-org>.okta.com/oauth2/default"
$env:GROUNDWORK_OIDC_CLIENT_ID     = "<client-id>"
$env:GROUNDWORK_OIDC_TENANT_CLAIM  = "tenant"       # dedicated tenant claim (see below)
$env:GROUNDWORK_OIDC_TENANT_ALLOWLIST = "acme"      # optional: restrict to known tenants
$env:GROUNDWORK_OIDC_ADMIN_ROLES_CLAIM = "roles"
$env:GROUNDWORK_OIDC_ADMIN_ROLES   = "security-admin"
```

**Never use `sub` as the tenant claim.** `sub` is the per-user subject
identifier; it is *not* a tenant identifier. Two Okta orgs can issue the
same `sub` value for different users, so binding a tenant to `sub`
would let a user from another org land in your tenant. The runtime
refuses `GROUNDWORK_OIDC_TENANT_CLAIM=sub` at startup (fail closed).

Okta's default authorization server has no `tid` claim. Configure a
dedicated tenant claim on the authorization server:

1. **Security** → **API** → your authorization server → **Claims** →
   **Add Claim**.
2. Name: `tenant`, include in **ID Token**.
3. Value type: **Expression**, expression `"acme"` (your org slug) — or
   map it from a profile attribute with a group policy.
4. Set `GROUNDWORK_OIDC_TENANT_CLAIM=tenant` (and
   `GROUNDWORK_OIDC_TENANT_ALLOWLIST=acme`).

### Issuer binding (org isolation)

The authorization server's issuer URL (`https://<your-org>.okta.com/oauth2/default`)
is itself org-unique and is validated exactly. A deployment with a
single Okta org can rely on the issuer for org isolation; the tenant
claim is then informational. **Multi-org deployments (multiple Okta
orgs, or Okta plus another provider) must configure the dedicated
tenant claim and an allowlist — never `sub`, never rely on `iss`
alone.**

## 5. Console Configuration

```powershell
# Console (apps/console)
$env:OIDC_ISSUER        = "https://<your-org>.okta.com/oauth2/default"
$env:OIDC_CLIENT_ID     = "<client-id>"
$env:OIDC_CLIENT_SECRET = "<client-secret>"
$env:NEXTAUTH_SECRET    = "<32+ byte random string>"
$env:NEXTAUTH_URL       = "https://<console-host>"
```

## 6. Security Notes

- **Token lifetime**: default Okta ID token lifetime (60 minutes) is
  fine. The console session cookie is 8 hours, but the raw ID token's
  `exp` still gates every runtime call.
- **Key rotation**: Okta rotates signing keys automatically; the
  runtime refreshes JWKS on unknown `kid` and uses stale-while-error
  for known kids.
- **Redirect URI**: must be HTTPS in production. The console never
  sends raw tokens to browser JavaScript; only server route handlers
  forward the ID token to the runtime.
- **Fail closed**: an unreachable issuer or mismatched discovery
  document fails runtime startup, and every verification failure
  rejects the request.