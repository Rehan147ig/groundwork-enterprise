# Entra ID (Azure AD) OIDC Setup Guide

This guide covers configuring Microsoft Entra ID as the OIDC identity
provider for the Groundwork console and runtime. The runtime validates
every end-user identity assertion against the Entra JWKS directly —
the console never mints identities.

## 1. Create the App Registration

1. Sign in to the [Azure portal](https://portal.azure.com) →
   **Microsoft Entra ID** → **App registrations** → **New registration**.
2. **Name**: `Groundwork Console` (or your product name).
3. **Supported account types**: choose **Single tenant** (recommended —
   Groundwork maps the `tid` claim to tenant-scoped enforcement).
4. **Redirect URI (Web)**: `https://<console-host>/api/auth/callback/oidc`.
   For local development: `http://localhost:3000/api/auth/callback/oidc`.
5. Click **Register**. Record the **Application (client) ID** and
   **Directory (tenant) ID** — the tenant ID is the Groundwork tenant
   claim value.

## 2. Create a Client Secret

1. **Certificates & secrets** → **New client secret**.
2. Description: `groundwork-console`, expiry: **12 months or less**
   (key rotation is handled by issuing a new secret and updating the
   deployment; Groundwork never caches the secret).
3. Record the secret value immediately — it is shown only once.

## 3. Configure the Token (ID Token) Claims

Groundwork needs three claims on the **ID token**:

| Claim | Requirement | Notes |
|-------|-------------|-------|
| `sub` | default | Canonical user id (default claim). |
| `tid` | default | Tenant id. Map it to your Groundwork tenant allow-list. |
| `roles` | optional, for admin mapping | Application role or group claim. |

To emit roles:

1. **App registrations** → your app → **App roles** → **Create app role**:
   - `security-admin` (or your admin role name) — allowed member types:
     **Users/Groups/Applications**.
2. **Enterprise applications** → your app → **Users and groups** →
   assign users/groups to the `security-admin` role.
3. **Token configuration** → **Add groups claim** if you prefer group
   claims over app roles. Groundwork's `roles` claim parsing accepts
   arrays of strings; Entra group IDs are opaque, so prefer app roles
   with human-readable values.

## 4. Runtime Configuration

```powershell
# Runtime (services/query-runtime)
$env:GROUNDWORK_OIDC_ISSUER        = "https://login.microsoftonline.com/<tenant-id>/v2.0"
$env:GROUNDWORK_OIDC_CLIENT_ID     = "<application-client-id>"
$env:GROUNDWORK_OIDC_TENANT_CLAIM  = "tid"
$env:GROUNDWORK_OIDC_TENANT_ALLOWLIST = "<tenant-id>"   # must be explicit with allow-list
$env:GROUNDWORK_OIDC_ADMIN_ROLES_CLAIM = "roles"
$env:GROUNDWORK_OIDC_ADMIN_ROLES   = "security-admin"
```

The issuer URL must exactly match the `iss` claim emitted by Entra for
the v2.0 endpoint: `https://login.microsoftonline.com/{tenant-id}/v2.0`.

## 5. Console Configuration

```powershell
# Console (apps/console)
$env:OIDC_ISSUER        = "https://login.microsoftonline.com/<tenant-id>/v2.0"
$env:OIDC_CLIENT_ID     = "<application-client-id>"
$env:OIDC_CLIENT_SECRET = "<client-secret>"
$env:NEXTAUTH_SECRET    = "<32+ byte random string>"
$env:NEXTAUTH_URL       = "https://<console-host>"
```

The console requests `openid profile email` scopes. Entra issues an ID
token the runtime verifies with its own JWKS fetch.

## 6. Security Notes

- **Token lifetime**: the default ID token lifetime (60 minutes) is
  fine. The console session cookie is 8 hours, but the raw ID token's
  `exp` still gates every runtime call — sessions refresh via
  `maxAge` revalidation.
- **Key rotation**: Entra rotates signing keys automatically. The
  runtime refreshes JWKS on an unknown `kid` and uses stale-while-error
  for known kids, so rotation does not interrupt traffic.
- **Redirect URI**: must be HTTPS in production. The console never
  sends raw tokens to browser JavaScript; only server route handlers
  forward the ID token to the runtime.
- **Fail closed**: an unreachable issuer or mismatched discovery
  document fails runtime startup, and every verification failure
  rejects the request.