import NextAuth from "next-auth";
import type { NextAuthConfig, Session } from "next-auth";
import { getToken, type JWT } from "next-auth/jwt";
import type { OIDCConfig, Provider } from "next-auth/providers";

// Profile shape of a generic OIDC IdP (Okta / Entra v2 / Google all
// expose these standard claims on the identity token / userinfo).
interface IdPProfile {
  sub?: string;
  name?: string;
  email?: string;
  picture?: string;
  preferred_username?: string;
  roles?: string[];
}

// Enterprise OIDC/OAuth2 authentication for the console.
//
// One generic OpenID Connect provider is parameterized entirely from the
// environment, so it works against any standards-compliant issuer:
//
//   - Okta              (classic or workforce OIDC app)
//   - Entra ID / Azure AD (OIDC app, v2 endpoint)
//   - Google Workspace  (OAuth client with OpenID Connect enabled)
//
// All three publish a discovery document (/.well-known/
// openid-configuration), so NextAuth derives authorization/token/JWKS
// endpoints automatically. Client credentials never leave the server:
//
//   NEXTAUTH_SECRET        session-cookie signing/encryption key (AES-GCM + HMAC)
//   OIDC_ISSUER            IdP issuer URL (Okta tenant, Entra .../v2.0, Google accounts.google.com)
//   OIDC_CLIENT_ID         IdP application/client id
//   OIDC_CLIENT_SECRET     IdP application secret
//   NEXTAUTH_URL           optional: public console URL (trustHost covers local dev)
//
// Sessions use the JWT strategy: the browser cookie holds an encrypted,
// HMAC-signed JWT derived from NEXTAUTH_SECRET. The one-time IdP id_token
// is carried ONLY inside the session JWT (token.idToken), never in the
// public Session object. Server code retrieves it via runtimeUserToken()
// (getToken decodes the encrypted cookie) and forwards it to the
// Groundwork Go runtime as `Authorization: Bearer <id_token>` — the
// runtime validates the signature against the IdP's JWKS itself, so the
// console never mints identities for enterprise users. Because the
// id_token never appears on the Session, it cannot leak through
// useSession(), /api/auth/session, rendered HTML, or React props.
//
// When OIDC credentials are absent (local demo stacks), the provider
// list is empty and demo-mode persona auth continues to work.

function requiredOIDCConfig() {
  const issuer = (process.env.OIDC_ISSUER ?? "").trim();
  const clientId = (process.env.OIDC_CLIENT_ID ?? "").trim();
  const clientSecret = (process.env.OIDC_CLIENT_SECRET ?? "").trim();
  if (!issuer || !clientId || !clientSecret) return null;
  return { issuer, clientId, clientSecret };
}

export function oidcConfigured(): boolean {
  return requiredOIDCConfig() !== null;
}

export function demoMode(): boolean {
  return process.env.GROUNDWORK_DEMO_MODE === "true";
}

// The generic OIDC provider. This @auth/core build ships dedicated Okta /
// Entra / Google helpers; the generic one is assembled from the exported
// OIDCConfig type (identically shaped) so ONE provider serves every
// standards-compliant issuer selected at deploy time.
function oidcProvider(): Provider {
  const oidc = requiredOIDCConfig();
  if (!oidc) {
    throw new Error("oidcProvider() called without OIDC_ISSUER/OIDC_CLIENT_ID/OIDC_CLIENT_SECRET");
  }
  const provider: OIDCConfig<IdPProfile> & { type: "oidc" } = {
    id: "oidc",
    name: "OpenID Connect",
    type: "oidc",
    issuer: oidc.issuer,
    clientId: oidc.clientId,
    clientSecret: oidc.clientSecret,
    authorization: { params: { scope: "openid profile email" } },
    profile(profile) {
      const name =
        (profile.name as string | undefined) ??
        (profile.preferred_username as string | undefined) ??
        (profile.email as string | undefined);
      return {
        id: profile.sub ?? profile.email ?? "",
        name: name ?? undefined,
        email: profile.email ?? undefined,
        image: profile.picture ?? undefined,
      };
    },
  };
  return provider as Provider;
}

// Auth.js v5: `session: { strategy: "jwt" }` stores a signed+encrypted JWT
// session cookie (keys derived from NEXTAUTH_SECRET). Decode it server-side
// with `decode` from "next-auth/jwt" — the verification flow does exactly
// that to prove the session token is correctly signed.
export const authConfig: NextAuthConfig = {
  secret: process.env.NEXTAUTH_SECRET || process.env.AUTH_SECRET,
  trustHost: true,
  session: { strategy: "jwt", maxAge: 8 * 60 * 60 }, // 8h; the raw id_token's own exp still gates the runtime
  providers: oidcConfigured() ? [oidcProvider()] : [],
  callbacks: {
    async jwt({ token, account, profile }) {
      // Carry the IdP-verified id_token through the session JWT so route
      // handlers can forward it to the runtime without touching the IdP.
      if (account?.id_token) token.idToken = account.id_token as string;
      if (profile && "roles" in profile) {
        token.roles = (profile.roles as string[] | undefined) ?? [];
      }
      return token;
    },
    async session({ session, token }) {
      // Public Session shape — deliberately excludes the id_token (it
      // stays inside the encrypted session JWT and is read server-side
      // via runtimeUserToken/getToken).
      session.user.name = (token.name as string | undefined) ?? session.user.name;
      session.user.email = (token.email as string | undefined) ?? session.user.email;
      session.user.image = (token.picture as string | undefined) ?? session.user.image;
      session.user.roles = (token.roles as string[] | undefined) ?? [];
      return session;
    },
  },
};

export const { handlers, auth, signIn, signOut } = NextAuth(authConfig);

// Builds the public Session from a decoded session JWT. Exported so tests
// can prove the id_token never reaches the serialized session surface.
export function buildSession(token: JWT): Session {
  return {
    expires: new Date(
      token.exp ? token.exp * 1000 : Date.now() + 8 * 60 * 60 * 1000,
    ).toISOString(),
    user: {
      id: (token.sub as string | undefined) ?? "",
      name: (token.name as string | undefined) ?? undefined,
      email: (token.email as string | undefined) ?? undefined,
      image: (token.picture as string | undefined) ?? undefined,
      roles: (token.roles as string[] | undefined) ?? [],
    },
  };
}

// runtimeUserToken returns the verified user's OIDC id_token for the
// current request, or null when the caller is unauthenticated. The token
// is read from the encrypted session cookie (Auth.js getToken) — never
// from the Session object — so it stays server-only. Route handlers embed
// it as: Authorization: Bearer <id_token>.
export async function runtimeUserToken(req?: Request | Headers): Promise<string | null> {
  try {
    // getToken accepts a Request or an object exposing `.headers`; a
    // caller-supplied Request contributes its own headers, otherwise the
    // Next headers() accessor is used.
    const source = req ?? (await currentHeaders());
    const headersLike = source instanceof Request ? source.headers : source;
    const token = await getToken({
      req: { headers: headersLike as unknown as Headers },
      secret: process.env.NEXTAUTH_SECRET || process.env.AUTH_SECRET,
    });
    return (token?.idToken as string | undefined) ?? null;
  } catch {
    return null;
  }
}

// currentHeaders lazily imports next/headers. next/headers is server-only:
// importing it at module scope would mark this whole module server-only and
// break any import from client-component graphs at build time. The dynamic
// import only ever executes inside a server request context.
async function currentHeaders(): Promise<Headers> {
  const { headers } = await import("next/headers");
  return headers();
}

// Declare the extended session/user shape used above. NOTE: Session
// deliberately has no idToken field — the raw token must never cross the
// client boundary (useSession / /api/auth/session / HTML / React props).
declare module "next-auth" {
  interface Session {
    // idToken is intentionally absent: provider tokens stay server-only.
  }
  interface User {
    roles?: string[];
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    idToken?: string;
    roles?: string[];
  }
}

export type { Session as AuthSession, JWT as AuthJWT };