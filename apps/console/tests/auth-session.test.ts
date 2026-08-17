import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { encode, decode } from "next-auth/jwt";
import { buildSession, runtimeUserToken } from "@/lib/auth";

// Provider ID tokens must be server-only: carried in the encrypted Auth.js
// session JWT, retrievable server-side via getToken, and absent from every
// public session surface (useSession / /api/auth/session / HTML / props).

const SECRET = "test-session-secret-0123456789abcdef0123456789abcdef";
const ID_TOKEN = "FAKE_IDP_ID_TOKEN_VALUE_MUST_NEVER_LEAK";
// Matches Auth.js's default non-secure session cookie salt (getToken's
// default when no salt is passed).
const SALT = "authjs.session-token";

describe("session JWT carries the provider id_token server-side", () => {
  it("encodes a session JWT containing the id_token", async () => {
    const cookie = await encode({
      token: { sub: "user-1", idToken: ID_TOKEN, roles: ["admin"], email: "admin@example.com" },
      secret: SECRET,
      salt: SALT,
    });
    expect(cookie).toBeTruthy();

    const decoded = await decode({ token: cookie, secret: SECRET, salt: SALT });
    expect(decoded).not.toBeNull();
    expect(decoded!.idToken).toBe(ID_TOKEN);
    expect(decoded!.roles).toContain("admin");
  });

  it("buildSession never exposes the id_token", async () => {
    const cookie = await encode({
      token: { sub: "user-1", idToken: ID_TOKEN, roles: ["auditor"] },
      secret: SECRET,
      salt: SALT,
    });
    const decoded = await decode({ token: cookie, secret: SECRET, salt: SALT });
    expect(decoded).not.toBeNull();
    const session = buildSession(decoded!);
    expect(session.user).toBeTruthy();

    expect("idToken" in session).toBe(false);
    expect(JSON.stringify(session)).not.toContain("idToken");
    // The raw token value must never appear in the serialized session.
    expect(JSON.stringify(session)).not.toContain(ID_TOKEN);
    // The session it would render through /api/auth/session keeps only
    // role/identity data.
    expect(session.user!.email).toBeUndefined();
    expect(session.user!.roles).toEqual(["auditor"]);
  });

  it("runtimeUserToken retrieves the id_token server-side from the cookie", async () => {
    const cookie = await encode({
      token: { sub: "user-1", idToken: ID_TOKEN, roles: ["admin"] },
      secret: SECRET,
      salt: SALT,
    });
    process.env.NEXTAUTH_SECRET = SECRET;
    try {
      const req = new Request("http://localhost/api/agents", {
        headers: { cookie: `authjs.session-token=${cookie}` },
      });
      const token = await runtimeUserToken(req);
      expect(token).toBe(ID_TOKEN);
    } finally {
      delete process.env.NEXTAUTH_SECRET;
    }
  });

  it("runtimeUserToken returns null with no session cookie", async () => {
    process.env.NEXTAUTH_SECRET = SECRET;
    try {
      const req = new Request("http://localhost/api/agents");
      const token = await runtimeUserToken(req);
      expect(token).toBeNull();
    } finally {
      delete process.env.NEXTAUTH_SECRET;
    }
  });
});

describe("public session surface never leaks the token", () => {
  it("the Session type serialization excludes idToken", async () => {
    const cookie = await encode({
      token: { sub: "user-2", idToken: ID_TOKEN, roles: ["viewer"], name: "Ada" },
      secret: SECRET,
      salt: SALT,
    });
    const decoded = await decode({ token: cookie, secret: SECRET, salt: SALT });
    expect(decoded).not.toBeNull();
    const session = buildSession(decoded!);
    const asJson = JSON.stringify(session);

    expect(asJson).not.toContain(ID_TOKEN);
    expect(asJson).not.toContain("idToken");
    expect(asJson).toContain('"roles":["viewer"]');
    expect(asJson).toContain("Ada");
  });
});