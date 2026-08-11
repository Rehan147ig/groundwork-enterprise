import { SignJWT, importPKCS8, type KeyLike } from "jose";

// Console assertion minting for the runtime's verified-identity
// middleware (X-Groundwork-User-Assertion).
//
// RS256 is the production path: the console holds the private key and
// the runtime only ever sees the matching public key, so compromising
// the runtime can never mint identities or impersonate users.
//   - GROUNDWORK_JWT_RS_PRIVATE_KEY        inline PKCS#8 PEM
//   - GROUNDWORK_JWT_RS_PRIVATE_KEY_FILE   path to a PKCS#8 PEM file
//
// HS256 (GROUNDWORK_JWT_HS_SECRET) remains for local/dev only — a
// shared secret that both sides hold. Key rotation: generate a new RSA
// key pair, publish the public key to the runtime, then replace the
// private key at the console (short-lived 10m assertions mean the
// rotation window is minutes, not hours).
//
// Returns null when no signing key is configured; callers must then
// fail closed (or explicitly opt into GROUNDWORK_DEMO_MODE=true).

export async function mintConsoleAssertion(subject: string): Promise<string | null> {
  const rsaKey = await rsaPrivateKey();
  const now = Math.floor(Date.now() / 1000);
  if (rsaKey) {
    return new SignJWT({})
      .setProtectedHeader({ alg: "RS256" })
      .setSubject(subject)
      .setIssuedAt(now)
      .setExpirationTime("10m")
      .sign(rsaKey);
  }
  const secret = process.env.GROUNDWORK_JWT_HS_SECRET ?? "";
  if (secret) {
    return new SignJWT({})
      .setProtectedHeader({ alg: "HS256" })
      .setSubject(subject)
      .setIssuedAt(now)
      .setExpirationTime("10m")
      .sign(new TextEncoder().encode(secret));
  }
  return null;
}

async function rsaPrivateKey(): Promise<KeyLike | null> {
  let pem = (process.env.GROUNDWORK_JWT_RS_PRIVATE_KEY ?? "").trim();
  if (!pem) {
    const path = process.env.GROUNDWORK_JWT_RS_PRIVATE_KEY_FILE ?? "";
    if (path) {
      const fs = await import("node:fs/promises");
      pem = (await fs.readFile(path, "utf8")).trim();
    }
  }
  if (!pem) return null;
  return importPKCS8(pem, "RS256");
}