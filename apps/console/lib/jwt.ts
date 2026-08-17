import { SignJWT, importPKCS8, type KeyLike } from "jose";
import path from "node:path";

// Console assertion minting for the runtime's verified-identity
// middleware (X-Groundwork-User-Assertion).
//
// RS256 is the production path: the console holds the private key and
// the runtime only ever sees the matching public key, so compromising
// the runtime can never mint identities or impersonate users.
//   - GROUNDWORK_JWT_RS_PRIVATE_KEY        inline PKCS#8 PEM
//   - GROUNDWORK_JWT_RS_PRIVATE_KEY_FILE   path to a PKCS#8 PEM file
//
// Key files are constrained to a safe known directory so Next.js can
// trace the filesystem dependency at build time and the process can
// never be pointed at an arbitrary path via the environment:
//   - GROUNDWORK_JWT_KEYS_DIR              allowed directory (default: <cwd>/keys)
//   - GROUNDWORK_JWT_RS_PRIVATE_KEY_FILE   must resolve inside it
//                                          (relative paths resolve against it;
//                                          absolute paths outside it are rejected)
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

// keysDir returns the only directory private key files may be read from.
// Defaults to <cwd>/keys so Next's build-time filesystem tracing has a
// fixed, bounded location to scan.
export function jwtKeysDir(): string {
  const dir = (process.env.GROUNDWORK_JWT_KEYS_DIR ?? "").trim();
  return dir ? path.resolve(dir) : path.join(process.cwd(), "keys");
}

// resolveKeyFilePath constrains GROUNDWORK_JWT_RS_PRIVATE_KEY_FILE to
// the keys directory. Relative paths resolve inside it; absolute paths
// outside it are rejected (throw) rather than reading an arbitrary
// location named by the environment.
export function resolveKeyFilePath(candidate: string): string {
  const dir = jwtKeysDir();
  const resolved = path.isAbsolute(candidate) ? candidate : path.join(dir, candidate);
  const normalized = path.normalize(resolved);
  const dirPrefix = dir.endsWith(path.sep) ? dir : dir + path.sep;
  if (normalized !== dir && !normalized.startsWith(dirPrefix)) {
    throw new Error(
      `GROUNDWORK_JWT_RS_PRIVATE_KEY_FILE "${candidate}" resolves outside GROUNDWORK_JWT_KEYS_DIR (${dir}); refusing to read it.`,
    );
  }
  return normalized;
}

async function rsaPrivateKey(): Promise<KeyLike | null> {
  let pem = (process.env.GROUNDWORK_JWT_RS_PRIVATE_KEY ?? "").trim();
  if (!pem) {
    const candidate = process.env.GROUNDWORK_JWT_RS_PRIVATE_KEY_FILE ?? "";
    if (candidate) {
      const fs = await import("node:fs/promises");
      pem = (await fs.readFile(resolveKeyFilePath(candidate), "utf8")).trim();
    }
  }
  if (!pem) return null;
  return importPKCS8(pem, "RS256");
}