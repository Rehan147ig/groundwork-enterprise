import { describe, it, expect, beforeEach, afterEach } from "vitest";
import path from "node:path";
import { resolveKeyFilePath, jwtKeysDir, mintConsoleAssertion } from "@/lib/jwt";

// GROUNDWORK_JWT_RS_PRIVATE_KEY_FILE must resolve inside the safe keys
// directory — the process can never be pointed at an arbitrary path via
// the environment.

function setKeysDir(dir: string) {
  process.env.GROUNDWORK_JWT_KEYS_DIR = dir;
}

beforeEach(() => {
  setKeysDir(path.join(process.cwd(), "keys"));
});

afterEach(() => {
  delete process.env.GROUNDWORK_JWT_KEYS_DIR;
  delete process.env.GROUNDWORK_JWT_RS_PRIVATE_KEY_FILE;
  delete process.env.GROUNDWORK_JWT_HS_SECRET;
});

describe("resolveKeyFilePath", () => {
  it("defaults the keys directory to <cwd>/keys", () => {
    expect(jwtKeysDir()).toBe(path.join(process.cwd(), "keys"));
  });

  it("accepts a relative path inside the keys directory", () => {
    const dir = jwtKeysDir();
    expect(resolveKeyFilePath("groundwork-rs.pem")).toBe(path.join(dir, "groundwork-rs.pem"));
  });

  it("accepts an absolute path inside the keys directory", () => {
    const dir = jwtKeysDir();
    const inside = path.join(dir, "nested", "groundwork-rs.pem");
    expect(resolveKeyFilePath(inside)).toBe(inside);
  });

  it("rejects an absolute path outside the keys directory", () => {
    expect(() => resolveKeyFilePath("C:\\Windows\\system32\\whatever.pem")).toThrow(/outside/);
  });

  it("rejects path traversal out of the keys directory", () => {
    expect(() => resolveKeyFilePath("..\\..\\secrets\\rs.pem")).toThrow(/outside/);
    expect(() => resolveKeyFilePath("..\\env.pem")).toThrow(/outside/);
  });
});

describe("mintConsoleAssertion key loading", () => {
  it("refuses to read a key file outside the keys directory", async () => {
    process.env.GROUNDWORK_JWT_RS_PRIVATE_KEY_FILE = "C:\\Windows\\system32\\keys\\jwt.pem";
    await expect(mintConsoleAssertion("console-admin")).rejects.toThrow(/outside/);
  });

  it("returns null when no signing key is configured", async () => {
    expect(await mintConsoleAssertion("console-admin")).toBeNull();
  });

  it("mints an HS256 assertion for local/dev when the shared secret is set", async () => {
    process.env.GROUNDWORK_JWT_HS_SECRET = "dev-shared-secret-that-is-long-enough-000";
    const token = await mintConsoleAssertion("console-operator");
    expect(token).toBeTruthy();
    expect(token!.split(".")).toHaveLength(3);
    const header = JSON.parse(Buffer.from(token!.split(".")[0], "base64url").toString());
    expect(header.alg).toBe("HS256");
  });
});