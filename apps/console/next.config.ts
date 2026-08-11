import type { NextConfig } from "next";
import path from "node:path";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  turbopack: {
    root: path.resolve(__dirname, "../.."),
  },
  // Baseline security headers on every console response. The console is a
  // same-origin admin UI: framing is never needed (clickjacking), MIME
  // sniffing must stay off, referers must not leak query terms, and
  // nothing may be cached by intermediaries. HSTS is sent only in
  // production builds — localhost over http must keep working for dev.
  async headers() {
    const hsts =
      process.env.NODE_ENV === "production"
        ? [{ key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" }]
        : [];
    return [
      {
        source: "/:path*",
        headers: [
          ...hsts,
          { key: "X-Frame-Options", value: "DENY" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), usb=(), payment=()" },
          {
            key: "Content-Security-Policy",
            // App Router injects inline scripts/styles, so 'unsafe-inline'
            // is required for script-src/style-src unless nonce support is
            // added (see docs/threat-model.md for the hardening path).
            value: [
              "default-src 'self'",
              "script-src 'self' 'unsafe-inline'",
              "style-src 'self' 'unsafe-inline'",
              "img-src 'self' data: blob:",
              "font-src 'self' data:",
              "connect-src 'self' http://localhost:8080 ws://localhost:8080 http://localhost:8090",
              "frame-ancestors 'none'",
              "base-uri 'self'",
              "form-action 'self'",
            ].join("; "),
          },
          { key: "Cache-Control", value: "no-store" },
        ],
      },
    ];
  },
};

export default nextConfig;