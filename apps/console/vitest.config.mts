import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL(".", import.meta.url));

export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
    server: {
      // next-auth (CJS) imports "next/server" which Node's ESM loader
      // cannot resolve without an exports map; processing it through Vite
      // fixes the subpath resolution.
      deps: { inline: ["next-auth"] },
    },
  },
  resolve: {
    alias: {
      "@": root,
      // "server-only" throws when imported outside a React Server
      // Component; tests run in plain node, so stub it empty.
      "server-only": `${root}tests/helpers/server-only.ts`,
    },
  },
});