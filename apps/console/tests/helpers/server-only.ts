// Vitest stub for the `server-only` package: the real package throws when
// imported outside a React Server Component, which would break tests that
// exercise server-only modules (consoleAuth, auth). Under Next.js the real
// package still enforces server-only usage; this stub is only wired into
// the vitest resolve alias.
export {};
