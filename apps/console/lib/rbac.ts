// Role-based access control for the console UI. Roles arrive in the OIDC
// id_token `roles` claim and are surfaced as session.user.roles by
// lib/auth.ts. Unknown or missing claims never elevate: they fall back to
// the least-privileged role (viewer).

export type ConsoleRole = "admin" | "auditor" | "viewer";

export type ConsolePermission =
  | "query"
  | "leak-report"
  | "break-glass"
  | "tenant-settings"
  | "audit-verify"
  | "compliance-exports"
  | "query-simulation"
  | "agents-read"
  | "agents-manage"
  | "governance-read"
  | "governance-manage"
  | "connect";

export const ROLE_PERMISSIONS: Record<ConsoleRole, readonly ConsolePermission[]> = {
  admin: [
    "query",
    "leak-report",
    "break-glass",
    "tenant-settings",
    "audit-verify",
    "compliance-exports",
    "query-simulation",
    "agents-read",
    "agents-manage",
    "governance-read",
    "governance-manage",
    "connect",
  ],
  auditor: ["audit-verify", "leak-report", "compliance-exports", "governance-read"],
  viewer: ["query-simulation", "agents-read"],
};

const KNOWN_ROLES: readonly ConsoleRole[] = ["admin", "auditor", "viewer"];

export function parseRoles(roles: unknown): ConsoleRole[] {
  if (!Array.isArray(roles)) return [];
  const parsed: ConsoleRole[] = [];
  for (const raw of roles) {
    if (typeof raw !== "string") continue;
    const role = raw.trim().toLowerCase() as ConsoleRole;
    if (KNOWN_ROLES.includes(role) && !parsed.includes(role)) parsed.push(role);
  }
  return parsed;
}

export function effectiveRole(roles: unknown): ConsoleRole {
  const parsed = parseRoles(roles);
  if (parsed.includes("admin")) return "admin";
  if (parsed.includes("auditor")) return "auditor";
  return "viewer";
}

export function hasPermission(roles: unknown, permission: ConsolePermission): boolean {
  return ROLE_PERMISSIONS[effectiveRole(roles)].includes(permission);
}

export function roleLabel(role: ConsoleRole): string {
  switch (role) {
    case "admin":
      return "Admin";
    case "auditor":
      return "Auditor";
    case "viewer":
      return "Viewer";
  }
}

export const PERMISSION_DENIAL_TOOLTIPS: Record<ConsolePermission, string> = {
  query: "Requires Admin Role",
  "break-glass": "Requires Admin Role",
  "tenant-settings": "Requires Admin Role",
  "leak-report": "Requires Auditor or Admin role",
  "audit-verify": "Requires Auditor or Admin role",
  "compliance-exports": "Requires Auditor or Admin role",
  "query-simulation": "Requires Viewer or Admin role",
  "agents-read": "Requires Viewer or Admin role",
  "agents-manage": "Requires Admin Role",
  "governance-read": "Requires Auditor or Admin role",
  "governance-manage": "Requires Admin Role",
  connect: "Requires Admin Role",
};