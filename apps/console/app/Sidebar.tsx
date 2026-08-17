import Link from "next/link";
import { LogIn, LogOut, ShieldAlert } from "lucide-react";
import { auth, demoMode, oidcConfigured } from "@/lib/auth";
import { signInAction, signOutAction } from "@/app/actions";
import {
  ConsolePermission,
  PERMISSION_DENIAL_TOOLTIPS,
  effectiveRole,
  hasPermission,
} from "@/lib/rbac";

// Shared sidebar nav. Replaces the per-page duplicated nav. Only links to routes that
// actually exist — the old dead links (/tenants, /connectors, /traces, /policies) were
// removed as part of the Dashboard Layer 1 cleanup. /traces returns when the audit read
// API (Layer 2) lands.
//
// Role-based access control (RBAC): each nav item is gated on a console permission
// derived from the OIDC id_token roles claim (Admin → full access, Auditor → read-only
// audit/leak/compliance surfaces, Viewer → read-only query simulation). Items the
// current role cannot use render disabled with a clear tooltip ("Requires Admin Role")
// rather than hiding them, so the surface stays discoverable.
//
// Enterprise auth: when OIDC is configured the sidebar shows the verified
// session user (name/email from the IdP) with a server-action Sign out.
// Without a session and with OIDC configured, a Sign in button redirects
// to the IdP login page. The /demo persona console is shown ONLY when
// GROUNDWORK_DEMO_MODE=true — in enterprise mode (GROUNDWORK_DEMO_MODE=false
// or unset) the demo fallback is hidden entirely.

type NavItem = { href: string; label: string; permission: ConsolePermission | null };

const LINKS: NavItem[] = [
  { href: "/", label: "Security Overview", permission: null },
  { href: "/live-acl-test", label: "Live ACL Test", permission: "query-simulation" },
  { href: "/break-glass", label: "Break Glass", permission: "break-glass" },
  { href: "/console", label: "Console", permission: "query" },
];

export async function Sidebar() {
  const session = await auth();
  const showDemo = demoMode();
  const user = session?.user;
  const roles = user?.roles;
  const role = effectiveRole(roles);
  const links = showDemo
    ? [...LINKS, { href: "/demo", label: "Demo Console", permission: "query-simulation" as ConsolePermission }]
    : LINKS;

  return (
    <aside className="sidebar">
      <div className="brand">Groundwork</div>
      <nav className="nav">
        {links.map((link) =>
          link.permission === null || hasPermission(roles, link.permission) ? (
            <Link key={link.href} href={link.href}>
              {link.label}
            </Link>
          ) : (
            <span
              key={link.href}
              className="nav-disabled"
              title={link.permission ? PERMISSION_DENIAL_TOOLTIPS[link.permission] : undefined}
            >
              {link.label}
            </span>
          ),
        )}
      </nav>

      <div className="sidebar-user">
        {user ? (
          <>
            <div className="sidebar-user-identity">
              <strong>{user.name ?? user.email ?? "Signed in"}</strong>
              {user.email && user.name !== user.email && (
                <span className="muted">{user.email}</span>
              )}
              <span className="role-badge" title="Role from the OIDC id_token roles claim">
                <ShieldAlert size={11} /> {role} role
              </span>
            </div>
            <form action={signOutAction}>
              <button className="sidebar-user-action" type="submit" title="Sign out">
                <LogOut size={15} /> Sign out
              </button>
            </form>
          </>
        ) : oidcConfigured() ? (
          <form action={signInAction}>
            <button className="sidebar-user-action" type="submit" title="Sign in">
              <LogIn size={15} /> Sign in
            </button>
          </form>
        ) : (
          <div className="sidebar-user-identity">
            <strong className="muted">Local demo — auth not configured</strong>
          </div>
        )}
      </div>
    </aside>
  );
}