import "server-only";
import { NextResponse } from "next/server";
import { auth, demoMode, oidcConfigured } from "@/lib/auth";
import { hasPermission, type ConsolePermission } from "@/lib/rbac";

// Server-only authorization gate for every sensitive console API route.
//
// Enforcement rule: authentication AND RBAC are enforced whenever OIDC
// is configured and demo mode is disabled — i.e. exactly the enterprise
// deployments where the console holds a real identity provider. Demo
// mode (GROUNDWORK_DEMO_MODE=true) keeps local/dev flows working
// without a session; demo data itself remains gated by the flag at each
// route (demoData()), so production never fabricates responses.
//
//   - no verified Auth.js session            -> 401 authentication_required
//   - session without the required role      -> 403 forbidden (with permission)
//   - OIDC not configured (demo mode false)  -> 503 configuration_required
//   - authorized / demo mode                 -> null (caller proceeds)
//
// The check runs BEFORE any runtime call: a rejected request never
// touches the query runtime.
export async function requireConsolePermission(
  permission: ConsolePermission,
): Promise<NextResponse | null> {
  // Allow unrestricted access ONLY in explicit demo mode
  if (demoMode()) return null;
  // FAIL CLOSED: If demo mode is false and OIDC is not configured, refuse access
  if (!oidcConfigured()) {
    return NextResponse.json(
      {
        error: "configuration_required",
        message: "OIDC authentication must be configured when demo mode is disabled",
      },
      { status: 503 }
    );
  }
  const session = await auth();
  if (!session?.user) {
    return NextResponse.json({ error: "authentication_required" }, { status: 401 });
  }
  if (!hasPermission(session.user.roles, permission)) {
    return NextResponse.json({ error: "forbidden", permission }, { status: 403 });
  }
  return null;
}