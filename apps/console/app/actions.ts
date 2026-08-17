"use server";

import { redirect } from "next/navigation";
import { revalidatePath } from "next/cache";
import { runtimeUserToken, signIn, signOut } from "@/lib/auth";
import { mintConsoleAssertion } from "@/lib/jwt";
import { requireConsolePermission } from "@/lib/consoleAuth";

// Module-level server actions for the sidebar auth controls (Turbopack in
// Next 16 disallows inline "use server" functions inside JSX). The
// break-glass actions re-check the Admin role server-side — the disabled
// form is the UI gate, this check is the enforcement gate.
export async function signOutAction(): Promise<void> {
  await signOut({ redirectTo: "/" });
}

export async function signInAction(): Promise<void> {
  await signIn("oidc", { redirectTo: "/" });
}

const RUNTIME_URL = process.env.QUERY_RUNTIME_URL ?? "http://localhost:8080";
const API_KEY = process.env.GROUNDWORK_API_KEY ?? "";

export async function openBreakGlassAction(formData: FormData): Promise<void> {
  if (await requireConsolePermission("break-glass")) {
    redirect("/break-glass?denied=1");
  }
  const reason = (formData.get("reason") ?? "").toString().trim();
  const durationMinutes = Math.floor(Number(formData.get("duration_minutes") ?? 0));
  if (
    reason.length < 10 ||
    !Number.isFinite(durationMinutes) ||
    durationMinutes < 1 ||
    durationMinutes > 1440
  ) {
    redirect("/break-glass?denied=1");
  }
  const idToken = await runtimeUserToken();
  const operatorToken = idToken ?? (await mintConsoleAssertion("console-operator"));
  if (!operatorToken) {
    redirect("/break-glass?denied=1");
  }
  const res = await fetch(`${RUNTIME_URL}/v1/security/break-glass/grants`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Groundwork-API-Key": API_KEY,
      ...(idToken
        ? { Authorization: `Bearer ${idToken}` }
        : { "X-Groundwork-User-Assertion": operatorToken }),
    },
    body: JSON.stringify({ reason, duration_minutes: durationMinutes }),
    cache: "no-store",
  }).catch(() => null);
  revalidatePath("/break-glass");
  redirect(res && res.ok ? "/break-glass?opened=1" : "/break-glass?failed=1");
}

export async function revokeBreakGlassAction(formData: FormData): Promise<void> {
  if (await requireConsolePermission("break-glass")) {
    redirect("/break-glass?denied=1");
  }
  const id = (formData.get("grant_id") ?? "").toString().trim();
  const reason = (formData.get("reason") ?? "").toString().trim();
  if (!id || reason.length < 10) {
    redirect("/break-glass?denied=1");
  }
  const idToken = await runtimeUserToken();
  const operatorToken = idToken ?? (await mintConsoleAssertion("console-operator"));
  if (!operatorToken) {
    redirect("/break-glass?denied=1");
  }
  const res = await fetch(
    `${RUNTIME_URL}/v1/security/break-glass/grants/${encodeURIComponent(id)}/revoke`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Groundwork-API-Key": API_KEY,
        ...(idToken
          ? { Authorization: `Bearer ${idToken}` }
          : { "X-Groundwork-User-Assertion": operatorToken }),
      },
      body: JSON.stringify({ reason }),
      cache: "no-store",
    },
  ).catch(() => null);
  revalidatePath("/break-glass");
  redirect(res && res.ok ? "/break-glass?revoked=1" : "/break-glass?failed=1");
}