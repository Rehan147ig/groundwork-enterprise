"use client";

import { SessionProvider } from "next-auth/react";
import type { Session } from "next-auth";
import type { ReactNode } from "react";

// Client boundary: SessionProvider must live under "use client", the
// layout above it is a server component. The session passed here is the
// one `auth()` resolved server-side, so pages render without a flash.

export function Providers({ session, children }: { session: Session | null | undefined; children: ReactNode }) {
  return <SessionProvider session={session}>{children}</SessionProvider>;
}