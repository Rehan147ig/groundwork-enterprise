import { handlers } from "@/lib/auth";
import type { NextRequest } from "next/server";

// Next 16's generated RouteHandlerConfig requires every route handler to
// accept (request, context: { params: Promise<...> }), while this
// next-auth build types handlers with a single-arity signature. Re-type
// them to the shape Next 16 validates against; the underlying NextAuth
// runtime behavior (GET/POST catch-all for /api/auth/*) is unchanged.
type NextAuthCtx = { params: Promise<{ nextauth: string[] }> };

type AppRouteHandler = (
  request: NextRequest,
  context: NextAuthCtx,
) => Promise<Response | void> | Response | void;

export const GET = handlers.GET as unknown as AppRouteHandler;
export const POST = handlers.POST as unknown as AppRouteHandler;