import { NextResponse, type NextRequest } from "next/server";

import { auth, authEnabled } from "@/auth";

/**
 * Pages are not gated here: the backend decides what each visitor may see (their teams when
 * signed in, PUBLIC_TEAMS such as the demo for everyone). A signed-out visitor who opens a
 * private page is redirected to sign in by `getJson`, which needs the current path, so it is
 * passed along as `x-pathname`. Running through `auth()` also keeps the session cookie fresh
 * (including the periodically re-checked installation list).
 */
function withPathname(req: NextRequest) {
  const headers = new Headers(req.headers);
  headers.set("x-pathname", req.nextUrl.pathname + req.nextUrl.search);
  return NextResponse.next({ request: { headers } });
}

const withSession = auth((req) => withPathname(req));

export default function middleware(req: NextRequest, ctx: { params: Promise<object> }) {
  if (!authEnabled) return withPathname(req); // local demo mode
  return withSession(req, ctx as never);
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|ico)$).*)"],
};
