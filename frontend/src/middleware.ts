import { NextResponse, type NextRequest } from "next/server";

import { auth, authEnabled } from "@/auth";

const PUBLIC = [/^\/signin/, /^\/api\/auth\//];

const protect = auth((req) => {
  const { pathname, search } = req.nextUrl;
  if (req.auth?.user || PUBLIC.some((re) => re.test(pathname))) return NextResponse.next();
  if (pathname.startsWith("/api/")) {
    return NextResponse.json({ detail: "sign in required" }, { status: 401 });
  }
  const url = new URL("/signin", req.nextUrl);
  url.searchParams.set("callbackUrl", pathname + search);
  return NextResponse.redirect(url);
});

export default function middleware(req: NextRequest, ctx: { params: Promise<object> }) {
  if (!authEnabled) return NextResponse.next(); // local demo mode
  return protect(req, ctx as never);
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|ico)$).*)"],
};
