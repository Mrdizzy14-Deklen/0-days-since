import { NextRequest } from "next/server";

import { authEnabled } from "@/auth";
import { backendFetch } from "@/lib/backend";
import { getViewer } from "@/lib/viewer";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

/** Read-only routes the browser may reach (the API token never leaves the server). */
const ALLOWED = [
  /^teams\/[\w.-]+\/(leaderboard|stats|pushes|trends|stream)$/,
  /^pushes\/\d+$/,
  /^developers\/\d+$/,
];

/**
 * GET proxy from the browser to the FastAPI backend. Adds the server-held API token and the
 * signed-in user's GitHub login (membership is enforced by the backend), and streams the
 * response so the SSE live feed passes straight through.
 */
export async function GET(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  const { path } = await ctx.params;
  const target = path.join("/");
  if (!ALLOWED.some((re) => re.test(target))) {
    return Response.json({ detail: "not found" }, { status: 404 });
  }
  if (authEnabled && !(await getViewer()).signedIn) {
    return Response.json({ detail: "sign in required" }, { status: 401 });
  }

  const params = new URLSearchParams(req.nextUrl.searchParams);
  const headers = new Headers();
  // EventSource cannot set headers: accept the resume cursor as a query param as well.
  const lastEventId = req.headers.get("last-event-id") || params.get("last_event_id");
  params.delete("last_event_id");
  if (lastEventId && /^\d+$/.test(lastEventId)) headers.set("Last-Event-ID", lastEventId);

  const query = params.toString();
  let upstream: Response;
  try {
    upstream = await backendFetch(query ? `${target}?${query}` : target, {
      headers,
      signal: req.signal,
    });
  } catch {
    return Response.json({ detail: "ZeroDay API unreachable" }, { status: 502 });
  }

  const isStream = target.endsWith("/stream");
  return new Response(upstream.body, {
    status: upstream.status,
    headers: {
      "Content-Type": upstream.headers.get("content-type") ?? "application/json",
      "Cache-Control": "no-cache, no-transform",
      ...(isStream ? { Connection: "keep-alive", "X-Accel-Buffering": "no" } : {}),
    },
  });
}
