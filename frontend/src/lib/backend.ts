import "server-only";

import { headers as requestHeaders } from "next/headers";
import { redirect } from "next/navigation";

import { authEnabled } from "@/auth";
import { getViewer } from "@/lib/viewer";

const BACKEND_URL = (process.env.ZERODAY_API_URL || "http://localhost:8000").replace(/\/$/, "");

export class BackendError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

/**
 * Headers for server-to-server calls: the shared API token, the signed-in GitHub login and the
 * GitHub App installations that login can access. The backend decides visibility from these.
 */
export async function backendHeaders(): Promise<Headers> {
  const headers = new Headers({ Accept: "application/json" });
  const token = process.env.ZERODAY_API_TOKEN;
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const { login, installations } = await getViewer();
  if (login) headers.set("X-GitHub-Login", login);
  if (login && installations.length) headers.set("X-GitHub-Installations", installations.join(","));
  return headers;
}

/** Signed-out visitor hit something private: send them to sign in, then back here. */
async function redirectToSignIn(): Promise<never> {
  const path = (await requestHeaders()).get("x-pathname") || "/";
  redirect(`/signin?callbackUrl=${encodeURIComponent(path)}`);
}

export function backendUrl(path: string): string {
  return `${BACKEND_URL}/api/${path.replace(/^\//, "")}`;
}

export async function backendFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = await backendHeaders();
  new Headers(init.headers).forEach((v, k) => headers.set(k, v));
  return fetch(backendUrl(path), { ...init, headers, cache: "no-store" });
}

/** GET JSON from the backend; returns null on 404 so pages can render notFound(). */
export async function getJson<T>(path: string): Promise<T | null> {
  let res: Response;
  try {
    res = await backendFetch(path);
  } catch {
    throw new BackendError(503, `ZeroDay API unreachable at ${BACKEND_URL}`);
  }
  if (res.status === 404) {
    if (authEnabled && !(await getViewer()).signedIn) await redirectToSignIn();
    return null;
  }
  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new BackendError(res.status, `ZeroDay API ${res.status}: ${detail.slice(0, 200)}`);
  }
  return (await res.json()) as T;
}

/** Write call (PUT/POST/DELETE) for server actions. Returns the JSON body or the error detail. */
export async function sendJson<T>(
  path: string,
  method: "PUT" | "POST" | "DELETE",
  body?: unknown,
): Promise<{ ok: true; data: T } | { ok: false; error: string }> {
  let res: Response;
  try {
    res = await backendFetch(path, {
      method,
      headers: body === undefined ? undefined : { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    return { ok: false, error: "The 0 Days Since API is unreachable. Try again shortly." };
  }
  const data = await res.json().catch(() => null);
  if (res.ok) return { ok: true, data: data as T };
  const detail = data && typeof data.detail === "string" ? data.detail : `HTTP ${res.status}`;
  return { ok: false, error: detail };
}
