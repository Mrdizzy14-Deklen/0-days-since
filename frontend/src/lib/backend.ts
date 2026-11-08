import "server-only";

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

/** Headers for server-to-server calls: the shared API token plus the signed-in GitHub login. */
export async function backendHeaders(): Promise<Headers> {
  const headers = new Headers({ Accept: "application/json" });
  const token = process.env.ZERODAY_API_TOKEN;
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const { login } = await getViewer();
  if (login) headers.set("X-GitHub-Login", login);
  return headers;
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
  if (res.status === 404) return null;
  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new BackendError(res.status, `ZeroDay API ${res.status}: ${detail.slice(0, 200)}`);
  }
  return (await res.json()) as T;
}
