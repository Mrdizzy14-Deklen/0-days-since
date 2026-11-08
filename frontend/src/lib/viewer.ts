import "server-only";

import { auth, authEnabled } from "@/auth";

export interface Viewer {
  /** GitHub login forwarded to the backend as X-GitHub-Login. */
  login: string | null;
  name: string | null;
  image: string | null;
  signedIn: boolean;
  demoMode: boolean;
}

export async function getViewer(): Promise<Viewer> {
  if (!authEnabled) {
    const login = process.env.DEMO_GITHUB_LOGIN || null;
    return { login, name: login, image: null, signedIn: false, demoMode: true };
  }
  const session = await auth();
  const login = session?.user?.login ?? null;
  return {
    login,
    name: session?.user?.name ?? login,
    image: session?.user?.image ?? null,
    signedIn: Boolean(login),
    demoMode: false,
  };
}
