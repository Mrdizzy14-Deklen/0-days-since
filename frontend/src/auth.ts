import NextAuth from "next-auth";
import type { JWT } from "next-auth/jwt";
import GitHub from "next-auth/providers/github";

/**
 * GitHub sign-in is enabled when AUTH_GITHUB_ID / AUTH_GITHUB_SECRET are set (use the GitHub
 * App's own Client ID / secret). Without them the dashboard runs in local demo mode: no
 * sign-in, and the backend is called with DEMO_GITHUB_LOGIN (or anonymously when the backend
 * runs without API_TOKEN).
 */
export const authEnabled = Boolean(process.env.AUTH_GITHUB_ID && process.env.AUTH_GITHUB_SECRET);

/** How often the list of GitHub App installations the user can access is re-checked. */
const INSTALLATIONS_TTL_MS = 5 * 60 * 1000;

/**
 * IDs of the 0 Days Since installations this user can access (their own account plus any org
 * they belong to that installed the app). This is what lets a teammate who has never pushed see
 * their team. Uses the user's own token, so GitHub decides membership, not us.
 */
async function fetchInstallations(accessToken: string): Promise<number[] | null> {
  try {
    const res = await fetch("https://api.github.com/user/installations?per_page=100", {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
      },
      cache: "no-store",
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return null;
    const body = (await res.json()) as { installations?: { id: number }[] };
    return (body.installations ?? []).map((i) => i.id).filter(Number.isInteger);
  } catch {
    return null;
  }
}

async function refreshInstallations(token: JWT): Promise<JWT> {
  if (!token.ghToken) return token;
  const ids = await fetchInstallations(token.ghToken);
  // On failure (e.g. an expired user token) keep the last known list rather than locking out.
  return { ...token, installations: ids ?? token.installations ?? [], installationsAt: Date.now() };
}

export const { handlers, auth, signIn, signOut } = NextAuth({
  providers: authEnabled ? [GitHub] : [],
  pages: { signIn: "/signin" },
  session: { strategy: "jwt" },
  callbacks: {
    async jwt({ token, profile, account }) {
      // GitHub's `login` is what the backend uses to resolve team membership.
      if (profile && typeof profile.login === "string") token.login = profile.login;
      if (account?.access_token) {
        // Kept only inside the encrypted session cookie; never sent to the browser or backend.
        token.ghToken = account.access_token;
        return refreshInstallations(token);
      }
      if (Date.now() - (token.installationsAt ?? 0) > INSTALLATIONS_TTL_MS) {
        return refreshInstallations(token);
      }
      return token;
    },
    session({ session, token }) {
      if (typeof token.login === "string") session.user.login = token.login;
      session.user.installations = token.installations ?? [];
      return session;
    },
  },
});
