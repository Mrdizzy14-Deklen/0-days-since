import NextAuth from "next-auth";
import GitHub from "next-auth/providers/github";

/**
 * GitHub OAuth is enabled when AUTH_GITHUB_ID / AUTH_GITHUB_SECRET are set. Without them the
 * dashboard runs in local demo mode: no sign-in, and the backend is called with
 * DEMO_GITHUB_LOGIN (or anonymously when the backend runs without API_TOKEN).
 */
export const authEnabled = Boolean(process.env.AUTH_GITHUB_ID && process.env.AUTH_GITHUB_SECRET);

export const { handlers, auth, signIn, signOut } = NextAuth({
  providers: authEnabled ? [GitHub] : [],
  pages: { signIn: "/signin" },
  session: { strategy: "jwt" },
  callbacks: {
    jwt({ token, profile }) {
      // GitHub's `login` is what the backend uses to resolve team membership.
      if (profile && typeof profile.login === "string") token.login = profile.login;
      return token;
    },
    session({ session, token }) {
      if (typeof token.login === "string") session.user.login = token.login;
      return session;
    },
  },
});
