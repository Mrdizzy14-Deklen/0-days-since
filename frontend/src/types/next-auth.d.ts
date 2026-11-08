import "next-auth";
import "next-auth/jwt";

declare module "next-auth" {
  interface Session {
    user: {
      login?: string;
      /** GitHub App installation IDs this user can access (see auth.ts). */
      installations?: number[];
      name?: string | null;
      email?: string | null;
      image?: string | null;
    };
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    login?: string;
    /** The user's GitHub OAuth token; server-side only (the JWT cookie is encrypted). */
    ghToken?: string;
    installations?: number[];
    installationsAt?: number;
  }
}
