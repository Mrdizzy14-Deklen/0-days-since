import { redirect } from "next/navigation";
import { ShieldHalf } from "lucide-react";

import { GithubMark } from "@/components/icons";
import { authEnabled, signIn } from "@/auth";
import { Button } from "@/components/ui/button";
import { getViewer } from "@/lib/viewer";

export const metadata = { title: "Sign in" };

function safeCallback(url: string | undefined): string {
  // Only same-origin relative paths; never an open redirect.
  return url && url.startsWith("/") && !url.startsWith("//") ? url : "/";
}

export default async function SignInPage({
  searchParams,
}: {
  searchParams: Promise<{ callbackUrl?: string; error?: string }>;
}) {
  const { callbackUrl, error } = await searchParams;
  const target = safeCallback(callbackUrl);
  if (!authEnabled || (await getViewer()).signedIn) redirect(target);

  return (
    <main className="grid min-h-dvh place-items-center px-4">
      <div className="w-full max-w-sm rounded-xl border bg-card p-8 shadow-sm">
        <div className="mb-6 flex items-center gap-2 font-semibold">
          <span className="grid size-8 place-items-center rounded-md bg-foreground text-background">
            <ShieldHalf className="size-4" aria-hidden />
          </span>
          ZeroDay Score
        </div>
        <h1 className="text-xl font-semibold tracking-tight">Sign in to your team</h1>
        <p className="mt-2 text-sm text-muted-foreground">
          Your GitHub login decides which teams you can see. Only installations you belong to are
          shown.
        </p>
        {error && (
          <p className="mt-4 rounded-md border border-critical/40 bg-critical/10 px-3 py-2 text-sm">
            Sign-in failed ({error}). Try again.
          </p>
        )}
        <form
          className="mt-6"
          action={async () => {
            "use server";
            await signIn("github", { redirectTo: target });
          }}
        >
          <Button type="submit" className="w-full" size="lg">
            <GithubMark className="size-4" /> Continue with GitHub
          </Button>
        </form>
      </div>
    </main>
  );
}
