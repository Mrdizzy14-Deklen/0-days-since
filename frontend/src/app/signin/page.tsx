import { redirect } from "next/navigation";

import { GithubMark } from "@/components/icons";
import { LogoMark, Wordmark } from "@/components/logo";
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
      <div className="plate w-full max-w-sm p-8">
        <div className="mb-8 flex items-center gap-2.5">
          <LogoMark />
          <Wordmark />
        </div>
        <h1 className="font-display text-4xl font-black uppercase leading-none">Clock in</h1>
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
