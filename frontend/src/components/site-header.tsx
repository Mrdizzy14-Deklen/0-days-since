import Link from "next/link";
import { LogOut, ShieldHalf } from "lucide-react";

import { signOut } from "@/auth";
import { DevAvatar } from "@/components/dev-avatar";
import { ThemeToggle } from "@/components/theme-toggle";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import type { TeamRef } from "@/lib/types";
import { getViewer } from "@/lib/viewer";

export async function SiteHeader({ team }: { team?: TeamRef | null }) {
  const viewer = await getViewer();
  return (
    <header className="sticky top-[env(safe-area-inset-top,0px)] z-40 border-b bg-background/85 backdrop-blur">
      <div className="mx-auto flex h-14 max-w-[1440px] items-center gap-3 px-4 sm:px-6">
        <Link href="/" className="flex items-center gap-2 font-semibold tracking-tight">
          <span className="grid size-7 place-items-center rounded-md bg-foreground text-background">
            <ShieldHalf className="size-4" aria-hidden />
          </span>
          <span className="hidden sm:inline">ZeroDay Score</span>
        </Link>
        {team && (
          <>
            <span className="text-muted-foreground/60" aria-hidden>
              /
            </span>
            <Link
              href={`/teams/${team.slug}`}
              className="truncate text-sm font-medium text-muted-foreground hover:text-foreground"
            >
              {team.name}
            </Link>
          </>
        )}
        <div className="ml-auto flex items-center gap-1">
          {viewer.demoMode && (
            <span className="mr-2 hidden rounded-full border px-2 py-0.5 text-xs text-muted-foreground md:inline">
              Local demo mode
            </span>
          )}
          <ThemeToggle />
          {viewer.signedIn && viewer.login && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="icon" aria-label="Account">
                  <DevAvatar login={viewer.login} src={viewer.image} className="size-7" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-52">
                <DropdownMenuLabel className="font-normal">
                  <div className="text-sm font-medium">{viewer.name}</div>
                  <div className="text-xs text-muted-foreground">@{viewer.login}</div>
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
                <form
                  action={async () => {
                    "use server";
                    await signOut({ redirectTo: "/signin" });
                  }}
                >
                  <DropdownMenuItem asChild>
                    <button type="submit" className="w-full">
                      <LogOut className="size-4" /> Sign out
                    </button>
                  </DropdownMenuItem>
                </form>
              </DropdownMenuContent>
            </DropdownMenu>
          )}
        </div>
      </div>
    </header>
  );
}

export function PageShell({ children }: { children: React.ReactNode }) {
  return <main className="mx-auto w-full max-w-[1440px] px-4 py-6 sm:px-6 lg:py-8">{children}</main>;
}
