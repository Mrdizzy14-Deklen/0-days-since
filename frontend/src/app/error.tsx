"use client";

import { RotateCw, ServerCrash } from "lucide-react";

import { Button } from "@/components/ui/button";

export default function ErrorPage({ error, reset }: { error: Error; reset: () => void }) {
  return (
    <main className="grid min-h-[70dvh] place-items-center px-4">
      <div className="max-w-md text-center">
        <ServerCrash className="mx-auto size-10 text-muted-foreground" aria-hidden />
        <h1 className="mt-4 text-xl font-semibold">Couldn&apos;t load this page</h1>
        <p className="mt-2 text-sm text-muted-foreground">
          {error.message.includes("unreachable")
            ? "The ZeroDay API isn't responding. Check that the backend is running and ZERODAY_API_URL points at it."
            : "Something went wrong talking to the ZeroDay API."}
        </p>
        <Button className="mt-6" variant="outline" onClick={reset}>
          <RotateCw className="size-4" /> Try again
        </Button>
      </div>
    </main>
  );
}
