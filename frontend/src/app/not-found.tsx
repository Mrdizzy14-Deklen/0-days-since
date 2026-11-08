import Link from "next/link";

import { Button } from "@/components/ui/button";

export default function NotFound() {
  return (
    <main className="grid min-h-[70dvh] place-items-center px-4">
      <div className="max-w-md text-center">
        <p className="font-mono text-sm text-muted-foreground">404</p>
        <h1 className="mt-2 text-xl font-semibold">Not found</h1>
        <p className="mt-2 text-sm text-muted-foreground">
          It doesn&apos;t exist, or it belongs to a team you&apos;re not a member of.
        </p>
        <Button asChild className="mt-6" variant="outline">
          <Link href="/">Back to your teams</Link>
        </Button>
      </div>
    </main>
  );
}
