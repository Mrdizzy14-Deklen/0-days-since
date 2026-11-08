import type { Metadata } from "next";

import { PlayPageBody } from "@/components/play-page";
import { PageShell, SiteHeader } from "@/components/site-header";

export const metadata: Metadata = {
  title: "Daily Zero-Day",
  description: "Find the vulnerable line in three guesses. A new Python security puzzle every day.",
};

/** Public puzzle page: shareable with anyone, no team needed. */
export default function PlayPage() {
  return (
    <>
      <SiteHeader />
      <PageShell>
        <PlayPageBody />
      </PageShell>
    </>
  );
}
