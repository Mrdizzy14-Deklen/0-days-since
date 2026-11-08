import type { Metadata } from "next";
import { Atkinson_Hyperlegible_Next, Big_Shoulders, Big_Shoulders_Stencil, Martian_Mono } from "next/font/google";

import { Providers } from "@/components/providers";
import "./globals.css";

/** Signage condensed for headings and scoreboard numerals. */
const signage = Big_Shoulders({ variable: "--font-signage", subsets: ["latin"], axes: ["opsz"] });
/** Stencil cut for the "days since last incident" sign. */
const stencil = Big_Shoulders_Stencil({ variable: "--font-stencil-face", subsets: ["latin"], weight: ["800"] });
/** Body text: designed by the Braille Institute for maximum legibility. */
const body = Atkinson_Hyperlegible_Next({ variable: "--font-body", subsets: ["latin"] });
/** Code, paths, SHAs. */
const code = Martian_Mono({ variable: "--font-code", subsets: ["latin"], axes: ["wdth"] });

export const metadata: Metadata = {
  title: { default: "0 Days Since", template: "%s · 0 Days Since" },
  description:
    "Whole-project security and code-craft scoring for every push, with a team leaderboard.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html
      lang="en"
      suppressHydrationWarning
      className={`${signage.variable} ${stencil.variable} ${body.variable} ${code.variable}`}
    >
      <body className="min-h-dvh font-sans antialiased">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
