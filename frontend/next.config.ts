import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // `next dev` and `next build` get separate output folders, so running the dev server while a
  // production build exists (or the reverse) can't delete the other one's CSS/JS chunks.
  distDir: process.env.NODE_ENV === "development" ? ".next-dev" : ".next",
};

export default nextConfig;
