"use server";

import { revalidatePath } from "next/cache";

import { sendJson } from "@/lib/backend";
import type { Integrations } from "@/lib/types";

export type ActionResult = { ok: true; data: Integrations } | { ok: false; error: string };

const SLUG = /^[\w.-]{1,100}$/;

function path(slug: string, suffix = "") {
  if (!SLUG.test(slug)) throw new Error("bad team");
  return `teams/${encodeURIComponent(slug)}/integrations/discord${suffix}`;
}

/** Connect or update the channel. The backend validates the URL and sends a test message. */
export async function saveDiscord(
  slug: string,
  input: { webhookUrl?: string; includeWarnings: boolean },
): Promise<ActionResult> {
  const res = await sendJson<Integrations>(path(slug), "PUT", {
    webhook_url: input.webhookUrl?.trim() || null,
    include_warnings: input.includeWarnings,
  });
  revalidatePath(`/teams/${slug}/settings`);
  return res;
}

export async function testDiscord(slug: string): Promise<ActionResult> {
  const res = await sendJson<Integrations>(path(slug, "/test"), "POST");
  revalidatePath(`/teams/${slug}/settings`);
  return res;
}

export async function disconnectDiscord(slug: string): Promise<ActionResult> {
  const res = await sendJson<Integrations>(path(slug), "DELETE");
  revalidatePath(`/teams/${slug}/settings`);
  return res;
}
