"use client";

import { useState, useTransition } from "react";
import { AlertTriangle, CheckCircle2, Loader2, Send, Unplug } from "lucide-react";
import { toast } from "sonner";

import { disconnectDiscord, saveDiscord, testDiscord, type ActionResult } from "@/app/teams/[slug]/settings/actions";
import { DiscordMark } from "@/components/icons";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { Integrations } from "@/lib/types";

const HOW_TO = [
  "In Discord, open the channel's settings (gear icon) > Integrations > Webhooks.",
  "Click New Webhook, name it \"0 Days Since\", then Copy Webhook URL.",
  "Paste it below and click Connect. A test message is posted right away.",
];

function when(iso: string | null) {
  if (!iso) return null;
  return new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

/** Connect a Discord channel that hears about faulty pushes. All checks happen server-side. */
export function DiscordSettings({ slug, initial }: { slug: string; initial: Integrations }) {
  const [state, setState] = useState(initial);
  const [url, setUrl] = useState("");
  const [warnings, setWarnings] = useState(initial.discord.include_warnings);
  const [error, setError] = useState<string | null>(null);
  const [confirmDisconnect, setConfirmDisconnect] = useState(false);
  const [pending, start] = useTransition();
  const d = state.discord;

  function run(action: () => Promise<ActionResult>, success: string) {
    setError(null);
    start(async () => {
      const res = await action();
      if (res.ok) {
        setState(res.data);
        setWarnings(res.data.discord.include_warnings);
        setUrl("");
        setConfirmDisconnect(false);
        toast.success(success);
      } else {
        setError(res.error);
      }
    });
  }

  return (
    <div className="card-surface space-y-6 p-5 sm:p-6">
      <div className="flex flex-wrap items-center gap-3">
        <span className="grid size-11 place-items-center rounded-md border-2 border-foreground bg-[#5865f2] text-white shadow-[2px_2px_0_var(--outline)]">
          <DiscordMark className="size-6" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="card-title">Discord channel</div>
          {d.connected ? (
            <div className="mt-0.5 flex flex-wrap items-center gap-x-2 text-sm text-muted-foreground">
              <CheckCircle2 className="size-4 text-good" aria-hidden />
              <span className="font-medium text-foreground">Connected</span>
              <code className="truncate font-mono text-xs">{d.webhook}</code>
            </div>
          ) : (
            <div className="mt-0.5 text-sm text-muted-foreground">Not connected</div>
          )}
        </div>
      </div>

      {d.connected && d.last_error && (
        <p className="flex items-start gap-2 rounded-md border-2 border-critical/50 bg-critical/10 px-3 py-2 text-sm" role="alert">
          <AlertTriangle className="mt-0.5 size-4 shrink-0 text-critical" aria-hidden />
          <span>
            <strong>Last message failed:</strong> {d.last_error}
          </span>
        </p>
      )}
      {d.connected && !d.last_error && d.last_sent_at && (
        <p className="text-sm text-muted-foreground">Last message posted {when(d.last_sent_at)}.</p>
      )}

      {!state.can_edit ? (
        <p className="text-sm text-muted-foreground">
          Only members of this team can change its alerts. Sign in with GitHub as a team member.
        </p>
      ) : (
        <form
          className="space-y-5"
          onSubmit={(e) => {
            e.preventDefault();
            run(
              () => saveDiscord(slug, { webhookUrl: url || undefined, includeWarnings: warnings }),
              url ? "Connected. Check your channel for the test message." : "Saved.",
            );
          }}
        >
          {!d.connected && (
            <ol className="space-y-1.5 text-sm">
              {HOW_TO.map((step, i) => (
                <li key={step} className="flex gap-2.5">
                  <span className="grid size-5 shrink-0 place-items-center rounded-full border-2 border-foreground font-mono text-[0.65rem] font-bold">
                    {i + 1}
                  </span>
                  <span>{step}</span>
                </li>
              ))}
            </ol>
          )}

          <div className="space-y-1.5">
            <label htmlFor="discord-url" className="text-sm font-medium">
              {d.connected ? "Switch to another channel (optional)" : "Webhook URL"}
            </label>
            <Input
              id="discord-url"
              type="url"
              inputMode="url"
              autoComplete="off"
              spellCheck={false}
              placeholder="https://discord.com/api/webhooks/…"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              required={!d.connected}
              className="font-mono text-xs"
              aria-describedby="discord-url-help"
            />
            <p id="discord-url-help" className="text-xs text-muted-foreground">
              Treat it like a password: anyone with it can post to the channel. It is stored on the
              server and never shown again.
            </p>
          </div>

          <label className="flex cursor-pointer items-start gap-3 text-sm">
            <input
              type="checkbox"
              checked={warnings}
              onChange={(e) => setWarnings(e.target.checked)}
              className="mt-0.5 size-4 accent-[var(--brand)]"
            />
            <span>
              <span className="font-medium">Also post warnings</span>
              <span className="block text-muted-foreground">
                Faulty pushes (the ones that reset the counter) are always posted. Turn this on to also
                hear about pushes that pass with a warning.
              </span>
            </span>
          </label>

          {error && (
            <p className="rounded-md border-2 border-critical/50 bg-critical/10 px-3 py-2 text-sm" role="alert">
              {error}
            </p>
          )}

          <div className="flex flex-wrap items-center gap-3">
            <Button type="submit" disabled={pending || (!d.connected && !url)}>
              {pending ? <Loader2 className="size-4 animate-spin" /> : <DiscordMark className="size-4" />}
              {d.connected ? (url ? "Switch channel" : "Save") : "Connect"}
            </Button>
            {d.connected && (
              <>
                <Button
                  type="button"
                  variant="outline"
                  disabled={pending}
                  onClick={() => run(() => testDiscord(slug), "Test message sent.")}
                >
                  <Send className="size-4" /> Send test
                </Button>
                {confirmDisconnect ? (
                  <span className="flex items-center gap-2 text-sm">
                    Stop posting to this channel?
                    <Button
                      type="button"
                      variant="destructive"
                      size="sm"
                      disabled={pending}
                      onClick={() => run(() => disconnectDiscord(slug), "Disconnected.")}
                    >
                      Disconnect
                    </Button>
                    <Button type="button" variant="ghost" size="sm" onClick={() => setConfirmDisconnect(false)}>
                      Cancel
                    </Button>
                  </span>
                ) : (
                  <Button type="button" variant="ghost" disabled={pending} onClick={() => setConfirmDisconnect(true)}>
                    <Unplug className="size-4" /> Disconnect
                  </Button>
                )}
              </>
            )}
          </div>
        </form>
      )}
    </div>
  );
}
