"use client";

import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { ArrowRight, FileText, Network, Sparkles } from "lucide-react";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

type Tab = "review" | "impact" | "craft";
const TABS: Tab[] = ["review", "impact", "craft"];

const TabContext = createContext<(t: Tab) => void>(() => {});

/** Push page tabs. The active tab is mirrored in the URL hash so links can point at it. */
export function PushTabs({
  review,
  impact,
  craft,
  counts,
}: {
  review: React.ReactNode;
  impact: React.ReactNode;
  craft: React.ReactNode;
  counts: { issues: number; files: number; craft: number | null };
}) {
  const [tab, setTabState] = useState<Tab>("review");
  useEffect(() => {
    const fromHash = window.location.hash.slice(1) as Tab;
    if (TABS.includes(fromHash)) setTabState(fromHash);
  }, []);
  const setTab = useCallback((t: Tab) => {
    setTabState(t);
    history.replaceState(null, "", t === "review" ? window.location.pathname : `#${t}`);
    document.getElementById("push-tabs")?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, []);

  const items: { id: Tab; label: string; icon: typeof FileText; badge: string | null }[] = [
    { id: "review", label: "Review", icon: FileText, badge: counts.issues ? String(counts.issues) : null },
    { id: "impact", label: "Impact map", icon: Network, badge: counts.files ? `${counts.files} files` : null },
    { id: "craft", label: "Code craft", icon: Sparkles, badge: counts.craft !== null ? `${counts.craft}/300` : null },
  ];

  return (
    <TabContext.Provider value={setTab}>
      <div id="push-tabs" className="scroll-mt-20">
        <div role="tablist" aria-label="Push details" className="flex gap-1 overflow-x-auto border-b">
          {items.map(({ id, label, icon: Icon, badge }) => (
            <button
              key={id}
              role="tab"
              type="button"
              id={`tab-${id}`}
              aria-selected={tab === id}
              aria-controls={`panel-${id}`}
              onClick={() => setTab(id)}
              className={cn(
                "relative flex shrink-0 items-center gap-2 px-3 py-2.5 text-sm transition-colors",
                tab === id ? "font-medium text-foreground" : "text-muted-foreground hover:text-foreground",
              )}
            >
              <Icon className="size-4" aria-hidden />
              {label}
              {badge && (
                <span className="rounded-full bg-muted px-1.5 py-px font-mono text-[11px] text-muted-foreground">
                  {badge}
                </span>
              )}
              {tab === id && <span className="absolute inset-x-2 -bottom-px h-0.5 rounded-full bg-brand" aria-hidden />}
            </button>
          ))}
        </div>
        {TABS.map((id) => (
          <div key={id} role="tabpanel" id={`panel-${id}`} aria-labelledby={`tab-${id}`} hidden={tab !== id} className="pt-6">
            {id === "review" ? review : id === "impact" ? impact : craft}
          </div>
        ))}
      </div>
    </TabContext.Provider>
  );
}

/** Button that switches to the Impact map tab (used from inside the Review tab). */
export function ShowAttackPath() {
  const setTab = useContext(TabContext);
  return (
    <Button variant="outline" size="sm" onClick={() => setTab("impact")}>
      See the attack path <ArrowRight className="size-3.5" />
    </Button>
  );
}

export function GoToCraft({ children }: { children: React.ReactNode }) {
  const setTab = useContext(TabContext);
  return (
    <button type="button" className="font-medium text-brand underline-offset-2 hover:underline" onClick={() => setTab("craft")}>
      {children}
    </button>
  );
}
