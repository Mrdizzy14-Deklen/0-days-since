import { Skeleton } from "@/components/ui/skeleton";

function HeaderBar() {
  return (
    <div className="border-b">
      <div className="mx-auto flex h-14 max-w-[1400px] items-center gap-3 px-4 sm:px-6">
        <Skeleton className="size-8 rounded-lg" />
        <Skeleton className="h-4 w-32" />
      </div>
    </div>
  );
}

/** Placeholder layouts shown while a page's data loads. */
export function PageSkeleton({ variant }: { variant: "team" | "list" | "push" | "developer" }) {
  return (
    <div aria-busy="true" aria-label="Loading">
      <HeaderBar />
      <div className="mx-auto max-w-[1400px] space-y-6 px-4 py-8 sm:px-6">
        {variant !== "team" && <Skeleton className="h-12 w-64" />}
        {variant === "team" && (
          <>
            <div className="grid grid-cols-1 items-center gap-6 lg:grid-cols-[minmax(0,1fr)_460px]">
              <Skeleton className="h-16 w-80" />
              <Skeleton className="h-44 rounded-md" />
            </div>
            <div className="grid grid-cols-1 gap-8 lg:grid-cols-[minmax(0,1fr)_380px]">
              <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
                {Array.from({ length: 3 }, (_, i) => (
                  <Skeleton key={i} className="h-72 rounded-md" />
                ))}
              </div>
              <Skeleton className="h-[480px] rounded-md" />
            </div>
          </>
        )}
        {variant === "list" && (
          <div className="mx-auto max-w-3xl space-y-2">
            {Array.from({ length: 8 }, (_, i) => (
              <Skeleton key={i} className="h-16 rounded-lg" />
            ))}
          </div>
        )}
        {variant === "push" && (
          <>
            <Skeleton className="h-36 rounded-xl" />
            <Skeleton className="h-10 w-80" />
            <Skeleton className="h-72 rounded-xl" />
          </>
        )}
        {variant === "developer" && (
          <>
            <Skeleton className="h-32 rounded-xl" />
            <Skeleton className="h-20 rounded-xl" />
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
              <Skeleton className="h-72 rounded-xl" />
              <Skeleton className="h-72 rounded-xl lg:col-span-2" />
            </div>
          </>
        )}
      </div>
    </div>
  );
}
