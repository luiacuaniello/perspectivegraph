// DashboardSkeleton is the first-paint placeholder — a calm shimmer that mirrors
// the overview's shape (stat cards + panels), so the initial load reads as
// "loading this screen" rather than a blank flash or a bare "Loading…".
export default function DashboardSkeleton() {
  return (
    <div className="flex h-full flex-col gap-4 overflow-hidden pt-1" aria-busy="true" aria-label="Loading dashboard">
      <div className="flex flex-wrap gap-3">
        {Array.from({ length: 6 }).map((_, i) => (
          <div key={i} className="min-w-[140px] flex-1 rounded-xl border border-edge bg-panel p-4 shadow-card">
            <div className="skeleton h-2.5 w-20" />
            <div className="skeleton mt-3 h-7 w-12" />
            <div className="skeleton mt-3 h-2 w-24" />
          </div>
        ))}
      </div>
      <div className="rounded-xl border border-edge bg-panel p-4 shadow-card">
        <div className="skeleton h-2.5 w-28" />
        <div className="skeleton mt-3 h-8 w-full" />
      </div>
      <div className="flex flex-col gap-2">
        {Array.from({ length: 3 }).map((_, i) => (
          <div key={i} className="rounded-xl border border-edge bg-panel p-3.5 shadow-card">
            <div className="flex items-center gap-3">
              <div className="skeleton h-6 w-6 rounded-md" />
              <div className="skeleton h-3.5 flex-1" />
              <div className="skeleton h-5 w-10 rounded-md" />
            </div>
            <div className="skeleton mt-2.5 ml-9 h-2.5 w-2/3" />
          </div>
        ))}
      </div>
    </div>
  );
}
