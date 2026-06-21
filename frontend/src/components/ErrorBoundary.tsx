import { Component, type ErrorInfo, type ReactNode } from "react";

// A render error in any view should not blank the whole app. This boundary
// catches it, shows a recoverable message, and keeps the rest of the shell.
export default class ErrorBoundary extends Component<
  { children: ReactNode },
  { error: Error | null }
> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // Surface it for debugging without crashing the tree.
    console.error("dashboard render error:", error, info.componentStack);
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="grid h-full place-items-center p-8">
        <div className="max-w-lg rounded-2xl border border-red-500/30 bg-panel shadow-card p-7 text-center">
          <h2 className="text-base font-semibold text-slate-900">Something broke while rendering</h2>
          <p className="mx-auto mt-2 max-w-md text-[13px] leading-relaxed text-slate-600">
            The dashboard hit an unexpected error. The backend and your data are unaffected — reload to
            recover.
          </p>
          <pre className="mt-3 max-h-40 overflow-auto rounded-lg bg-ink p-3 text-left font-mono text-[11px] text-red-700">
            {String(this.state.error.message || this.state.error)}
          </pre>
          <button
            onClick={() => window.location.reload()}
            className="mt-4 rounded-lg bg-accent px-3.5 py-1.5 text-xs font-semibold text-white transition hover:bg-accent/90"
          >
            Reload
          </button>
        </div>
      </div>
    );
  }
}
