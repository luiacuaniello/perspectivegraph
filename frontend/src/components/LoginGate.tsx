import { useEffect, useState, type ReactNode } from "react";
import { fetchAuthConfig, authToken, setAuthToken, type AuthConfig } from "../api/client";
import { beginPkceLogin, completePkceLogin, randomString } from "../auth/pkce";
import { AlertTriangleIcon } from "./icons";

// OpenInstanceBanner is the only place an unauthenticated instance says so to a human.
// The backend logs a warning at startup and /auth/config reports authRequired: false, but
// a log scrolls past and an endpoint is not read by whoever opens the page - so an install
// exposed by accident looked exactly like one exposed on purpose.
//
// It is deliberately not dismissible. The Helm chart refuses to publish an install without
// a credential, but it can only see exposure arranged through the chart: a patched Service
// or a hand-written Ingress is invisible to it, and this banner is what covers that gap. A
// signal that can be clicked away does not cover it.
//
// It shows in `make demo` too, which runs open by design. That is the point rather than a
// side effect: the demo is where someone learns this is open until they configure it.
function OpenInstanceBanner() {
  return (
    <div
      role="alert"
      className="flex shrink-0 items-center gap-2 border-b border-flag/25 bg-flag-soft px-4 py-2 text-xs text-flag"
    >
      <AlertTriangleIcon className="size-3.5 shrink-0" />
      <span>
        <strong className="font-semibold">This instance requires no credential.</strong>{" "}
        Anyone who can reach it can read these attack paths and post to the ingest endpoint.
        Set <code>API_TOKENS</code> or <code>OIDC_JWKS_URL</code>, and{" "}
        <code>INGEST_HMAC_SECRET</code>, before exposing it.
      </span>
    </div>
  );
}

// LoginGate fronts the dashboard with a runtime login when the API requires auth.
// It reads GET /auth/config (public) to learn the mode, so the same build works
// whether the backend is open, token-secured, or SSO-secured - no rebuild, no
// token baked into the bundle.
//
//   - open API            → renders straight through.
//   - token / both / oidc → asks for a credential. "Sign in with SSO" runs the
//     full OIDC Authorization-Code + PKCE flow when a token endpoint is advertised
//     (code → token exchange, no secret in the browser), else an implicit
//     #access_token return. Either way the token lands in sessionStorage.
export default function LoginGate({ children }: { children: ReactNode }) {
  const [ready, setReady] = useState(false);
  const [authed, setAuthed] = useState(false);
  const [config, setConfig] = useState<AuthConfig | null>(null);
  // Whether /auth/config actually answered. A failed fetch falls back to "open" so the
  // dashboard still renders, but it is not evidence that the instance IS open - and
  // claiming so on a network blip would teach people to ignore the banner.
  const [configKnown, setConfigKnown] = useState(false);
  const [token, setToken] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;

    async function init() {
      try {
        const url = new URL(window.location.href);
        const code = url.searchParams.get("code");
        const state = url.searchParams.get("state");
        const implicit = new URLSearchParams(window.location.hash.replace(/^#/, "")).get("access_token");

        if (code && state) {
          // Authorization-Code + PKCE return: exchange the code for a token.
          try {
            setAuthToken(await completePkceLogin(code, state));
          } catch (e) {
            if (alive) setError(`SSO sign-in failed: ${(e as Error).message}`);
          }
          cleanUrl();
        } else if (implicit) {
          // Implicit return (#access_token=…) for IdPs without a CORS token endpoint.
          setAuthToken(implicit);
          cleanUrl();
        }
      } catch {
        /* malformed return URL - ignore and fall through to the gate */
      }

      let known = true;
      const c = await fetchAuthConfig().catch(() => {
        known = false;
        return { authRequired: false, mode: "none" } as AuthConfig;
      });
      if (!alive) return;
      setConfig(c);
      setConfigKnown(known);
      setAuthed(!c.authRequired || !!authToken());
      setReady(true);
    }

    init();
    return () => {
      alive = false;
    };
  }, []);

  if (!ready) return null;
  if (authed || !config) {
    const open = configKnown && config !== null && !config.authRequired;
    return (
      <>
        {open && <OpenInstanceBanner />}
        {children}
      </>
    );
  }

  const oidc = config.oidc;
  const ssoAvailable = !!(oidc && oidc.authorizeUrl && oidc.clientId);

  const submitToken = () => {
    const t = token.trim();
    if (!t) {
      setError("Paste a token to continue.");
      return;
    }
    setAuthToken(t);
    setAuthed(true);
  };

  const ssoLogin = () => {
    if (!oidc) return;
    setError(null);
    if (oidc.tokenUrl) {
      // Full Authorization-Code + PKCE.
      beginPkceLogin(oidc).catch((e) => setError(`Could not start SSO: ${(e as Error).message}`));
      return;
    }
    // Implicit fallback when no token endpoint is configured.
    const params = new URLSearchParams({
      response_type: "token",
      client_id: oidc.clientId || "",
      redirect_uri: window.location.origin + window.location.pathname,
      scope: oidc.scopes || "openid",
      state: randomString(32),
      nonce: randomString(32),
    });
    window.location.href = `${oidc.authorizeUrl}?${params.toString()}`;
  };

  return (
    <div className="flex min-h-[400px] items-center justify-center p-6">
      <div className="w-full max-w-sm rounded-2xl border border-edge bg-panel p-6 shadow-card">
        <h1 className="text-lg font-semibold text-slate-900">Sign in to PerspectiveGraph</h1>
        <p className="mt-1 text-[13px] text-slate-500">
          This instance requires authentication
          {config.mode === "oidc" ? " (SSO)" : config.mode === "both" ? " (SSO or token)" : ""}.
        </p>

        {ssoAvailable && (
          <button
            onClick={ssoLogin}
            className="mt-4 w-full rounded-lg bg-accent px-3 py-2 text-sm font-medium text-white transition hover:opacity-90"
          >
            Sign in with SSO
          </button>
        )}

        {ssoAvailable && (
          <div className="my-4 flex items-center gap-3 text-[11px] uppercase tracking-wide text-slate-400">
            <span className="h-px flex-1 bg-edge" />
            or use a token
            <span className="h-px flex-1 bg-edge" />
          </div>
        )}

        <label className="mt-2 block text-[12px] font-medium text-slate-600">API or access token</label>
        <input
          type="password"
          value={token}
          onChange={(e) => {
            setToken(e.target.value);
            setError(null);
          }}
          onKeyDown={(e) => e.key === "Enter" && submitToken()}
          placeholder="Bearer token"
          className="mt-1 w-full rounded-lg border border-edge bg-ink px-3 py-2 text-sm text-slate-800 outline-hidden focus:border-accent"
          autoFocus={!ssoAvailable}
        />
        {error && <p className="mt-2 text-[12px] text-flag">{error}</p>}
        <button
          onClick={submitToken}
          className="mt-3 w-full rounded-lg border border-edge bg-ink px-3 py-2 text-sm font-medium text-slate-700 transition hover:border-accent/50"
        >
          Continue
        </button>

        <p className="mt-4 text-[11px] leading-relaxed text-slate-400">
          The token is stored only in this tab (sessionStorage) and sent as a Bearer credential. It is never
          written to disk or the bundle.
        </p>
      </div>
    </div>
  );
}

// cleanUrl strips OAuth return params (?code&state, #access_token) so a reload
// doesn't replay the exchange and the address bar stays tidy.
function cleanUrl() {
  const url = new URL(window.location.href);
  ["code", "state", "session_state", "iss", "access_token", "token_type", "expires_in"].forEach((p) =>
    url.searchParams.delete(p),
  );
  url.hash = "";
  window.history.replaceState(null, "", url.pathname + url.search);
}
