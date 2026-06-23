import { useEffect, useState, type ReactNode } from "react";
import { fetchAuthConfig, authToken, setAuthToken, type AuthConfig } from "../api/client";
import { beginPkceLogin, completePkceLogin, randomString } from "../auth/pkce";

// LoginGate fronts the dashboard with a runtime login when the API requires auth.
// It reads GET /auth/config (public) to learn the mode, so the same build works
// whether the backend is open, token-secured, or SSO-secured — no rebuild, no
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
        /* malformed return URL — ignore and fall through to the gate */
      }

      const c = await fetchAuthConfig().catch(
        () => ({ authRequired: false, mode: "none" }) as AuthConfig,
      );
      if (!alive) return;
      setConfig(c);
      setAuthed(!c.authRequired || !!authToken());
      setReady(true);
    }

    init();
    return () => {
      alive = false;
    };
  }, []);

  if (!ready) return null;
  if (authed || !config) return <>{children}</>;

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
          className="mt-1 w-full rounded-lg border border-edge bg-ink px-3 py-2 text-sm text-slate-800 outline-none focus:border-accent"
          autoFocus={!ssoAvailable}
        />
        {error && <p className="mt-2 text-[12px] text-red-600">{error}</p>}
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
