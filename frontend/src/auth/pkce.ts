// OIDC Authorization Code + PKCE (RFC 7636) for the dashboard's SSO login.
//
// PKCE lets a public client (a browser SPA with no secret) exchange an
// authorization code safely: the client sends a hash of a random verifier on the
// way out, and the verifier itself on the token exchange, so an intercepted code
// is useless without it. The access token never leaves the browser and is stored
// only in this tab's sessionStorage (see client.ts).

const PKCE_KEY = "pg-pkce";

function base64url(bytes: ArrayBuffer): string {
  let s = "";
  const arr = new Uint8Array(bytes);
  for (const b of arr) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// randomString returns a URL-safe high-entropy string of the given length.
export function randomString(len = 64): string {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return base64url(arr.buffer).slice(0, len);
}

// generateCodeVerifier returns a PKCE code_verifier (43–128 URL-safe chars).
export function generateCodeVerifier(): string {
  return randomString(64);
}

// codeChallenge derives the S256 code_challenge = BASE64URL(SHA-256(verifier)).
export async function codeChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64url(digest);
}

interface PendingPkce {
  verifier: string;
  state: string;
  tokenUrl: string;
  clientId: string;
  redirectUri: string;
}

export interface OidcParams {
  authorizeUrl?: string | null;
  tokenUrl?: string | null;
  clientId?: string | null;
  scopes?: string | null;
}

function redirectUri(): string {
  return window.location.origin + window.location.pathname;
}

// beginPkceLogin starts the Authorization Code + PKCE flow: it stashes the
// verifier + state (to survive the redirect) and navigates to the IdP.
export async function beginPkceLogin(oidc: OidcParams): Promise<void> {
  const verifier = generateCodeVerifier();
  const challenge = await codeChallenge(verifier);
  const state = randomString(32);
  const pending: PendingPkce = {
    verifier,
    state,
    tokenUrl: oidc.tokenUrl || "",
    clientId: oidc.clientId || "",
    redirectUri: redirectUri(),
  };
  sessionStorage.setItem(PKCE_KEY, JSON.stringify(pending));
  const params = new URLSearchParams({
    response_type: "code",
    client_id: oidc.clientId || "",
    redirect_uri: pending.redirectUri,
    scope: oidc.scopes || "openid",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  window.location.href = `${oidc.authorizeUrl}?${params.toString()}`;
}

// completePkceLogin exchanges the authorization code for an access token. It
// verifies the returned state (CSRF) against the stashed one and POSTs the
// verifier to the token endpoint. Returns the access token, or throws.
export async function completePkceLogin(code: string, returnedState: string): Promise<string> {
  const raw = sessionStorage.getItem(PKCE_KEY);
  if (!raw) throw new Error("no PKCE login in progress");
  sessionStorage.removeItem(PKCE_KEY);
  const pending = JSON.parse(raw) as PendingPkce;
  if (!pending.state || pending.state !== returnedState) {
    throw new Error("state mismatch - possible CSRF, login aborted");
  }
  if (!pending.tokenUrl) throw new Error("no token endpoint configured");

  const res = await fetch(pending.tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: pending.redirectUri,
      client_id: pending.clientId,
      code_verifier: pending.verifier,
    }).toString(),
  });
  if (!res.ok) throw new Error(`token exchange failed (${res.status})`);
  const json = (await res.json()) as { access_token?: string };
  if (!json.access_token) throw new Error("no access_token in token response");
  return json.access_token;
}
