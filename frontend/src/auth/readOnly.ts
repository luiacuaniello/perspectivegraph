import { createContext, useContext } from "react";
import type { Me } from "../api/client";

// ReadOnlyContext carries why this tab cannot change anything, or null when it can.
//
// Every write the backend refuses answers 403, which is what enforces it; this only decides
// what the page offers. A visitor used to see Validate, Open fix PR, Suppress and Create
// ticket as live buttons, press one, and get an error - the backend was right and the page
// still looked broken. So the controls stay visible (they are how someone learns what the
// product does), disabled, and say why.
//
// The reason is carried, not just the fact, because there are two and they call for
// different next steps: an instance published read-only takes no changes from anyone
// without a credential, while a viewer signed in to a working instance needs a different
// role. Telling the viewer "this instance is read-only" would send them looking for a
// setting that does not exist.
export const ReadOnlyContext = createContext<string | null>(null);

export const useReadOnly = () => useContext(ReadOnlyContext);

export const READ_ONLY_REASON = "Changes are off on this read-only instance";

export const roleReason = (role: string) => `Signed in as ${role}: changes need the admin role`;

// writeRestriction decides the context's value. `me` is GET /auth/me, or null while it is
// loading or when the backend predates it; `publishedAnonymous` is the guess available
// without it - an instance published read-only, visited without a credential.
export function writeRestriction(me: Me | null, publishedAnonymous: boolean): string | null {
  if (!me) return publishedAnonymous ? READ_ONLY_REASON : null;
  if (me.canWrite) return null;
  return me.anonymous ? READ_ONLY_REASON : roleReason(me.role ?? "this role");
}
