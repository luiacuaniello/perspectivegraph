import { useState } from "react";

// Whether the explainer banner is showing, and the two actions that change it.
//
// It lives in its own module rather than beside the banner because a file that exports
// both a component and a hook defeats React Fast Refresh: an edit to either forces a full
// reload instead of a hot update. Splitting them is the fix the lint rule
// react-refresh/only-export-components is actually asking for.

const KEY = "pg_intro_dismissed_v1";
// OPEN_VALUE is the stored flag for "the reader asked to see this", the inverse of
// the old dismissed flag. A new key would have been equivalent; reusing this one
// with inverted meaning would silently re-open the banner for everyone who had
// dismissed it, so the name changes with the semantics.
const OPEN_KEY = "pg_intro_open_v1";

export function useIntroDismissed() {
  const [dismissed, setDismissed] = useState<boolean>(() => {
    try {
      // Closed unless explicitly opened. The legacy key is still honoured so a
      // reader who dismissed the old banner is never shown it again either way.
      return localStorage.getItem(OPEN_KEY) !== "1" || localStorage.getItem(KEY) === "1";
    } catch {
      return true;
    }
  });
  const dismiss = () => {
    try {
      localStorage.removeItem(OPEN_KEY);
      localStorage.setItem(KEY, "1");
    } catch {
      /* ignore */
    }
    setDismissed(true);
  };
  const reopen = () => {
    try {
      localStorage.setItem(OPEN_KEY, "1");
      localStorage.removeItem(KEY);
    } catch {
      /* ignore */
    }
    setDismissed(false);
  };
  return { dismissed, dismiss, reopen };
}
