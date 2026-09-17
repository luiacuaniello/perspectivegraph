import { createContext, useContext } from "react";

// ReadOnlyContext is true on an instance published read-only on purpose
// (API_ANONYMOUS_ROLE, reported by /auth/config as anonymousRole) when this tab holds no
// credential of its own.
//
// Every write on such an instance answers 403 from the backend, which is what keeps it
// read-only; this only decides what the page offers. A visitor used to see Validate,
// Open fix PR, Suppress and Create ticket as live buttons, press one, and get an error -
// the backend was right and the page still looked broken. So the controls stay visible
// (they are how someone learns what the product does) and say why they are off.
export const ReadOnlyContext = createContext(false);

export const useReadOnly = () => useContext(ReadOnlyContext);

export const READ_ONLY_REASON = "Changes are off on this read-only instance";
