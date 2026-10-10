import { createContext } from "react-router";

import type { SessionState } from "@udibo/oauth2/client";

/** What the server knows about the request before React Router runs. */
export interface RequestContext {
  /** The BFF session for the request's cookie, with no tokens in it. */
  session: SessionState;
  /** True when the server seeded the demo account (`APP_ENV` is not production). */
  demoAccount: boolean;
}

/** Provided by `server/load-context.ts`; read in root and route loaders. */
export const requestContext = createContext<RequestContext>();
