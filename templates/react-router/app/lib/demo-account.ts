import { useRouteLoaderData } from "react-router";

import type { loader as rootLoader } from "../root.tsx";

/**
 * True when the server seeded the demo account, so sign-in hints only appear
 * where the account actually exists. Read from the root loader, so it is
 * correct in the server-rendered HTML.
 */
export function useDemoAccount(): boolean {
  return useRouteLoaderData<typeof rootLoader>("root")?.demoAccount === true;
}
