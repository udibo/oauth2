import type { Context } from "hono";
import { RouterContextProvider } from "react-router";

import { requestContext } from "../app/context.ts";
import { config } from "./config.ts";
import { bff } from "./oauth2/server.ts";

/**
 * Builds the router context every loader receives: the BFF session read from
 * the request's cookie and whether the demo account exists. This is how
 * server-rendered pages know who is signed in without a round trip.
 */
export async function createLoadContext(
  c: Context,
): Promise<RouterContextProvider> {
  const context = new RouterContextProvider();
  context.set(requestContext, {
    session: await bff.readSession(c),
    demoAccount: !config.isProduction,
  });
  return context;
}
