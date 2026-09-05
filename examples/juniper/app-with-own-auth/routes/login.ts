/**
 * Server loader + action for the IDP login route (`/login`).
 *
 * `loader` reads the (sanitized) `return_to` the authorize handler preserved
 * when it found no session. `action` validates the credentials against the auth
 * server's user store, opens an IDP session, and redirects back to `return_to`.
 *
 * `return_to` is the server-only `/oauth2/authorize` URL — not a UI route — so
 * a successful sign-in redirects with a full document navigation
 * (`redirectDocument`), letting the browser follow the authorize → callback →
 * return_to chain itself.
 *
 * @module
 */

import { redirectDocument } from "react-router";

import type {
  AnyParams,
  RouteActionArgs,
  RouteLoaderArgs,
} from "@udibo/juniper";
import { safeReturnTo } from "@udibo/oauth2/url";

import { authenticateCredentials } from "@/oauth2/server.ts";
import { createSessionCookie } from "@/sessions.ts";

import type { LoginActionData, LoginLoaderData } from "./login.tsx";

export function loader(
  { request }: RouteLoaderArgs<AnyParams, LoginLoaderData>,
): LoginLoaderData {
  const returnTo = safeReturnTo(
    new URL(request.url).searchParams.get("return_to"),
  );
  return { returnTo };
}

export async function action(
  { request }: RouteActionArgs<AnyParams, LoginActionData>,
): Promise<LoginActionData | Response> {
  const form = await request.formData();
  const username = String(form.get("username") ?? "");
  const password = String(form.get("password") ?? "");
  const returnTo = safeReturnTo(form.get("return_to")?.toString());

  const user = await authenticateCredentials(username, password);
  if (!user) {
    return { error: "Invalid username or password.", returnTo };
  }

  return redirectDocument(returnTo, {
    headers: { "Set-Cookie": createSessionCookie(user.id) },
  });
}
