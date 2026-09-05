/**
 * Server loader + action for the sign-in form (`/login`). Credentials go
 * through `IdentityService.signIn` (`@/oauth2/identity.ts`), which throttles
 * before the account lookup and equalizes the work it does on every failure,
 * so the response reveals nothing about whether the username exists. On
 * success it opens an IDP session and hands back to the OAuth2 flow via
 * `bff.loginContinuation`, which resumes an in-flight authorize request or
 * starts a fresh BFF login.
 *
 * @module
 */

import { redirectDocument } from "react-router";

import type {
  AnyParams,
  RouteActionArgs,
  RouteLoaderArgs,
} from "@udibo/juniper";
import { isIdentityError } from "@udibo/oauth2/identity";
import { safeReturnTo } from "@udibo/oauth2/url";

import { identity } from "@/oauth2/identity.ts";
import { bff } from "@/oauth2/server.ts";
import { isSameOrigin } from "@/security.ts";
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
  if (!isSameOrigin(request)) {
    return new Response("Cross-site request", { status: 403 });
  }
  const form = await request.formData();
  const username = String(form.get("username") ?? "");
  const password = String(form.get("password") ?? "");
  const returnTo = safeReturnTo(form.get("return_to")?.toString());

  let user: Awaited<ReturnType<typeof identity.signIn>>;
  try {
    user = await identity.signIn({ identifier: username, password });
  } catch (error) {
    if (isIdentityError(error) && error.code === "rate_limited") {
      return {
        error: "Too many sign-in attempts. Try again in a few minutes.",
        returnTo,
      };
    }
    throw error;
  }
  if (!user) {
    return { error: "Invalid username or password.", returnTo };
  }

  return redirectDocument(bff.loginContinuation(returnTo), {
    headers: { "Set-Cookie": createSessionCookie(user.id) },
  });
}
