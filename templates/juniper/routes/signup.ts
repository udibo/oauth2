/**
 * Server loader + action for the sign-up form (`/signup`). `IdentityService`
 * (`@/oauth2/identity.ts`) enforces the password policy and rejects a taken
 * username; on success it creates the account, the action opens an IDP
 * session, and `bff.loginContinuation` hands back to the OAuth2 flow so the
 * new user lands in the app already signed in.
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

import type { SignupActionData, SignupLoaderData } from "./signup.tsx";

const MESSAGES: Record<string, string> = {
  identifier_taken: "That username is already taken.",
  weak_password: "Password must be at least 8 characters.",
};

export function loader(
  { request }: RouteLoaderArgs<AnyParams, SignupLoaderData>,
): SignupLoaderData {
  const returnTo = safeReturnTo(
    new URL(request.url).searchParams.get("return_to"),
  );
  return { returnTo };
}

export async function action(
  { request }: RouteActionArgs<AnyParams, SignupActionData>,
): Promise<SignupActionData | Response> {
  if (!isSameOrigin(request)) {
    return new Response("Cross-site request", { status: 403 });
  }
  const form = await request.formData();
  const username = String(form.get("username") ?? "").trim();
  const name = String(form.get("name") ?? "").trim();
  const password = String(form.get("password") ?? "");
  const returnTo = safeReturnTo(form.get("return_to")?.toString());

  if (!username || !name) {
    return { error: "Username and name are required.", returnTo };
  }

  let user;
  try {
    user = await identity.signUp({ password, profile: { username, name } });
  } catch (error) {
    if (isIdentityError(error) && MESSAGES[error.code]) {
      return { error: MESSAGES[error.code], returnTo };
    }
    throw error;
  }

  return redirectDocument(bff.loginContinuation(returnTo), {
    headers: { "Set-Cookie": createSessionCookie(user.id) },
  });
}
