/**
 * A type-resolution canary: the smallest possible consumer of the published
 * package, living outside the workspace with its own import map and
 * `compilerOptions`.
 *
 * `deno check` here resolves `@udibo/oauth2` through the export map in
 * `src/deno.json` — the way an adopter's app resolves it from JSR — instead of
 * through workspace member paths, so a broken export, a missing type, or a JSX
 * entrypoint that only compiles under this repo's `compilerOptions` fails
 * `deno task check` instead of an immutable publish.
 *
 * @module
 */

import type { ReactNode } from "react";

import { BffClient, SIGNED_OUT } from "@udibo/oauth2/client";
import { sha256Hash } from "@udibo/oauth2/crypto";
import {
  DEFAULT_PROXY_FORWARD_HEADERS,
  EncryptedCookieAuthRequestStorage,
  EncryptedCookieSessionStore,
  type HonoBffOptions,
} from "@udibo/oauth2/hono/bff";
import { OAuth2Provider, RequireAuth } from "@udibo/oauth2/react";
import { SignInForm } from "@udibo/oauth2/react/components";
import { redactedRequestTarget, requestLogger } from "@udibo/oauth2/hono/log";

const client = new BffClient();
const signedOut = SIGNED_OUT;
export const logging = requestLogger();
export const callbackTarget = redactedRequestTarget(
  "https://app.example.com/auth/callback?code=secret",
);

export function SmokeConsumer(): ReactNode {
  return (
    <OAuth2Provider client={client} initialState={{ isLoading: false }}>
      <RequireAuth fallback={<SignInForm onSubmit={() => {}} />}>
        <p>{signedOut.isAuthenticated ? "in" : "out"}</p>
      </RequireAuth>
    </OAuth2Provider>
  );
}

export const forwardHeaders: readonly string[] = DEFAULT_PROXY_FORWARD_HEADERS;

export const hash: (value: string) => Promise<string> = sha256Hash;

const SECRET = "a-smoke-consumer-secret-of-at-least-32-bytes";

/**
 * Both encrypted-cookie stores are constructed the same way and assign
 * straight into their `HonoBff` option, so learning one teaches the other.
 */
export const stores: Pick<
  HonoBffOptions,
  "sessionStore" | "authRequestStorage"
> = {
  sessionStore: new EncryptedCookieSessionStore({ secret: SECRET }),
  authRequestStorage: new EncryptedCookieAuthRequestStorage({
    secret: SECRET,
  }),
};
