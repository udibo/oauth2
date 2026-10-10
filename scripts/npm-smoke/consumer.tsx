/**
 * The type-resolution half of the npm smoke test: a consumer that statically
 * imports every subpath of the packed `@udibo/oauth2` tarball under
 * `moduleResolution: "NodeNext"`, the way `tsc` in a Node project resolves
 * `npm install @udibo/oauth2`. `scripts/npm-smoke.ts` asserts this file imports
 * every subpath in the export map, so a subpath cannot silently drop out of
 * type-check coverage. `main.mjs` is the runtime half.
 *
 * @module
 */

import type { ReactNode } from "react";

import { BffClient, SIGNED_OUT } from "@udibo/oauth2/client";
import { sha256Hash } from "@udibo/oauth2/crypto";
import {
  DEFAULT_PBKDF2_ITERATIONS,
  MemoryOtpStore,
} from "@udibo/oauth2/identity";
import {
  DEFAULT_DISCOVERY_TTL_MS,
  MemoryDiscoveryCache,
} from "@udibo/oauth2/identity/external";
import { MemoryMfaStore, type MfaService } from "@udibo/oauth2/identity/mfa";
import {
  findLegacyVerifier,
  parsePhc,
  type PhcHash,
} from "@udibo/oauth2/identity/migration";
import { HonoAuthorizationServer } from "@udibo/oauth2/hono/authorization-server";
import {
  DEFAULT_PROXY_FORWARD_HEADERS,
  EncryptedCookieAuthRequestStorage,
  EncryptedCookieSessionStore,
  type HonoBffOptions,
} from "@udibo/oauth2/hono/bff";
import {
  createTestSession,
  type CreateTestSessionOptions,
} from "@udibo/oauth2/hono/bff/testing";
import { honoIdentityRoutes } from "@udibo/oauth2/hono/identity";
import { redactedRequestTarget, requestLogger } from "@udibo/oauth2/hono/log";
import {
  HonoResourceServer,
  OAUTH2_CONTEXT_KEY,
} from "@udibo/oauth2/hono/resource-server";
import { OAuth2Provider, RequireAuth } from "@udibo/oauth2/react";
import { SignInForm } from "@udibo/oauth2/react/components";
import {
  createMockBffClient,
  MockOAuth2Provider,
} from "@udibo/oauth2/react/testing";
import { BasicScope, isOAuth2Error } from "@udibo/oauth2/server";
import { AuthorizationServer } from "@udibo/oauth2/server/authorization";
import { isPublicSuffix } from "@udibo/oauth2/server/public-suffix";
import { BEARER_TOKEN, ResourceServer } from "@udibo/oauth2/server/resource";
import { loginContinuation, safeReturnTo } from "@udibo/oauth2/url";
import { createFakeTenant } from "@udibo/oauth2/testing";
import { runLockoutStoreContractTests } from "@udibo/oauth2/testing/contract";

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

export function MockedSmokeConsumer(): ReactNode {
  return (
    <MockOAuth2Provider client={createMockBffClient()}>
      <p>mocked</p>
    </MockOAuth2Provider>
  );
}

export const hash: (value: string) => Promise<string> = sha256Hash;

const SECRET = "an-npm-smoke-consumer-secret-of-at-least-32-bytes";

export const stores: Pick<
  HonoBffOptions,
  "sessionStore" | "authRequestStorage"
> = {
  sessionStore: new EncryptedCookieSessionStore({ secret: SECRET }),
  authRequestStorage: new EncryptedCookieAuthRequestStorage({
    secret: SECRET,
  }),
};

export const forwardHeaders: readonly string[] = DEFAULT_PROXY_FORWARD_HEADERS;

export const scope: BasicScope = new BasicScope("openid");
export const errorGuard: typeof isOAuth2Error = isOAuth2Error;

export const authorizationServerCtor: typeof AuthorizationServer =
  AuthorizationServer;

export const bearer: RegExp = BEARER_TOKEN;
export const resourceServerCtor: typeof ResourceServer = ResourceServer;

export const comIsPublicSuffix: boolean = isPublicSuffix("com");

export const pbkdf2Iterations: number = DEFAULT_PBKDF2_ITERATIONS;
export const otpStore: MemoryOtpStore = new MemoryOtpStore();

export const discoveryTtlMs: number = DEFAULT_DISCOVERY_TTL_MS;
export const discoveryCache: MemoryDiscoveryCache = new MemoryDiscoveryCache();

export const mfaStoreCtor: typeof MemoryMfaStore = MemoryMfaStore;
export type Mfa = MfaService;

export const parsed: PhcHash | null = parsePhc(
  "$pbkdf2-sha256$i=600000$c2FsdA$aGFzaA",
);
export const verifierFinder: typeof findLegacyVerifier = findLegacyVerifier;

export const honoAuthorizationServerCtor: typeof HonoAuthorizationServer =
  HonoAuthorizationServer;

export const testSessionFactory: typeof createTestSession = createTestSession;
export type TestSessionOptions = CreateTestSessionOptions;

export const identityRoutes: typeof honoIdentityRoutes = honoIdentityRoutes;

export const honoResourceServerCtor: typeof HonoResourceServer =
  HonoResourceServer;
export const contextKey: string = OAUTH2_CONTEXT_KEY;

export const continuation: typeof loginContinuation = loginContinuation;
export const returnTo: typeof safeReturnTo = safeReturnTo;

export const fakeTenantFactory: typeof createFakeTenant = createFakeTenant;
export const lockoutContract: typeof runLockoutStoreContractTests =
  runLockoutStoreContractTests;
