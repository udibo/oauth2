/**
 * The development identity provider itself: a real {@link AuthorizationServer}
 * over the in-memory services, served on a socket with a sign-in page, an
 * optional consent screen, and a test-control surface under `/__admin/`.
 *
 * Everything here is packaging — the protocol behavior is the same code an
 * application runs in production. What makes it a development tool is the
 * storage (memory, dropped on exit) and the admin endpoints, which mint tokens
 * for any seeded user without their password.
 *
 * Three guardrails are enforced rather than documented: the admin endpoints
 * require a startup token in a custom header (so a browser must preflight, and
 * a drive-by page cannot), a non-loopback bind needs an explicit opt-in, and
 * the issuer is pinned at startup instead of read from the request's `Host`.
 *
 * @module
 */

import type { ClientInterface } from "../../models/client.ts";
import type { BasicScope } from "../../models/scope.ts";
import {
  type AuthenticateUserFn,
  AuthorizationServer,
  type AuthorizationServerOptions,
  type HandleConsentFn,
} from "../../server/authorization-server.ts";
import { AuthorizationCodeGrant } from "../../server/grants/authorization-code.ts";
import { ClientCredentialsGrant } from "../../server/grants/client-credentials.ts";
import { PasswordGrant } from "../../server/grants/password.ts";
import { RefreshTokenGrant } from "../../server/grants/refresh-token.ts";
import {
  type SigningKey,
  StaticSigningKeyProvider,
} from "../../server/signing-keys.ts";
import {
  generateCodeChallenge,
  generateCodeVerifier,
  generateState,
} from "../../utils/pkce.ts";
import { timingSafeEqualString } from "../../utils/crypto.ts";
import { safeReturnTo } from "../../utils/url.ts";
import {
  MemoryAuthorizationCodeService,
  MemoryClientService,
  MemoryTokenService,
  MemoryUserService,
} from "../../testing/services.ts";

import type { DevIdpConfig } from "./config.ts";
import {
  consentPage,
  htmlResponse,
  loginPage,
  messagePage,
  statusPage,
} from "./pages.ts";

const SESSION_COOKIE = "dev_idp_session";
const CONSENT_COOKIE = "dev_idp_consent";
const CONSENT_LIFETIME = 120;

/** Header the admin endpoints require, carrying the token printed at startup. */
export const ADMIN_TOKEN_HEADER = "x-admin-token";

const LOOPBACK_HOSTNAMES = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);
const WILDCARD_HOSTNAMES = new Set(["0.0.0.0", "::", "[::]"]);

/**
 * Whether a bind address only accepts connections from this machine. A
 * non-loopback bind exposes the admin endpoints to the network, so it needs an
 * explicit opt-in.
 */
export function isLoopbackHostname(hostname: string): boolean {
  return LOOPBACK_HOSTNAMES.has(hostname) || hostname.startsWith("127.");
}

/** A seeded user, as the memory services and the OIDC claim mapper see it. */
interface DevIdpUser {
  id: string;
  username: string;
  claims: Record<string, unknown>;
}

interface ConsentDecision {
  userId: string;
  clientId: string;
  approved: boolean;
}

interface DevIdpState {
  server: AuthorizationServer<ClientInterface, DevIdpUser, BasicScope>;
  userService: MemoryUserService<DevIdpUser>;
  clientService: MemoryClientService<ClientInterface, DevIdpUser>;
  sessions: Map<string, string>;
  consents: Map<string, ConsentDecision>;
  secrets: Map<string, string>;
}

async function createState(
  config: DevIdpConfig,
  signingKey: SigningKey,
  issuer: { value: string },
): Promise<DevIdpState> {
  const userService = new MemoryUserService<DevIdpUser>();
  const clientService = new MemoryClientService<ClientInterface, DevIdpUser>(
    userService,
  );
  const tokenService = new MemoryTokenService<
    ClientInterface,
    DevIdpUser,
    BasicScope
  >({
    clientService,
    userService,
    accessTokenLifetime: config.accessTokenLifetime,
  });
  const authorizationCodeService = new MemoryAuthorizationCodeService<
    ClientInterface,
    DevIdpUser,
    BasicScope
  >({ clientService, userService });

  const grants: AuthorizationServerOptions<
    ClientInterface,
    DevIdpUser,
    BasicScope
  >["grants"] = {};
  if (config.grants.authorization_code) {
    grants.authorization_code = new AuthorizationCodeGrant({
      resolve: () => ({
        clientService,
        tokenService,
        authorizationCodeService,
      }),
      allowRefreshToken: config.grants.refresh_token,
    });
  }
  if (config.grants.client_credentials) {
    grants.client_credentials = new ClientCredentialsGrant({
      resolve: () => ({ clientService, tokenService }),
    });
  }
  if (config.grants.refresh_token) {
    grants.refresh_token = new RefreshTokenGrant({
      resolve: () => ({ clientService, tokenService }),
    });
  }
  if (config.grants.password) {
    grants.password = new PasswordGrant({
      resolve: () => ({ clientService, tokenService, userService }),
    });
  }

  const server = new AuthorizationServer<
    ClientInterface,
    DevIdpUser,
    BasicScope
  >({
    resolve: () => ({
      services: { clientService, tokenService },
      issuer: issuer.value,
    }),
    grants,
    scopesSupported: config.scopesSupported,
    signingKeys: new StaticSigningKeyProvider(signingKey),
    userClaims: (user) => ({
      preferred_username: user.username,
      ...user.claims,
    }),
  });

  const secrets = new Map<string, string>();
  for (const user of config.users) {
    await userService.add({
      id: user.id,
      username: user.username,
      claims: user.claims,
    }, user.password);
  }
  for (const client of config.clients) {
    await clientService.add(
      {
        id: client.id,
        grants: client.grants,
        redirectUris: client.redirectUris,
      },
      client.secret,
      client.ownerUserId,
    );
    if (client.secret) secrets.set(client.id, client.secret);
  }

  return {
    server,
    userService,
    clientService,
    sessions: new Map(),
    consents: new Map(),
    secrets,
  };
}

function readCookie(request: Request, name: string): string | undefined {
  const header = request.headers.get("cookie");
  if (!header) return undefined;
  for (const entry of header.split(";")) {
    const separator = entry.indexOf("=");
    if (separator === -1) continue;
    if (entry.slice(0, separator).trim() === name) {
      return decodeURIComponent(entry.slice(separator + 1).trim());
    }
  }
  return undefined;
}

function cookie(
  name: string,
  value: string,
  options: { maxAge?: number; path?: string } = {},
): string {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    `Path=${options.path ?? "/"}`,
    "HttpOnly",
    "SameSite=Lax",
  ];
  if (options.maxAge !== undefined) parts.push(`Max-Age=${options.maxAge}`);
  return parts.join("; ");
}

function redirect(location: string, headers: HeadersInit = {}): Response {
  return new Response(null, {
    status: 303,
    headers: { ...Object.fromEntries(new Headers(headers)), location },
  });
}

function json(body: unknown, status = 200): Response {
  return Response.json(body, {
    status,
    headers: { "cache-control": "no-store" },
  });
}

function jsonError(status: number, message: string): Response {
  return json({ error: message }, status);
}

function rejectUnauthorizedAdmin(
  request: Request,
  adminToken: string,
): Response | undefined {
  if (request.headers.has("origin")) {
    return jsonError(
      403,
      "the admin API refuses browser cross-origin requests; call it from your test runner",
    );
  }
  const presented = request.headers.get(ADMIN_TOKEN_HEADER);
  if (!presented || !timingSafeEqualString(presented, adminToken)) {
    return jsonError(
      401,
      `the admin API requires the ${ADMIN_TOKEN_HEADER} header; its value is printed at startup`,
    );
  }
  if (request.method === "POST") {
    const contentType = request.headers.get("content-type") ?? "";
    if (!contentType.toLowerCase().startsWith("application/json")) {
      return jsonError(
        415,
        "the admin API requires content-type: application/json",
      );
    }
  }
  return undefined;
}

function pathAndQuery(request: Request): string {
  const { pathname, search } = new URL(request.url);
  return `${pathname}${search}`;
}

function formValue(
  form: FormData,
  name: string,
): string | undefined {
  const value = form.get(name);
  return typeof value === "string" ? value : undefined;
}

async function currentUser(
  state: DevIdpState,
  request: Request,
): Promise<DevIdpUser | undefined> {
  const sessionId = readCookie(request, SESSION_COOKIE);
  if (!sessionId) return undefined;
  const userId = state.sessions.get(sessionId);
  if (!userId) return undefined;
  return await state.userService.get(userId);
}

function authenticateUserFor(
  state: DevIdpState,
  config: DevIdpConfig,
  request: Request,
): AuthenticateUserFn<DevIdpUser> {
  return async () => {
    const user = await currentUser(state, request);
    if (user) return { user };
    return htmlResponse(
      loginPage({ returnTo: pathAndQuery(request), users: config.users }),
    );
  };
}

function handleConsentFor(
  state: DevIdpState,
  request: Request,
): HandleConsentFn<ClientInterface, BasicScope> {
  return async (client, requestedScope) => {
    const user = await currentUser(state, request);
    if (!user) return { approved: false };

    const decisionId = readCookie(request, CONSENT_COOKIE);
    const decision = decisionId ? state.consents.get(decisionId) : undefined;
    if (decision && decisionId) {
      state.consents.delete(decisionId);
      if (decision.userId === user.id && decision.clientId === client.id) {
        return { approved: decision.approved };
      }
    }

    return htmlResponse(consentPage({
      clientId: client.id,
      scope: requestedScope?.toString() || undefined,
      username: user.username,
      returnTo: pathAndQuery(request),
    }));
  };
}

async function handleLoginSubmission(
  state: DevIdpState,
  config: DevIdpConfig,
  request: Request,
): Promise<Response> {
  const form = await request.formData();
  const returnTo = safeReturnTo(formValue(form, "return_to"));
  const quickSignIn = formValue(form, "as");

  let user: DevIdpUser | undefined;
  let error: string | undefined;
  if (quickSignIn !== undefined && quickSignIn.length > 0) {
    user = await state.userService.findByUsername(quickSignIn);
    if (!user) error = `No seeded user named "${quickSignIn}".`;
  } else {
    const username = formValue(form, "username");
    const password = formValue(form, "password");
    user = username !== undefined && password !== undefined
      ? await state.userService.getAuthenticated(username, password)
      : undefined;
    if (!user) error = "Unknown username or password.";
  }

  if (!user) {
    return htmlResponse(
      loginPage({ returnTo, users: config.users, error }),
      401,
    );
  }

  const sessionId = crypto.randomUUID();
  state.sessions.set(sessionId, user.id);
  return redirect(returnTo, {
    "set-cookie": cookie(SESSION_COOKIE, sessionId),
  });
}

async function handleConsentSubmission(
  state: DevIdpState,
  request: Request,
): Promise<Response> {
  const user = await currentUser(state, request);
  if (!user) return redirect("/login");

  const form = await request.formData();
  const returnTo = safeReturnTo(formValue(form, "return_to"));
  const target = new URL(returnTo, request.url);
  const clientId = target.searchParams.get("client_id");
  if (target.pathname !== "/authorize" || !clientId) {
    return htmlResponse(
      messagePage("Invalid consent request", "Start again from your app."),
      400,
    );
  }

  const decisionId = crypto.randomUUID();
  state.consents.set(decisionId, {
    userId: user.id,
    clientId,
    approved: form.get("decision") === "approve",
  });
  return redirect(returnTo, {
    "set-cookie": cookie(CONSENT_COOKIE, decisionId, {
      maxAge: CONSENT_LIFETIME,
    }),
  });
}

function handleLogout(
  state: DevIdpState,
  config: DevIdpConfig,
  request: Request,
): Response {
  const sessionId = readCookie(request, SESSION_COOKIE);
  if (sessionId) state.sessions.delete(sessionId);

  const expired = cookie(SESSION_COOKIE, "", { maxAge: 0 });
  const postLogout = new URL(request.url).searchParams.get(
    "post_logout_redirect_uri",
  );
  if (postLogout) {
    const registered = config.clients.some((client) =>
      client.redirectUris.includes(postLogout)
    );
    if (registered) {
      return redirect(postLogout, { "set-cookie": expired });
    }
    return htmlResponse(
      messagePage(
        "Invalid logout request",
        "post_logout_redirect_uri must exactly match a redirect URI registered by one of the configured clients.",
      ),
      400,
    );
  }
  return new Response(
    messagePage("Signed out", "The session was dropped."),
    {
      status: 200,
      headers: {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
        "set-cookie": expired,
      },
    },
  );
}

async function readJsonBody(
  request: Request,
): Promise<Record<string, unknown>> {
  const text = await request.text();
  if (text.trim().length === 0) return {};
  const parsed: unknown = JSON.parse(text);
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("body must be a JSON object");
  }
  return parsed as Record<string, unknown>;
}

async function resolveRequestedUser(
  state: DevIdpState,
  body: Record<string, unknown>,
): Promise<DevIdpUser | undefined> {
  if (typeof body.userId === "string") {
    return await state.userService.get(body.userId);
  }
  if (typeof body.username === "string") {
    return await state.userService.findByUsername(body.username);
  }
  return undefined;
}

async function handleAdminSession(
  state: DevIdpState,
  request: Request,
): Promise<Response> {
  const body = await readJsonBody(request);
  const user = await resolveRequestedUser(state, body);
  if (!user) {
    return jsonError(400, 'no seeded user matched "userId" or "username"');
  }
  const sessionId = crypto.randomUUID();
  state.sessions.set(sessionId, user.id);
  return new Response(
    JSON.stringify({
      sessionId,
      cookie: SESSION_COOKIE,
      user: { id: user.id, username: user.username },
    }),
    {
      status: 200,
      headers: {
        "content-type": "application/json",
        "cache-control": "no-store",
        "set-cookie": cookie(SESSION_COOKIE, sessionId),
      },
    },
  );
}

async function handleAdminTokens(
  state: DevIdpState,
  config: DevIdpConfig,
  request: Request,
): Promise<Response> {
  const body = await readJsonBody(request);
  const user = await resolveRequestedUser(state, body);
  if (!user) {
    return jsonError(400, 'no seeded user matched "userId" or "username"');
  }
  if (typeof body.clientId !== "string") {
    return jsonError(400, '"clientId" is required');
  }
  const client = await state.clientService.get(body.clientId);
  if (!client) return jsonError(400, `unknown client "${body.clientId}"`);
  if (!client.grants?.includes("authorization_code")) {
    return jsonError(
      400,
      `client "${client.id}" is not registered for the authorization_code grant`,
    );
  }
  const redirectUri = typeof body.redirectUri === "string"
    ? body.redirectUri
    : client.redirectUris?.[0];
  if (!redirectUri) {
    return jsonError(400, `client "${client.id}" has no redirect URI`);
  }
  const scope = typeof body.scope === "string"
    ? body.scope
    : config.scopesSupported.join(" ");

  const verifier = generateCodeVerifier();
  const origin = new URL(request.url).origin;
  const authorizeUrl = new URL("/authorize", origin);
  authorizeUrl.search = new URLSearchParams({
    response_type: "code",
    client_id: client.id,
    redirect_uri: redirectUri,
    scope,
    state: generateState(),
    code_challenge: await generateCodeChallenge(verifier),
    code_challenge_method: "S256",
  }).toString();

  const authorized = await state.server.handleAuthorizeRequest(
    new Request(authorizeUrl),
    () => Promise.resolve({ user }),
  );
  const location = authorized.headers.get("location");
  if (!location) {
    return jsonError(400, "the authorization request was rejected");
  }
  const authorizeParams = new URL(location).searchParams;
  const code = authorizeParams.get("code");
  if (!code) {
    return jsonError(
      400,
      authorizeParams.get("error_description") ??
        authorizeParams.get("error") ?? "the authorization request failed",
    );
  }

  const form = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    client_id: client.id,
    code_verifier: verifier,
  });
  const secret = state.secrets.get(client.id);
  if (secret) form.set("client_secret", secret);
  return await state.server.handleTokenRequest(
    new Request(new URL("/token", origin), {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: form,
    }),
  );
}

function adminState(
  state: DevIdpState,
  config: DevIdpConfig,
  issuer: string,
): Response {
  return json({
    issuer,
    users: config.users.map((user) => ({
      id: user.id,
      username: user.username,
    })),
    clients: config.clients.map((client) => ({
      id: client.id,
      confidential: client.secret !== undefined,
      redirectUris: client.redirectUris,
      grants: client.grants,
    })),
    sessions: state.sessions.size,
  });
}

/** A running development identity provider. */
export interface DevIdentityProvider {
  /** Base URL the server is reachable at. */
  url: string;
  /** Issuer pinned at startup and stamped into every token and metadata document. */
  issuer: string;
  /** Token the `/__admin/` endpoints require in {@link ADMIN_TOKEN_HEADER}. */
  adminToken: string;
  /** Port the server bound. Resolved when the config asked for port `0`. */
  port: number;
  /** Hostname the server bound. */
  hostname: string;
  /** Resolves once the server has finished shutting down. */
  finished: Promise<void>;
  /** Stops accepting connections and drains in-flight requests. */
  shutdown(): Promise<void>;
}

/** Options for {@link startDevIdentityProvider}. */
export interface StartDevIdentityProviderOptions {
  /** Resolved configuration, as returned by the config parser. */
  config: DevIdpConfig;
  /** Key the server signs id_tokens with and publishes at `/jwks`. */
  signingKey: SigningKey;
  /**
   * Token the admin endpoints require. Generated when omitted; supply one so a
   * CI job can hold it before the server starts.
   */
  adminToken?: string;
  /**
   * Permits binding a non-loopback address, which exposes the admin endpoints
   * to the network. Refused unless this is explicitly set.
   */
  allowRemoteAccess?: boolean;
}

/**
 * Starts the development identity provider on a socket and resolves once it is
 * accepting connections.
 *
 * The caller owns the lifetime: keep the returned {@link DevIdentityProvider}
 * and call `shutdown()` (a test's `finally`, a CI teardown step). Nothing is
 * written to disk and no state survives the process.
 *
 * **This server is for development and CI only.** Its `/__admin/` endpoints
 * mint tokens for any seeded user without their password; they are gated by
 * {@link DevIdentityProvider.adminToken}, not by anything stronger.
 *
 * @throws {Error} When the config binds a non-loopback address without
 * `allowRemoteAccess`.
 *
 * @example
 * ```ts
 * const idp = await startDevIdentityProvider({
 *   config: defaultDevIdpConfig(),
 *   signingKey: await generateSigningKey(),
 * });
 * try {
 *   const discovery = await fetch(
 *     `${idp.url}/.well-known/openid-configuration`,
 *   );
 *   // ...point the app under test at the discovered endpoints.
 * } finally {
 *   await idp.shutdown();
 * }
 * ```
 */
export async function startDevIdentityProvider(
  options: StartDevIdentityProviderOptions,
): Promise<DevIdentityProvider> {
  const { config, signingKey } = options;
  if (!isLoopbackHostname(config.hostname) && !options.allowRemoteAccess) {
    throw new Error(
      `refusing to bind ${config.hostname}: a non-loopback address exposes the ` +
        `admin endpoints, which mint tokens for any seeded user. Pass ` +
        `--unsafe-remote-access if the network really is one you control.`,
    );
  }
  const adminToken = options.adminToken ?? crypto.randomUUID();
  const issuer = { value: config.issuer ?? "" };
  let state = await createState(config, signingKey, issuer);

  const handler = async (request: Request): Promise<Response> => {
    const { pathname } = new URL(request.url);
    const { method } = request;

    if (pathname.startsWith("/__admin/")) {
      const rejected = rejectUnauthorizedAdmin(request, adminToken);
      if (rejected) return rejected;
    }

    try {
      switch (pathname) {
        case "/":
          return htmlResponse(statusPage({
            issuer: issuer.value,
            users: config.users,
            clients: config.clients,
          }));
        case "/authorize":
          return await state.server.handleAuthorizeRequest(
            request,
            authenticateUserFor(state, config, request),
            config.consent === "prompt"
              ? handleConsentFor(state, request)
              : undefined,
          );
        case "/token":
          return await state.server.handleTokenRequest(request);
        case "/revoke":
          return await state.server.handleRevocationRequest(request);
        case "/introspect":
          return await state.server.handleIntrospectionRequest(request);
        case "/userinfo":
          return await state.server.handleUserInfoRequest(request);
        case "/jwks":
          return await state.server.handleJwksRequest(request);
        case "/.well-known/openid-configuration":
          return await state.server.handleOidcMetadataRequest(request);
        case "/.well-known/oauth-authorization-server":
          return await state.server.handleMetadataRequest(request);
        case "/login":
          if (method === "POST") {
            return await handleLoginSubmission(state, config, request);
          }
          return htmlResponse(loginPage({
            returnTo: safeReturnTo(
              new URL(request.url).searchParams.get("return_to"),
            ),
            users: config.users,
          }));
        case "/consent":
          if (method !== "POST") return jsonError(405, "method must be POST");
          return await handleConsentSubmission(state, request);
        case "/logout":
          return handleLogout(state, config, request);
        case "/__admin/reset":
          if (method !== "POST") return jsonError(405, "method must be POST");
          state = await createState(config, signingKey, issuer);
          return json({ reset: true });
        case "/__admin/session":
          if (method !== "POST") return jsonError(405, "method must be POST");
          return await handleAdminSession(state, request);
        case "/__admin/tokens":
          if (method !== "POST") return jsonError(405, "method must be POST");
          return await handleAdminTokens(state, config, request);
        case "/__admin/state":
          return adminState(state, config, issuer.value);
        default:
          return jsonError(404, `no route for ${pathname}`);
      }
    } catch (error) {
      return jsonError(
        400,
        error instanceof Error ? error.message : String(error),
      );
    }
  };

  const server = Deno.serve({
    port: config.port,
    hostname: config.hostname,
    onListen: () => {},
  }, handler);

  const { hostname, port } = server.addr;
  const host = hostname.includes(":") ? `[${hostname}]` : hostname;
  const url = `http://${host}:${port}`;
  issuer.value ||= `http://${
    WILDCARD_HOSTNAMES.has(hostname) ? "localhost" : host
  }:${port}`;
  return {
    url,
    issuer: issuer.value,
    adminToken,
    hostname,
    port,
    finished: server.finished,
    shutdown: () => server.shutdown(),
  };
}
