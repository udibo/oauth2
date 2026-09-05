/**
 * Thin, optional Hono route factory over {@link IdentityService} for the
 * **password-credential** flows.
 *
 * `honoIdentityRoutes(service, opts)` mounts exactly five POST endpoints —
 * `/signup`, `/signin`, `/password/reset-request`, `/password/reset`, and
 * `/email/verify` — by delegating to the service's methods. It is deliberately
 * **not** an opinionated framework: the service methods are the real API, and
 * this just wires the password path to routes for apps that want them mounted
 * (the `IdentityService` stays usable directly from your own
 * routes/loaders/actions).
 *
 * **Scope — password path only, by design.** The newer flows are intentionally
 * *not* mounted here, because their safe wiring carries app-owned policy the
 * factory can't guess. Drive them by calling the service methods from your own
 * handlers, as each guide shows:
 * - **MFA** (enroll / confirm / verify / disable / regenerate, via `MfaService`):
 *   *when* a challenge is required, where the pending challenge state lives, and
 *   the cookie shape are all yours — see `docs/guides/add-mfa.md`.
 * - **Passwordless** (`requestSignInLink` / `consumeSignInLink`,
 *   `requestSignInCode` / `verifySignInCode`): the enumeration-safe response
 *   shape, whether `rate_limited` is swallowed, and IP throttling are yours —
 *   see `docs/guides/passwordless.md`.
 * - **Social / OIDC** (start / callback, via `@udibo/oauth2/identity/external`):
 *   transient `state`/PKCE custody and the account-resolution/linking policy
 *   (where the account-takeover bugs live) are yours — see
 *   `docs/guides/social-sign-in.md`.
 *
 * Session creation stays in your app: the `signup`/`signin` routes call your
 * `onAuthenticated(c, user)` hook on success, where you mint your session and
 * return a `Response` (e.g. a redirect via `bff.loginContinuation`). Omit the
 * hook to mount only the stateless reset/verify routes.
 *
 * Accepts JSON or form-encoded bodies. Responses are simple JSON
 * (`{ ok: true }` / `{ error }`); render your own UI around them. Because a
 * form-encoded POST is exactly what a cross-site page can forge, the routes
 * refuse requests a browser reports as cross-site — see
 * {@link HonoIdentityOptions.csrf}.
 *
 * @module
 */

import { Hono } from "hono";
import type { Context, Handler, MiddlewareHandler } from "hono";

import {
  type IdentityErrorCode,
  identityErrorStatus,
  isIdentityError,
} from "../../identity/errors.ts";
import type { IdentityService, IdentityUser } from "../../identity/service.ts";

/** Paths for the routes mounted by {@link honoIdentityRoutes}. */
export interface HonoIdentityPaths {
  /** `POST` sign-up. Default `/signup`. */
  signUp?: string;
  /** `POST` sign-in. Default `/signin`. */
  signIn?: string;
  /** `POST` password-reset request (enumeration-safe). Default `/password/reset-request`. */
  requestPasswordReset?: string;
  /** `POST` password reset (consume token). Default `/password/reset`. */
  resetPassword?: string;
  /** `POST` email verification (consume token). Default `/email/verify`. */
  verifyEmail?: string;
}

/**
 * Tunes the same-origin guard {@link honoIdentityRoutes} mounts by default.
 * Pass `csrf: false` instead to turn the guard off entirely — only when
 * something in front of these routes already stops cross-site requests.
 */
export interface HonoIdentityCsrfOptions {
  /**
   * Additional origins allowed to post to these routes, as exact
   * `scheme://host[:port]` strings (e.g. `"https://app.example.com"`). Use it
   * when the page holding your sign-in form is served from a different origin
   * than the routes. The origin serving the routes is always allowed.
   */
  allowedOrigins?: string[];
}

/** Options for {@link honoIdentityRoutes}. */
export interface HonoIdentityOptions<User extends IdentityUser> {
  /**
   * Cross-site request protection, **on by default**. These routes carry no
   * token of their own, so the guard reads what the browser states about the
   * request: a `Sec-Fetch-Site` of `same-origin`/`none` passes, any other value
   * is refused, and browsers too old to send it fall back to matching the
   * `Origin` header's host against the request's. A request with neither header
   * — curl, a server-side call, a native app — passes, since cross-site request
   * forgery needs a browser.
   *
   * Refusals get `403` `{ error: "forbidden_origin" }` before any handler runs.
   * Set {@link HonoIdentityCsrfOptions.allowedOrigins} for a legitimate
   * cross-origin caller, or `false` to disable the guard when a proxy or an
   * outer middleware already terminates CSRF.
   */
  csrf?: HonoIdentityCsrfOptions | false;
  /**
   * Called after `signup`/`signin` authenticates a user. Your app owns what
   * happens next — create your session and return a `Response` (e.g. a redirect
   * via `bff.loginContinuation`). **Required to mount the signup/signin routes**;
   * omit it to mount only the stateless reset/verify routes.
   */
  onAuthenticated?: (
    c: Context,
    user: User,
    action: "signUp" | "signIn",
  ) => Response | Promise<Response>;
  /** Override the default paths. */
  paths?: HonoIdentityPaths;
}

/**
 * Wrap a handler so a thrown {@link IdentityError} (e.g. `identifier_taken` from
 * your user store, or `weak_password` from a policy check) becomes a consistent
 * `{ error: code }` response with the conventional status; other errors
 * propagate untouched.
 */
function handle(
  fn: (c: Context) => Response | Promise<Response>,
): Handler {
  return async (c) => {
    try {
      return await fn(c);
    } catch (error) {
      if (!isIdentityError(error)) throw error;
      if (error.retryAfterMs !== undefined) {
        c.header("Retry-After", String(Math.ceil(error.retryAfterMs / 1000)));
      }
      return c.json({ error: error.code }, identityErrorStatus(error.code));
    }
  };
}

const STRING_FIELDS = new Set(["password", "identifier", "email", "token"]);

/**
 * Reads a JSON or form-encoded request body. A JSON body keeps each value's
 * type except for {@link STRING_FIELDS}; a body that is not a JSON object
 * (array, string, `null`) reads as empty. A form-encoded body is all strings by
 * construction.
 */
async function readBody(c: Context): Promise<Record<string, unknown>> {
  const contentType = c.req.header("content-type") ?? "";
  if (contentType.includes("application/json")) {
    try {
      const body = await c.req.json();
      if (typeof body !== "object" || body === null || Array.isArray(body)) {
        return {};
      }
      const out: Record<string, unknown> = {};
      for (const [key, value] of Object.entries(body)) {
        out[key] = STRING_FIELDS.has(key) && value !== null &&
            value !== undefined
          ? String(value)
          : value;
      }
      return out;
    } catch {
      return {};
    }
  }
  try {
    const form = await c.req.formData();
    const out: Record<string, string> = {};
    for (const [key, value] of form) out[key] = String(value);
    return out;
  } catch {
    return {};
  }
}

const FORBIDDEN_ORIGIN: IdentityErrorCode = "forbidden_origin";
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

function hostOf(origin: string): string | undefined {
  try {
    return new URL(origin).host;
  } catch {
    return undefined;
  }
}

function isTrustedOrigin(c: Context, allowedOrigins: Set<string>): boolean {
  const origin = c.req.header("origin");
  const site = c.req.header("sec-fetch-site");
  if (site) {
    return site === "same-origin" || site === "none" ||
      (!!origin && allowedOrigins.has(origin));
  }
  if (!origin) return true;
  return allowedOrigins.has(origin) ||
    hostOf(origin) === new URL(c.req.url).host;
}

/**
 * Refuses an unsafe-method request a browser reports as coming from another
 * site, per {@link HonoIdentityOptions.csrf}.
 */
function sameOriginGuard(options: HonoIdentityCsrfOptions): MiddlewareHandler {
  const allowedOrigins = new Set(options.allowedOrigins ?? []);
  return async (c, next) => {
    if (
      !SAFE_METHODS.has(c.req.method) && !isTrustedOrigin(c, allowedOrigins)
    ) {
      return c.json(
        { error: FORBIDDEN_ORIGIN },
        identityErrorStatus(FORBIDDEN_ORIGIN),
      );
    }
    await next();
  };
}

/**
 * Build a Hono app mounting the password-credential endpoints
 * (`/signup`, `/signin`, `/password/reset-request`, `/password/reset`,
 * `/email/verify`) over `service`. Mount it wherever you like, e.g.
 * `app.route("/auth", honoIdentityRoutes(service, …))`.
 *
 * A JSON body keeps each field's type except `password`, `identifier`, `email`,
 * and `token`, which are coerced to strings when present; on the sign-up route
 * every other field is passed to `service.signUp` as `profile`. A form-encoded
 * body is all strings.
 *
 * Every mounted route sits behind the same-origin guard described in
 * {@link HonoIdentityOptions.csrf}, which is on unless you pass `csrf: false`.
 *
 * Passwordless, MFA, and social are intentionally not mounted — see the module
 * doc for why and where to hand-wire each.
 */
export function honoIdentityRoutes<User extends IdentityUser>(
  service: IdentityService<User>,
  options: HonoIdentityOptions<User> = {},
): Hono {
  const app = new Hono();
  const paths: Required<HonoIdentityPaths> = {
    signUp: "/signup",
    signIn: "/signin",
    requestPasswordReset: "/password/reset-request",
    resetPassword: "/password/reset",
    verifyEmail: "/email/verify",
    ...options.paths,
  };
  const onAuthenticated = options.onAuthenticated;
  if (options.csrf !== false) {
    app.use("*", sameOriginGuard(options.csrf ?? {}));
  }

  if (onAuthenticated) {
    app.post(
      paths.signUp,
      handle(async (c) => {
        const { password, ...profile } = await readBody(c);
        if (typeof password !== "string" || !password) {
          return c.json({ error: "invalid_request" }, 400);
        }
        const user = await service.signUp({ password, profile });
        return await onAuthenticated(c, user, "signUp");
      }),
    );

    app.post(
      paths.signIn,
      handle(async (c) => {
        const body = await readBody(c);
        const user = await service.signIn({
          identifier: String(body.identifier ?? ""),
          password: String(body.password ?? ""),
        });
        if (!user) return c.json({ error: "invalid_credentials" }, 401);
        return await onAuthenticated(c, user, "signIn");
      }),
    );
  }

  app.post(
    paths.requestPasswordReset,
    handle(async (c) => {
      const body = await readBody(c);
      await service.requestPasswordReset(String(body.email ?? ""));
      return c.json({ ok: true });
    }),
  );

  app.post(
    paths.resetPassword,
    handle(async (c) => {
      const body = await readBody(c);
      const result = await service.resetPassword({
        token: String(body.token ?? ""),
        password: String(body.password ?? ""),
      });
      return result
        ? c.json({ ok: true })
        : c.json({ error: "invalid_token" }, 400);
    }),
  );

  app.post(
    paths.verifyEmail,
    handle(async (c) => {
      const body = await readBody(c);
      const result = await service.verifyEmail(String(body.token ?? ""));
      if (result.status === "success") {
        return c.json({ ok: true, userId: result.userId });
      }
      return c.json({ error: `token_${result.status}` }, 400);
    }),
  );

  return app;
}
