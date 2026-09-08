/**
 * Request logging that removes query values, including OAuth callback credentials.
 *
 * @module hono/log
 */
import type { MiddlewareHandler } from "hono";

/**
 * Produces a request target with every query value replaced by `[redacted]`.
 * Keeps the pathname and percent-encoded parameter names, including repeats,
 * and drops the origin and fragment. Use it before recording a request URL.
 * Paths and parameter names must themselves contain no secrets.
 *
 * @param url An absolute request URL.
 * @returns The pathname followed by redacted query parameters, if any.
 * @throws TypeError if `url` is not a valid absolute URL.
 *
 * @example
 * ```ts
 * import { redactedRequestTarget } from "@udibo/oauth2/hono/log";
 *
 * const target = redactedRequestTarget(
 *   "https://app.example.com/auth/callback?code=secret&state=nonce",
 * );
 * // "/auth/callback?code=[redacted]&state=[redacted]"
 * ```
 */
export function redactedRequestTarget(url: string | URL): string {
  const { pathname, searchParams } = new URL(url);
  const names = [...searchParams.keys()];
  if (names.length === 0) return pathname;
  const query = names
    .map((name) => `${encodeURIComponent(name)}=[redacted]`)
    .join("&");
  return `${pathname}?${query}`;
}

/**
 * Logs Hono requests and responses without any query values. Mount before
 * authentication routes so OAuth callback codes and state stay out of logs.
 * Logs method, redacted target, response status, and elapsed milliseconds;
 * does not log headers or bodies. Paths and parameter names remain visible.
 *
 * @param print Receives each log line; defaults to `console.log`, resolved per line.
 * @returns Middleware emitting a request line and, after downstream completion,
 * a response line.
 *
 * @example
 * ```ts
 * import { Hono } from "hono";
 * import { requestLogger } from "@udibo/oauth2/hono/log";
 *
 * const app = new Hono();
 * app.use(requestLogger());
 * app.get("/", (c) => c.text("Hello"));
 * ```
 */
export function requestLogger(
  print?: (line: string) => void,
): MiddlewareHandler {
  const emit = print ?? ((line: string) => console.log(line));
  return async (c, next) => {
    const target = redactedRequestTarget(c.req.url);
    emit(`<-- ${c.req.method} ${target}`);
    const start = Date.now();
    await next();
    emit(
      `--> ${c.req.method} ${target} ${c.res.status} ${Date.now() - start}ms`,
    );
  };
}
