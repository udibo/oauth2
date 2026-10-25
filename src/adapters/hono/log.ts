/**
 * Request logging that removes query values, including OAuth callback credentials.
 *
 * @module hono/log
 */
import { AsyncLocalStorage } from "node:async_hooks";

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

interface OuterRequest {
  calls: string[];
  answered: boolean;
}

function summary(
  method: string,
  url: string,
  status: number,
  started: number,
): string {
  return `${method} ${redactedRequestTarget(url)} ${status} ${
    Date.now() - started
  }ms`;
}

/**
 * Logs each Hono request as one line, written when the response is ready,
 * without any query values. Mount before authentication routes so OAuth
 * callback codes and state stay out of logs. Logs method, redacted target,
 * response status and elapsed milliseconds; does not log headers or bodies.
 * Paths and parameter names remain visible. A request whose handler throws
 * something Hono does not answer (a non-`Error`) is still logged, as `500`.
 *
 * A request this middleware sees while it is handling another one (the app
 * calling its own `fetch` from a handler or a server-rendered page's loader) is
 * folded into the outer request's line, in brackets, in completion order,
 * instead of writing its own. One that completes after the outer response was
 * ready gets its own line, marked `(in-process)`; that includes a request
 * started later from a timer or promise the outer request created. Each
 * `requestLogger()` call folds only the requests it sees itself, so a sub-app
 * with its own logger writes to its own sink.
 *
 * @param print Receives each log line; defaults to `console.log`, resolved per line.
 * @returns Middleware emitting one line per request after downstream completion.
 *
 * @example
 * ```ts
 * import { Hono } from "hono";
 * import { requestLogger } from "@udibo/oauth2/hono/log";
 *
 * const app = new Hono();
 * app.use(requestLogger());
 * app.get("/", (c) => c.text("Hello"));
 * // --> GET /?code=[redacted] 200 3ms
 * ```
 */
export function requestLogger(
  print?: (line: string) => void,
): MiddlewareHandler {
  const emit = print ?? ((line: string) => console.log(line));
  const outerRequest = new AsyncLocalStorage<OuterRequest>();
  return async (c, next) => {
    const started = Date.now();
    const outer = outerRequest.getStore();
    let status = 500;
    if (outer) {
      try {
        await next();
        status = c.res.status;
      } finally {
        const call = summary(c.req.method, c.req.url, status, started);
        if (outer.answered) emit(`--> (in-process) ${call}`);
        else outer.calls.push(call);
      }
      return;
    }
    const request: OuterRequest = { calls: [], answered: false };
    try {
      await outerRequest.run(request, next);
      status = c.res.status;
    } finally {
      request.answered = true;
      const calls =
        request.calls.length === 0 ? "" : ` [${request.calls.join(", ")}]`;
      emit(`--> ${summary(c.req.method, c.req.url, status, started)}${calls}`);
    }
  };
}
