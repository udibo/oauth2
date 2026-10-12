/**
 * Not part of the public API. Copies a request the server received, for
 * middleware that hands downstream handlers a changed `c.req.raw`.
 *
 * @module
 */

/**
 * `request` with `headers` in place of its own, keeping its URL, method, body
 * stream and the client's abort signal. Built from those parts rather than
 * `new Request(request, …)`, which throws on `@hono/node-server`'s lightweight
 * request unless the adapter replaced the global `Request` (the Vite dev
 * server's does not). The body moves to the copy, so reading it from
 * `request` afterwards finds it used.
 */
export function inboundRequestWithHeaders(
  request: Request,
  headers: Headers,
): Request {
  const init: RequestInit & { duplex: "half" } = {
    method: request.method,
    headers,
    body: request.body,
    signal: request.signal,
    redirect: request.redirect,
    duplex: "half",
  };
  return new Request(request.url, init);
}
