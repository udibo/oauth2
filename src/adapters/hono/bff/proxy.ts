/**
 * Header hygiene and URL resolution for {@link HonoBff.proxy}.
 *
 * The proxy is the "full BFF" shape from the IETF "OAuth 2.0 for Browser-Based
 * Apps" BCP §6.1.1: the browser calls the BFF, the BFF forwards to a **separate**
 * resource server with the session's access token attached, and the response is
 * streamed back. This module owns the parts that are pure functions of the
 * request — which headers cross the boundary in each direction, and which
 * upstream URL an inbound path maps to.
 *
 * @module
 */

/**
 * Options for {@link HonoBff.proxy}. The upstream base URL is a separate
 * argument because it is fixed at configuration time: nothing about the target
 * is ever derived from the request.
 */
export interface HonoBffProxyOptions {
  /**
   * Mount prefix removed from the request path before it is appended to the
   * upstream base. Mounting at `/api/*` against `https://api.example.com/v1`
   * with `stripPrefix: "/api"` maps `GET /api/things?page=2` to
   * `GET https://api.example.com/v1/things?page=2`. Omit to append the full
   * request path.
   */
  stripPrefix?: string;
  /**
   * Request headers forwarded upstream, replacing
   * {@link DEFAULT_PROXY_FORWARD_HEADERS}. Spread the default to extend it:
   * `[...DEFAULT_PROXY_FORWARD_HEADERS, "x-tenant"]`. Matched
   * case-insensitively. `Cookie`, `Authorization`, `Host`, the CSRF header, and
   * the hop-by-hop headers are dropped even when listed here.
   */
  forwardHeaders?: readonly string[];
  /**
   * Retry once with a freshly refreshed access token when the upstream answers
   * `401` with an `error="invalid_token"` challenge. Defaults to `true`.
   * Requests that carry a body are never retried — the body has already been
   * streamed upstream and buffering it would defeat the streaming — so those
   * `401`s pass through as-is.
   */
  retryOn401?: boolean;
  /**
   * `fetch` used for the upstream call. Defaults to the global. Inject a stub
   * in tests to assert what crosses the boundary without running a server.
   */
  fetch?: (input: URL, init: RequestInit) => Promise<Response>;
}

/**
 * Hop-by-hop headers (RFC 9110 §7.6.1). They describe a single transport
 * connection, so a proxy must not pass them through in either direction.
 */
const HOP_BY_HOP_HEADERS: readonly string[] = [
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
];

/**
 * Request headers forwarded upstream unless {@link HonoBffProxyOptions.forwardHeaders}
 * replaces the list. Content negotiation, conditional requests, ranges, and the
 * common tracing headers — everything a resource server needs to answer
 * correctly, and nothing that identifies the BFF's own session.
 */
export const DEFAULT_PROXY_FORWARD_HEADERS: readonly string[] = [
  "accept",
  "accept-language",
  "content-language",
  "content-type",
  "if-match",
  "if-modified-since",
  "if-none-match",
  "if-unmodified-since",
  "range",
  "user-agent",
  "baggage",
  "traceparent",
  "tracestate",
  "x-request-id",
];

/**
 * Never forwarded upstream, even when named in
 * {@link HonoBffProxyOptions.forwardHeaders}. `cookie` and `authorization` are
 * the security-critical entries: the browser's session cookie is the BFF's
 * credential (not the API's), and an inbound `Authorization` must never be able
 * to override the token the BFF attaches. `accept-encoding` and `content-length`
 * are dropped because `fetch` owns content coding and body framing.
 */
const NEVER_FORWARDED_REQUEST_HEADERS: readonly string[] = [
  ...HOP_BY_HOP_HEADERS,
  "accept-encoding",
  "authorization",
  "content-length",
  "cookie",
  "cookie2",
  "host",
];

/**
 * Never returned to the browser. `set-cookie` is dropped so an upstream API
 * cannot plant cookies on the BFF's origin, where they would ride along with
 * the session cookie.
 */
const NEVER_RETURNED_RESPONSE_HEADERS: readonly string[] = [
  ...HOP_BY_HOP_HEADERS,
  "set-cookie",
];

/**
 * Dropped only when a body is actually streamed back: `fetch` has already
 * decoded it, so the upstream's content coding and length no longer describe
 * what the browser receives. A body-less response (`HEAD`, `204`, `304`) was
 * never decoded, and there `Content-Length` *is* the answer.
 */
const DECODED_BODY_RESPONSE_HEADERS: readonly string[] = [
  "content-encoding",
  "content-length",
];

/** Case-insensitive header name set. */
function headerSet(names: readonly string[]): Set<string> {
  return new Set(names.map((name) => name.toLowerCase()));
}

/**
 * Resolves the effective request-forward allowlist: the caller's list (or the
 * default) minus everything that must never leave the BFF, including the CSRF
 * header, which is a BFF-internal signal.
 */
export function resolveForwardHeaders(
  forwardHeaders: readonly string[] | undefined,
  csrfHeaderName: string | undefined,
): Set<string> {
  const allowed = headerSet(forwardHeaders ?? DEFAULT_PROXY_FORWARD_HEADERS);
  const denied = headerSet(NEVER_FORWARDED_REQUEST_HEADERS);
  if (csrfHeaderName) denied.add(csrfHeaderName.toLowerCase());
  for (const name of denied) allowed.delete(name);
  return allowed;
}

/**
 * Builds the upstream request headers: the allowlisted inbound headers plus the
 * session's bearer token. The session cookie, any inbound `Authorization`, and
 * every hop-by-hop header are left behind by construction — this starts from an
 * empty `Headers` and only copies what `allowed` names.
 */
export function buildUpstreamHeaders(
  inbound: Headers,
  allowed: Set<string>,
  accessToken: string,
): Headers {
  const headers = new Headers();
  for (const [name, value] of inbound) {
    if (allowed.has(name.toLowerCase())) headers.set(name, value);
  }
  headers.set("Authorization", `Bearer ${accessToken}`);
  return headers;
}

/**
 * The header names an upstream `Connection` field lists. RFC 9110 §7.6.1 makes
 * those connection-specific too, so a proxy must drop them alongside the
 * well-known hop-by-hop set.
 */
function connectionNamedHeaders(headers: Headers): string[] {
  return (headers.get("connection") ?? "")
    .split(",")
    .map((name) => name.trim().toLowerCase())
    .filter((name) => name.length > 0);
}

/** Headers whose value is a URL into the upstream's namespace. */
const URL_VALUED_RESPONSE_HEADERS: readonly string[] = [
  "location",
  "content-location",
];

/**
 * Rewrites an upstream URL into the mount's namespace, so a `Location` naming
 * the resource server neither leaks internal topology to the browser nor points
 * it at a host it cannot reach. A relative value resolves against the upstream
 * request first. Anything outside the configured base is left alone — it is a
 * genuinely external destination, not part of what this mount proxies.
 */
function rewriteUpstreamUrl(
  value: string,
  upstreamUrl: URL,
  base: URL,
  mountPrefix: string,
): string {
  let resolved: URL;
  try {
    resolved = new URL(value, upstreamUrl);
  } catch {
    return value;
  }
  if (resolved.origin !== base.origin) return value;

  const basePath = base.pathname.endsWith("/")
    ? base.pathname.slice(0, -1)
    : base.pathname;
  const underBase = basePath === "" ||
    resolved.pathname === basePath ||
    resolved.pathname.startsWith(`${basePath}/`);
  if (!underBase) return value;

  const suffix = resolved.pathname.slice(basePath.length) || "/";
  return `${mountPrefix}${suffix}${resolved.search}${resolved.hash}`;
}

/** Adds `name` to `Vary` without disturbing what the upstream already varies on. */
function appendVary(headers: Headers, name: string): void {
  const existing = headers.get("vary");
  if (!existing) {
    headers.set("vary", name);
    return;
  }
  if (existing.trim() === "*") return;
  const present = existing
    .split(",")
    .some((token) => token.trim().toLowerCase() === name.toLowerCase());
  if (!present) headers.set("vary", `${existing}, ${name}`);
}

/**
 * Forces the response private. Upstream sees an `Authorization`-protected
 * request, which RFC 9111 §3.5 already keeps out of shared caches; downstream
 * the same response is authenticated by a cookie, which carries no such rule.
 */
function forcePrivateCache(headers: Headers): void {
  const existing = headers.get("cache-control");
  if (!existing) {
    headers.set("cache-control", "private");
    return;
  }
  const directives = existing
    .split(",")
    .map((directive) => directive.trim().toLowerCase());
  if (
    directives.some((directive) =>
      directive === "private" || directive === "no-store" ||
      directive.startsWith("private=")
    )
  ) {
    return;
  }
  headers.set("cache-control", `private, ${existing}`);
}

/**
 * Builds the browser-facing response headers: everything except hop-by-hop
 * headers (the fixed set and whatever `Connection` names), upstream
 * `Set-Cookie`, and — when a body is actually streamed back — the content
 * coding and length that `fetch` already resolved.
 *
 * URL-valued headers are rewritten into the mount's namespace, and the result
 * is marked `private` + `Vary: Cookie` (it is cookie-authenticated) and
 * `nosniff` (an upstream body is served from the BFF's own origin).
 */
export function buildDownstreamHeaders(
  upstream: Response,
  context: { upstreamUrl: URL; base: URL; mountPrefix: string },
): Headers {
  const denied = headerSet(NEVER_RETURNED_RESPONSE_HEADERS);
  for (const name of connectionNamedHeaders(upstream.headers)) {
    denied.add(name);
  }
  if (upstream.body !== null) {
    for (const name of DECODED_BODY_RESPONSE_HEADERS) denied.add(name);
  }

  const urlValued = headerSet(URL_VALUED_RESPONSE_HEADERS);
  const headers = new Headers();
  for (const [name, value] of upstream.headers) {
    if (denied.has(name.toLowerCase())) continue;
    headers.append(
      name,
      urlValued.has(name.toLowerCase())
        ? rewriteUpstreamUrl(
          value,
          context.upstreamUrl,
          context.base,
          context.mountPrefix,
        )
        : value,
    );
  }

  appendVary(headers, "Cookie");
  forcePrivateCache(headers);
  headers.set("X-Content-Type-Options", "nosniff");
  return headers;
}

/**
 * Rejects a path segment that would become a dot segment once decoded.
 *
 * Fails closed on a malformed escape: `decodeURIComponent` throws on overlong
 * or invalid UTF-8 (`%C0%AF`, the classic `/` smuggle), and a lenient upstream
 * decoder may still reconstruct the separator, so the segment cannot be
 * forwarded unexamined. Encoded separators themselves are allowed through —
 * `a%2Fb` is a legitimate resource id — it is only `..` between them that is
 * refused.
 *
 * @throws {TypeError} If the segment has a malformed escape or hides `..`.
 */
function assertSafeSegment(segment: string): void {
  let decoded: string;
  try {
    decoded = decodeURIComponent(segment);
  } catch {
    throw new TypeError("proxy path segment has a malformed escape sequence");
  }
  if (decoded.split(/[/\\]/).some((part) => part === "..")) {
    throw new TypeError("proxy path segment hides a dot segment");
  }
}

/**
 * Maps an inbound request URL onto the configured upstream base.
 *
 * The base is fixed at configuration time and only the path and query travel
 * with the request, so the target can never be steered by the caller. `URL`
 * resolves dot segments (percent-encoded ones included) while parsing, so what
 * remains to defend against is a segment that only becomes `../` once an
 * upstream server decodes it again — see {@link assertSafeSegment}.
 *
 * Query strings are merged rather than replaced: a parameter pinned on the
 * target survives every request and **wins** over an inbound parameter of the
 * same name, so a browser cannot override what the mount configured.
 *
 * @param stripPrefix Mount prefix removed from the path before joining.
 * @throws {TypeError} If a path segment has a malformed escape or hides `..`.
 */
export function resolveProxyUrl(
  base: URL,
  requestUrl: string,
  stripPrefix?: string,
): URL {
  const inbound = new URL(requestUrl);
  let path = inbound.pathname;

  if (stripPrefix) {
    const prefix = stripPrefix.endsWith("/")
      ? stripPrefix.slice(0, -1)
      : stripPrefix;
    if (path === prefix) {
      path = "/";
    } else if (path.startsWith(`${prefix}/`)) {
      path = path.slice(prefix.length);
    }
  }

  for (const segment of path.split("/")) assertSafeSegment(segment);

  const basePath = base.pathname.endsWith("/")
    ? base.pathname.slice(0, -1)
    : base.pathname;
  const suffix = path.startsWith("/") ? path : `/${path}`;

  const url = new URL(base);
  url.pathname = `${basePath}${suffix}`;
  url.search = inbound.search;
  for (const name of new Set(base.searchParams.keys())) {
    url.searchParams.delete(name);
  }
  for (const [name, value] of base.searchParams) {
    url.searchParams.append(name, value);
  }
  url.hash = "";
  return url;
}

/**
 * Whether an upstream `401` is the kind a token refresh could fix. Mirrors the
 * `WWW-Authenticate: ... error="invalid_token"` gate `DirectClient.fetch`
 * applies (quotes optional here, since not every server emits them), so a `401`
 * meaning "wrong user" or "no such thing" passes straight through instead of
 * burning a refresh.
 */
export function isInvalidTokenChallenge(response: Response): boolean {
  if (response.status !== 401) return false;
  const challenge = response.headers.get("WWW-Authenticate") ?? "";
  return /error\s*=\s*"?invalid_token"?/i.test(challenge);
}
