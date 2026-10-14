import { setTimeout as delay } from "node:timers/promises";
import { assert, describe, expect, it, vi } from "vitest";
import {
  type Reply,
  type ReplyServer,
  serveReplies,
} from "../../_test_response-server.ts";
import {
  type ControlledTimeouts,
  controlTimeouts,
} from "../../_test_timeouts.ts";
import { encodeBase64 } from "../../utils/_encoding.ts";
import { base64urlEncode } from "../../utils/crypto.ts";
import { appleProvider } from "./apple.ts";
import { ExternalAuthError } from "./errors.ts";
import { githubProvider } from "./github.ts";
import { oauth2Provider } from "./oauth2.ts";
import { oidcProvider } from "./oidc.ts";
import type { ExternalProfile, ExternalProvider } from "./provider.ts";

const redirectUri = "https://app.example/cb";
const TOKEN_RESPONSE: Reply = {
  body: JSON.stringify({ access_token: "at", token_type: "Bearer" }),
  transfer: "length",
};

type StallPoint =
  | "before the response headers"
  | "before the first body byte"
  | "after a partial body";

const STALL_POINTS: StallPoint[] = [
  "before the response headers",
  "before the first body byte",
  "after a partial body",
];

function stalledReply(point: StallPoint, status = 200): Reply {
  if (point === "before the response headers") return { transfer: "silent" };
  return {
    status,
    body: point === "after a partial body" ? '{"sub":"sso-1","id":7' : "",
    transfer: "stall",
  };
}

/** What the client had seen of the stalled request when it was observed. */
interface StalledRead {
  fetch: typeof fetch;
  /** Whether the client is now waiting at `point`. */
  reached(point: StallPoint): boolean;
  /** The signal the connector sent the stalled request with. */
  readonly signal: AbortSignal | null | undefined;
  /** The deadline requested for that signal. */
  readonly deadlineMs: number | undefined;
}

/**
 * A `fetch` that sends every request to `server` over the real global
 * `fetch`, forwarding `init` untouched, and watches the one to `path`.
 */
function watchStalledRead(
  server: ReplyServer,
  path: string,
  timeouts: ControlledTimeouts,
): StalledRead {
  let arrived = false;
  let headers = false;
  let bodyBytes = 0;
  let signal: AbortSignal | null | undefined;
  let deadlineMs: number | undefined;
  return {
    async fetch(input, init) {
      const url = new URL(input instanceof Request ? input.url : input);
      if (url.pathname !== path) {
        return await fetch(`${server.origin}${url.pathname}`, init);
      }
      signal = init?.signal;
      if (signal) deadlineMs = timeouts.requested.at(-1);
      arrived = true;
      const response = await fetch(`${server.origin}${url.pathname}`, init);
      headers = true;
      if (!response.body) return response;
      const counted = response.body.pipeThrough(
        new TransformStream<Uint8Array, Uint8Array>({
          transform(chunk, controller) {
            bodyBytes += chunk.byteLength;
            controller.enqueue(chunk);
          },
        }),
      );
      return new Response(counted, {
        status: response.status,
        headers: response.headers,
      });
    },
    reached(point) {
      if (point === "before the response headers") return arrived;
      if (point === "before the first body byte") return headers;
      return bodyBytes > 0;
    },
    get signal() {
      return signal;
    },
    get deadlineMs() {
      return deadlineMs;
    },
  };
}

type Settled<T> =
  | { status: "fulfilled"; value: T }
  | { status: "rejected"; reason: unknown };

function settle<T>(promise: Promise<T>): Promise<Settled<T>> {
  return promise.then(
    (value) => ({ status: "fulfilled", value }),
    (reason: unknown) => ({ status: "rejected", reason }),
  );
}

async function settledWithin<T>(
  pending: Promise<Settled<T>>,
  ms: number,
): Promise<Settled<T> | "pending"> {
  const timer = new AbortController();
  try {
    return await Promise.race([
      pending,
      delay(ms, "pending" as const, { signal: timer.signal }),
    ]);
  } finally {
    timer.abort();
  }
}

/**
 * Starts `fetchProfile`, waits until the client is stuck at `point`, proves
 * the read is still waiting there, then expires the deadlines and returns how
 * the profile read settled. Fails if it has not settled soon after.
 */
async function profileAtDeadline(
  provider: ExternalProvider,
  read: StalledRead,
  point: StallPoint,
  timeouts: ControlledTimeouts,
): Promise<Settled<ExternalProfile>> {
  const pending = settle(provider.fetchProfile({ code: "code", redirectUri }));
  await vi.waitFor(() => expect(read.reached(point)).toBe(true));
  expect(
    await settledWithin(pending, 50),
    "the read ended before its deadline",
  ).toBe("pending");

  timeouts.expireAll();

  const outcome = await settledWithin(pending, 2_000);
  assert(
    outcome !== "pending",
    "the read was still waiting after its deadline",
  );
  expect(read.signal?.aborted).toBe(true);
  expect(read.signal?.reason).toMatchObject({ name: "TimeoutError" });
  expect(read.deadlineMs).toBe(10_000);
  return outcome;
}

function refusal(
  outcome: Settled<ExternalProfile>,
  messageIncludes: string,
): ExternalAuthError {
  assert(outcome.status === "rejected", "expected the profile read to fail");
  const error = outcome.reason;
  expect(error).toBeInstanceOf(ExternalAuthError);
  assert(error instanceof ExternalAuthError);
  expect(error.code).toBe("provider_error");
  expect(error.message).toContain(messageIncludes);
  return error;
}

function routes(table: Record<string, Reply>): (pathname: string) => Reply {
  return (pathname) =>
    table[pathname] ?? { status: 404, body: "{}", transfer: "length" };
}

const segment = (value: unknown): string =>
  base64urlEncode(new TextEncoder().encode(JSON.stringify(value)));

describe("external provider read deadline", () => {
  for (const point of STALL_POINTS) {
    describe(`a provider that stalls ${point}`, () => {
      it("is refused at the deadline by the generic profile read", async () => {
        using timeouts = controlTimeouts();
        await using server = await serveReplies(
          routes({
            "/token": TOKEN_RESPONSE,
            "/userinfo": stalledReply(point),
          }),
        );
        const read = watchStalledRead(server, "/userinfo", timeouts);
        const provider = oauth2Provider({
          id: "acme",
          displayName: "Acme",
          authorizationEndpoint: `${server.origin}/authorize`,
          tokenEndpoint: `${server.origin}/token`,
          userInfoEndpoint: `${server.origin}/userinfo`,
          clientId: "client",
          clientSecret: "secret",
          defaultScopes: ["identify"],
          mapProfile: ({ profile }) => ({ subject: String(profile.id) }),
          fetch: read.fetch,
        });

        const outcome = await profileAtDeadline(
          provider,
          read,
          point,
          timeouts,
        );

        const error = refusal(outcome, "[acme]");
        expect(error.message).toContain("Acme profile endpoint");
        await server.abandoned;
      });

      for (const path of ["/user", "/user/emails"]) {
        it(`is refused at the deadline by GitHub's ${path} read`, async () => {
          using timeouts = controlTimeouts();
          await using server = await serveReplies(
            routes({
              "/login/oauth/access_token": TOKEN_RESPONSE,
              "/user": { body: '{"id":7}', transfer: "length" },
              "/user/emails": { body: "[]", transfer: "length" },
              [path]: stalledReply(point),
            }),
          );
          const read = watchStalledRead(server, path, timeouts);
          const provider = githubProvider({
            clientId: "client",
            clientSecret: "secret",
            fetch: read.fetch,
          });

          const outcome = await profileAtDeadline(
            provider,
            read,
            point,
            timeouts,
          );

          refusal(outcome, `https://api.github.com${path}`);
          await server.abandoned;
        });
      }

      it("is refused at the deadline by Apple's JWKS read", async () => {
        using timeouts = controlTimeouts();
        const pair = await crypto.subtle.generateKey(
          { name: "ECDSA", namedCurve: "P-256" },
          true,
          ["sign", "verify"],
        );
        const pkcs8 = await crypto.subtle.exportKey("pkcs8", pair.privateKey);
        await using server = await serveReplies(
          routes({
            "/auth/token": {
              body: JSON.stringify({
                id_token: `${segment({ alg: "RS256", kid: "k" })}.${segment({})}.sig`,
              }),
              transfer: "length",
            },
            "/auth/keys": stalledReply(point),
          }),
        );
        const read = watchStalledRead(server, "/auth/keys", timeouts);
        const provider = appleProvider({
          clientId: "com.example.web",
          teamId: "ABCDE12345",
          keyId: "KEY1234567",
          privateKey: `-----BEGIN PRIVATE KEY-----\n${encodeBase64(
            new Uint8Array(pkcs8),
          )}\n-----END PRIVATE KEY-----`,
          fetch: read.fetch,
        });

        const outcome = await profileAtDeadline(
          provider,
          read,
          point,
          timeouts,
        );

        refusal(outcome, "Apple's JWKS endpoint");
        await server.abandoned;
      });

      it("gives up on OIDC UserInfo at the deadline and keeps the id_token claims", async () => {
        using timeouts = controlTimeouts();
        const issuer = "https://sso.example";
        const idToken = `${segment({ alg: "ES256" })}.${segment({
          iss: issuer,
          aud: "client",
          sub: "sso-1",
          email: "id-token@example.com",
          exp: Math.floor(Date.now() / 1000) + 3600,
        })}.sig`;
        await using server = await serveReplies(
          routes({
            "/.well-known/openid-configuration": {
              body: JSON.stringify({
                issuer,
                authorization_endpoint: `${issuer}/authorize`,
                token_endpoint: `${issuer}/token`,
                userinfo_endpoint: `${issuer}/userinfo`,
              }),
              transfer: "length",
            },
            "/token": {
              body: JSON.stringify({
                access_token: "at",
                token_type: "Bearer",
                id_token: idToken,
              }),
              transfer: "length",
            },
            "/userinfo": stalledReply(point),
          }),
        );
        const read = watchStalledRead(server, "/userinfo", timeouts);
        const provider = oidcProvider({
          issuer,
          clientId: "client",
          clientSecret: "secret",
          fetch: read.fetch,
        });

        const outcome = await profileAtDeadline(
          provider,
          read,
          point,
          timeouts,
        );

        assert(outcome.status === "fulfilled", "expected the id_token profile");
        expect(outcome.value.subject).toBe("sso-1");
        expect(outcome.value.email).toBe("id-token@example.com");
        await server.abandoned;
      });
    });
  }

  for (const point of [
    "before the first body byte",
    "after a partial body",
  ] as const) {
    it(`reports a profile error status whose body stalls ${point} at the deadline`, async () => {
      using timeouts = controlTimeouts();
      await using server = await serveReplies(
        routes({
          "/token": TOKEN_RESPONSE,
          "/userinfo": stalledReply(point, 401),
        }),
      );
      const read = watchStalledRead(server, "/userinfo", timeouts);
      const provider = oauth2Provider({
        id: "acme",
        displayName: "Acme",
        authorizationEndpoint: `${server.origin}/authorize`,
        tokenEndpoint: `${server.origin}/token`,
        userInfoEndpoint: `${server.origin}/userinfo`,
        clientId: "client",
        clientSecret: "secret",
        defaultScopes: ["identify"],
        mapProfile: ({ profile }) => ({ subject: String(profile.id) }),
        fetch: read.fetch,
      });

      const outcome = await profileAtDeadline(provider, read, point, timeouts);

      const error = refusal(
        outcome,
        "profile endpoint responded with HTTP 401. ",
      );
      expect(error.message).not.toContain("sso-1");
      await server.abandoned;
    });
  }
});
