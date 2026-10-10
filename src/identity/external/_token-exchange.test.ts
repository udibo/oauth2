import { setTimeout as delay } from "node:timers/promises";
import { assert, describe, expect, it, vi } from "vitest";
import { rejection } from "../../_test_assert.ts";
import { serve } from "../../_test_server.ts";
import { controlTimeouts } from "../../_test_timeouts.ts";
import { PROVIDER_TEXT_MAX_LENGTH } from "./_shared.ts";
import {
  MAX_TOKEN_RESPONSE_BYTES,
  runTokenExchange,
} from "./_token-exchange.ts";
import { appleProvider } from "./apple.ts";
import { discordProvider } from "./discord.ts";
import { ExternalAuthError } from "./errors.ts";
import { githubProvider } from "./github.ts";
import { oidcProvider } from "./oidc.ts";
import type { ExternalProvider } from "./provider.ts";

const redirectUri = "https://app.example/auth/social/callback";

type Handler = (request: Request) => Response | Promise<Response>;

async function withServer<T>(
  handler: Handler,
  run: (origin: string) => Promise<T>,
): Promise<T> {
  const server = await serve(handler);
  try {
    return await run(server.origin);
  } finally {
    await server.shutdown();
  }
}

function rewriteToOrigin(origin: string): typeof fetch {
  return (input, init) => {
    const target = new URL(
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.href
          : input.url,
    );
    return fetch(new URL(target.pathname + target.search, origin), init);
  };
}

function respond(body: BodyInit | null, init: ResponseInit = {}): Handler {
  return () => new Response(body, init);
}

const json = (value: unknown, status = 200): Handler =>
  respond(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" },
  });

const html = (body: string, status = 200): Handler =>
  respond(body, { status, headers: { "content-type": "text/html" } });

interface ExchangeOverrides {
  requiredField?: string;
  fetch?: typeof fetch;
  timeoutMs?: number;
}

function exchange(
  origin: string,
  overrides: ExchangeOverrides = {},
): Promise<{ value: string; raw: Record<string, unknown> }> {
  return runTokenExchange({
    provider: "acme",
    displayName: "Acme",
    endpoint: `${origin}/token`,
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: "the-code",
      redirect_uri: redirectUri,
      client_id: "acme-client",
      client_secret: "acme-secret",
    }),
    requiredField: overrides.requiredField ?? "access_token",
    fetch: overrides.fetch ?? globalThis.fetch,
    httpErrorHint: "Check the Acme app registration.",
    tokenErrorHint: (code) =>
      code === undefined
        ? "The response carried no token."
        : `Acme reported ${code}.`,
    timeoutMs: overrides.timeoutMs,
  });
}

function rejects(
  origin: string,
  overrides: ExchangeOverrides = {},
): Promise<ExternalAuthError> {
  return rejection(() => exchange(origin, overrides), ExternalAuthError);
}

describe("runTokenExchange", () => {
  it("posts the form-encoded body a provider expects over a real socket", async () => {
    let contentType: string | null = null;
    let accept: string | null = null;
    let form = new URLSearchParams();
    const result = await withServer(
      async (request) => {
        contentType = request.headers.get("content-type");
        accept = request.headers.get("accept");
        form = new URLSearchParams(await request.text());
        return Response.json({ access_token: "at", token_type: "bearer" });
      },
      (origin) => exchange(origin),
    );

    expect(contentType!).toContain("application/x-www-form-urlencoded");
    expect(accept).toStrictEqual("application/json");
    expect(form.get("grant_type")).toStrictEqual("authorization_code");
    expect(form.get("code")).toStrictEqual("the-code");
    expect(form.get("redirect_uri")).toStrictEqual(redirectUri);
    expect(form.get("client_id")).toStrictEqual("acme-client");
    expect(form.get("client_secret")).toStrictEqual("acme-secret");
    expect(result.value).toStrictEqual("at");
    expect(result.raw.token_type).toStrictEqual("bearer");
  });

  it("returns any required field the connector names", async () => {
    const result = await withServer(
      json({ id_token: "header.payload.signature" }),
      (origin) => exchange(origin, { requiredField: "id_token" }),
    );
    expect(result.value).toStrictEqual("header.payload.signature");
  });

  it("never replays the client credentials to a redirect target", async () => {
    let sinkHits = 0;
    await withServer(
      async (request) => {
        sinkHits++;
        await request.text();
        return Response.json({ access_token: "stolen" });
      },
      async (sinkOrigin) => {
        const error = await withServer(
          respond(null, {
            status: 307,
            headers: { location: `${sinkOrigin}/` },
          }),
          (origin) => rejects(origin),
        );
        expect(error.code).toStrictEqual("provider_error");
        expect(error.message).toContain("redirect");
        expect(error.message).toContain("HTTP 307");
        expect(
          sinkHits,
          "the redirect target must never be contacted",
        ).toStrictEqual(0);
      },
    );
  });

  it("refuses a 308 redirect as well", async () => {
    const error = await withServer(
      respond(null, {
        status: 308,
        headers: { location: "https://evil.example/" },
      }),
      (origin) => rejects(origin),
    );
    expect(error.message).toContain("HTTP 308");
  });

  it("bounds and flattens every hostile field at once", async () => {
    const hostile =
      `\u001b[31mred\u001b[0m\nERROR forged log line\r\n` + "x".repeat(50_000);
    const error = await withServer(
      json({
        error: `bad\u001b[0m\ncode` + "c".repeat(50_000),
        error_description: hostile,
        error_uri: `https://evil.example/\n` + "u".repeat(50_000),
      }),
      (origin) => rejects(origin),
    );
    expect(
      error.message.includes("\n"),
      "message must stay single-line",
    ).toBeFalsy();
    expect(
      error.message.includes("\r"),
      "message must stay single-line",
    ).toBeFalsy();
    expect(
      error.message.includes("\u001b"),
      "ANSI escapes must not survive",
    ).toBeFalsy();
    assert(
      error.message.length < 1_000,
      `message must stay bounded, got ${error.message.length}`,
    );
  });

  it("caps each provider-supplied string at the echo limit", async () => {
    const error = await withServer(
      json({
        error: "e".repeat(5_000),
        error_uri: `https://evil.example/${"u".repeat(5_000)}`,
      }),
      (origin) => rejects(origin),
    );
    expect(
      error.message.includes("e".repeat(PROVIDER_TEXT_MAX_LENGTH + 1)),
      "the error code must be capped",
    ).toBeFalsy();
    expect(
      error.message.includes("u".repeat(PROVIDER_TEXT_MAX_LENGTH + 1)),
      "the error_uri must be capped",
    ).toBeFalsy();
  });

  it("surfaces error_uri so a non-standard pointer is not dropped", async () => {
    const error = await withServer(
      json({ error: "invalid_grant", error_uri: "https://docs.example/e42" }),
      (origin) => rejects(origin),
    );
    expect(error.message).toContain("https://docs.example/e42");
  });

  it("bounds a hostile content-type echo", async () => {
    const error = await withServer(
      respond("not json", {
        headers: { "content-type": `text/${"x".repeat(5_000)}` },
      }),
      (origin) => rejects(origin),
    );
    expect(
      error.message.includes("x".repeat(PROVIDER_TEXT_MAX_LENGTH + 1)),
      "the content-type must be capped",
    ).toBeFalsy();
  });

  it("sanitizes the raw bytes a JSON parse error echoes back", async () => {
    const error = await withServer(
      respond(`\r\n\u001b[31mFORGED audit line\u0000` + "z".repeat(5_000), {
        headers: { "content-type": "application/json" },
      }),
      (origin) => rejects(origin),
    );
    expect(error.message.includes("\n"), "must stay single-line").toBeFalsy();
    expect(error.message.includes("\r"), "must stay single-line").toBeFalsy();
    expect(
      error.message.includes("\u001b"),
      "ANSI must not survive",
    ).toBeFalsy();
    expect(
      error.message.includes("\u0000"),
      "NUL must not survive",
    ).toBeFalsy();
    assert(
      error.message.length < 1_000,
      `message must stay bounded, got ${error.message.length}`,
    );
  });

  it("never truncates a hostile body into a lone surrogate", async () => {
    const error = await withServer(
      respond("\u{1F600}".repeat(5_000), {
        headers: { "content-type": "application/json" },
      }),
      (origin) => rejects(origin),
    );
    assert(error.message.isWellFormed(), "message must be well-formed UTF-16");
  });

  it("marks the echo as truncated when a non-2xx body overruns the cap", async () => {
    const error = await withServer(
      respond("o".repeat(MAX_TOKEN_RESPONSE_BYTES + 1_000), { status: 502 }),
      (origin) => rejects(origin),
    );
    expect(error.message).toContain("HTTP 502");
    expect(error.message).toContain("(truncated)");
  });

  it("refuses a token response larger than the byte cap", async () => {
    const oversized = JSON.stringify({
      access_token: "at",
      padding: "p".repeat(MAX_TOKEN_RESPONSE_BYTES + 1_000),
    });
    const error = await withServer(
      respond(oversized, { headers: { "content-type": "application/json" } }),
      (origin) => rejects(origin),
    );
    expect(error.message).toContain("exceeded");
    expect(error.message).toContain(String(MAX_TOKEN_RESPONSE_BYTES));
  });

  it("abandons an endpoint that drips the body past the deadline", async () => {
    using timeouts = controlTimeouts();
    const drips = new AbortController();
    let dripped = 0;
    const error = await withServer(
      () => {
        const stream = new ReadableStream({
          async pull(controller) {
            try {
              await delay(20, { signal: drips.signal });
            } catch {
              controller.close();
              return;
            }
            dripped++;
            controller.enqueue(new TextEncoder().encode(" ".repeat(1024)));
          },
          cancel() {
            drips.abort();
          },
        });
        return new Response(stream, {
          headers: { "content-type": "application/json" },
        });
      },
      async (origin) => {
        const pending = rejects(origin, { timeoutMs: 100 });
        await vi.waitFor(() => expect(dripped).toBeGreaterThan(0));
        await timeouts.expireOnceRequested(1);
        const rejection = await pending;
        drips.abort();
        return rejection;
      },
    );

    expect(timeouts.requested).toStrictEqual([100]);
    expect(error.code).toStrictEqual("provider_error");
    expect(error.message).toContain("[acme]");
  });

  it("still reports the status when a non-2xx body cannot be read", async () => {
    const error = await withServer(
      () => {
        const stream = new ReadableStream({
          start(controller) {
            controller.enqueue(new TextEncoder().encode("part"));
            controller.error(new Error("stream blew up"));
          },
        });
        return new Response(stream, { status: 502 });
      },
      (origin) => rejects(origin),
    );

    expect(error.message).toContain("HTTP 502");
    expect(error.message).toContain("Check the Acme app registration.");
  });

  it("maps a provider HTML error page instead of throwing SyntaxError", async () => {
    const error = await withServer(
      html("<html><body>502 Bad Gateway</body></html>"),
      (origin) => rejects(origin),
    );
    expect(error.code).toStrictEqual("provider_error");
    expect(error.message).toContain("[acme]");
    expect(error.message).toContain("not valid JSON");
    expect(error.message).toContain(`"text/html"`);
  });

  it("maps an empty 200 body", async () => {
    const error = await withServer(respond(null), (origin) => rejects(origin));
    expect(error.message).toContain("not valid JSON");
  });

  it("maps a JSON null body instead of throwing TypeError", async () => {
    const error = await withServer(json(null), (origin) => rejects(origin));
    expect(error.code).toStrictEqual("provider_error");
    expect(error.message).toContain("JSON null");
    expect(error.message).toContain("JSON object was required");
  });

  it("maps a JSON array body", async () => {
    const error = await withServer(json([{ access_token: "at" }]), (origin) =>
      rejects(origin),
    );
    expect(error.message).toContain("a JSON array");
  });

  it("maps a JSON scalar body", async () => {
    const error = await withServer(json("access_token=at"), (origin) =>
      rejects(origin),
    );
    expect(error.message).toContain("a JSON string");
  });

  it("maps an OAuth2 error body returned with HTTP 200", async () => {
    const error = await withServer(
      json({
        error: "invalid_grant",
        error_description: "code already redeemed",
      }),
      (origin) => rejects(origin),
    );
    expect(error.message).toContain("token exchange failed");
    expect(error.message).toContain(`"invalid_grant"`);
    expect(error.message).toContain("code already redeemed");
    expect(error.message).toContain("Acme reported invalid_grant.");
  });

  it("rejects a body that reports an error alongside a token", async () => {
    const error = await withServer(
      json({ access_token: "at", error: "invalid_scope" }),
      (origin) => rejects(origin),
    );
    expect(error.message).toContain("invalid_scope");
  });

  it("maps a non-200 OAuth2 error body and keeps both hints", async () => {
    const error = await withServer(
      json({ error: "invalid_client" }, 401),
      (origin) => rejects(origin),
    );
    expect(error.message).toContain(`HTTP 401: "invalid_client".`);
    expect(error.message).toContain("Acme reported invalid_client.");
    expect(error.message).toContain("Check the Acme app registration.");
  });

  it("keeps a non-JSON error body and the http hint on a non-200 status", async () => {
    const error = await withServer(
      respond("upstream unavailable", { status: 502 }),
      (origin) => rejects(origin),
    );
    expect(error.message).toContain("HTTP 502");
    expect(error.message).toContain("upstream unavailable");
    expect(error.message).toContain("Check the Acme app registration.");
  });

  it("bounds the echoed body of a large non-200 error page", async () => {
    const error = await withServer(
      html(`<html>${"x".repeat(5000)}</html>`, 500),
      (origin) => rejects(origin),
    );
    expect(error.message).toContain("HTTP 500");
    assert(
      error.message.length < 400,
      `echoed body must stay truncated, got ${error.message.length}`,
    );
  });

  it("maps a body whose required field is absent", async () => {
    const error = await withServer(json({ token_type: "bearer" }), (origin) =>
      rejects(origin),
    );
    expect(error.message).toContain("missing access_token");
    expect(error.message).toContain("The response carried no token.");
  });

  it("maps a body whose required field is the wrong type", async () => {
    const wrongType = await withServer(
      json({ access_token: 12345 }),
      (origin) => rejects(origin),
    );
    expect(wrongType.message).toContain("missing access_token");

    const empty = await withServer(json({ access_token: "" }), (origin) =>
      rejects(origin),
    );
    expect(empty.message).toContain("missing access_token");
  });

  it("wraps a rejected fetch instead of leaking it", async () => {
    const error = await rejection(
      () =>
        exchange("http://unused.invalid", {
          fetch: () => Promise.reject(new TypeError("network down")),
        }),
      ExternalAuthError,
    );
    expect(error.code).toStrictEqual("provider_error");
    expect(error.message).toContain("could not reach");
    expect(error.message).toContain("network down");
  });
});

interface ConnectorCase {
  name: string;
  tokenPath: string;
  provider: (origin: string) => ExternalProvider;
  /** `[error code, text the connector's hint table must produce]` */
  hints: [string | undefined, string][];
  /** Per-code hint text a mapped `invalid_client` must carry. */
  invalidClientHint: string;
  /** The connector's status-only hint, appended alongside the per-code one. */
  httpHint: string;
}

const githubCase: ConnectorCase = {
  name: "github",
  tokenPath: "/login/oauth/access_token",
  provider: (origin) =>
    githubProvider({
      clientId: "gh-client",
      clientSecret: "gh-secret",
      fetch: rewriteToOrigin(origin),
    }),
  hints: [
    ["incorrect_client_credentials", "GitHub OAuth App settings"],
    ["redirect_uri_mismatch", "Authorization callback"],
    ["bad_verification_code", "expired or was already used"],
    ["something_unmapped", "docs.github.com"],
    [undefined, "docs.github.com"],
  ],
  invalidClientHint: "docs.github.com",
  httpHint: "GitHub OAuth App and try again",
};

const discordCase: ConnectorCase = {
  name: "discord",
  tokenPath: "/api/oauth2/token",
  provider: (origin) =>
    discordProvider({
      clientId: "discord-client",
      clientSecret: "discord-secret",
      fetch: rewriteToOrigin(origin),
    }),
  hints: [
    ["invalid_client", "check clientId and clientSecret"],
    ["unauthorized_client", "check clientId and clientSecret"],
    ["invalid_grant", "redirect URI does not match"],
    ["invalid_scope", "rejected the requested scopes"],
    [undefined, "expired or already been used"],
  ],
  invalidClientHint: "check clientId and clientSecret",
  httpHint: "app registration, then try again",
};

const appleCase: ConnectorCase = {
  name: "apple",
  tokenPath: "/auth/token",
  provider: (origin) =>
    appleProvider({
      clientId: "com.example.web",
      teamId: "TEAM",
      keyId: "KEY",
      privateKey: "unused",
      clientSecret: () => Promise.resolve("stub.secret.jwt"),
      fetch: rewriteToOrigin(origin),
    }),
  hints: [
    ["invalid_client", "client-secret JWT is wrong"],
    ["invalid_grant", "expired, was already used"],
    ["something_unmapped", "Generate and validate tokens"],
    [undefined, `"openid" flow scopes`],
  ],
  invalidClientHint: "client-secret JWT is wrong",
  httpHint: "team id, key id, and Services ID",
};

const connectorCases = [githubCase, discordCase, appleCase];

function exchangeVia(
  connector: ConnectorCase,
  handler: Handler,
): Promise<ExternalAuthError> {
  return withServer(
    (request) => {
      const { pathname } = new URL(request.url);
      if (pathname === connector.tokenPath) return handler(request);
      return new Response("unexpected", { status: 404 });
    },
    (origin) =>
      rejection(
        () =>
          connector.provider(origin).fetchProfile({
            code: "the-code",
            redirectUri,
            nonce: "the-nonce",
          }),
        ExternalAuthError,
      ),
  );
}

describe("connector token exchange over a real socket", () => {
  for (const connector of connectorCases) {
    it(`${connector.name} maps a provider HTML error page`, async () => {
      const error = await exchangeVia(
        connector,
        html("<html><body>Service Unavailable</body></html>"),
      );
      expect(error.code).toStrictEqual("provider_error");
      expect(error.message).toContain(`[${connector.name}]`);
      expect(error.message).toContain("not valid JSON");
      expect(error.message).toContain(`"text/html"`);
    });

    it(`${connector.name} maps a JSON null token body`, async () => {
      const error = await exchangeVia(connector, json(null));
      expect(error.code).toStrictEqual("provider_error");
      expect(error.message).toContain("JSON object was required");
    });

    it(`${connector.name} maps a token body missing the required field`, async () => {
      const error = await exchangeVia(
        connector,
        json({ token_type: "bearer" }),
      );
      expect(error.code).toStrictEqual("provider_error");
      expect(error.message).toContain("token exchange failed");
      expect(error.message).toContain("missing ");
    });

    it(`${connector.name} maps a required field of the wrong type`, async () => {
      const field = connector.name === "apple" ? "id_token" : "access_token";
      const error = await exchangeVia(connector, json({ [field]: 12345 }));
      expect(error.code).toStrictEqual("provider_error");
      expect(error.message).toContain(`missing ${field}`);
    });

    it(`${connector.name} maps a non-200 status`, async () => {
      const error = await exchangeVia(
        connector,
        respond("gateway blew up", { status: 502 }),
      );
      expect(error.code).toStrictEqual("provider_error");
      expect(error.message).toContain("HTTP 502");
      expect(error.message).toContain("gateway blew up");
    });

    it(`${connector.name} maps an OAuth2 error body on a non-200 status`, async () => {
      const error = await exchangeVia(
        connector,
        json({ error: "invalid_client" }, 401),
      );
      expect(error.code).toStrictEqual("provider_error");
      expect(error.message).toContain(`HTTP 401: "invalid_client".`);
      expect(error.message).toContain(connector.invalidClientHint);
      expect(error.message).toContain(connector.httpHint);
    });

    it(`${connector.name} bounds a hostile error_description`, async () => {
      const error = await exchangeVia(
        connector,
        json({
          error: "invalid_grant",
          error_description: `\nforged\u001b[31m` + "x".repeat(10_000),
        }),
      );
      expect(error.message.includes("\n")).toBeFalsy();
      expect(error.message.includes("\u001b")).toBeFalsy();
      assert(error.message.length < 700);
    });

    for (const [code, expected] of connector.hints) {
      it(`${connector.name} hints ${code ?? "a missing token"}`, async () => {
        const body = code === undefined ? {} : { error: code };
        const error = await exchangeVia(connector, json(body));
        expect(error.message).toContain(expected);
      });
    }
  }

  it("github builds a profile from a real token exchange", async () => {
    let form = new URLSearchParams();
    const profile = await withServer(
      async (request) => {
        const { pathname } = new URL(request.url);
        if (pathname === "/login/oauth/access_token") {
          form = new URLSearchParams(await request.text());
          return Response.json({
            access_token: "gh-token",
            token_type: "bearer",
          });
        }
        if (pathname === "/user") {
          return Response.json({
            id: 583231,
            login: "octocat",
            name: "Octocat",
          });
        }
        if (pathname === "/user/emails") {
          return Response.json([
            { email: "octocat@example.com", primary: true, verified: true },
          ]);
        }
        return new Response("unexpected", { status: 404 });
      },
      (origin) =>
        githubCase.provider(origin).fetchProfile({
          code: "gh-code",
          redirectUri,
        }),
    );

    expect(profile.provider).toStrictEqual("github");
    expect(profile.subject).toStrictEqual("583231");
    expect(profile.email).toStrictEqual("octocat@example.com");
    expect(profile.emailVerified).toStrictEqual(true);
    expect(form.get("code")).toStrictEqual("gh-code");
    expect(form.get("client_secret")).toStrictEqual("gh-secret");
  });

  it("discord builds a profile from a real token exchange", async () => {
    let form = new URLSearchParams();
    const profile = await withServer(
      async (request) => {
        const { pathname } = new URL(request.url);
        if (pathname === "/api/oauth2/token") {
          form = new URLSearchParams(await request.text());
          return Response.json({
            access_token: "discord-token",
            token_type: "Bearer",
          });
        }
        if (pathname === "/api/users/@me") {
          return Response.json({
            id: "80351110224678912",
            username: "nelly",
            email: "nelly@example.com",
            verified: true,
          });
        }
        return new Response("unexpected", { status: 404 });
      },
      (origin) =>
        discordCase.provider(origin).fetchProfile({
          code: "discord-code",
          redirectUri,
        }),
    );

    expect(profile.provider).toStrictEqual("discord");
    expect(profile.subject).toStrictEqual("80351110224678912");
    expect(profile.emailVerified).toStrictEqual(true);
    expect(form.get("grant_type")).toStrictEqual("authorization_code");
    expect(form.get("client_secret")).toStrictEqual("discord-secret");
  });

  it("apple accepts the exchanged id_token and rejects its malformed header", async () => {
    let jwksHits = 0;
    const error = await withServer(
      (request) => {
        const { pathname } = new URL(request.url);
        if (pathname === "/auth/token") {
          return Response.json({ id_token: "not.a.jwt" });
        }
        jwksHits++;
        return Response.json({ keys: [] });
      },
      (origin) =>
        rejection(
          () =>
            appleCase.provider(origin).fetchProfile({
              code: "apple-code",
              redirectUri,
              nonce: "the-nonce",
            }),
          ExternalAuthError,
        ),
    );

    expect(error.code).toStrictEqual("provider_error");
    expect(error.message).toContain("[apple]");
    expect(error.message).toContain("id_token header");
    expect(
      jwksHits,
      "a malformed header must not reach the JWKS",
    ).toStrictEqual(0);
  });
});

function oidcExchange(handler: Handler): Promise<ExternalAuthError> {
  return withServer(
    (request) => {
      const url = new URL(request.url);
      if (url.pathname.startsWith("/.well-known/")) {
        return Response.json({
          issuer: url.origin,
          authorization_endpoint: `${url.origin}/authorize`,
          token_endpoint: `${url.origin}/token`,
        });
      }
      return handler(request);
    },
    (origin) =>
      rejection(
        () =>
          oidcProvider({
            id: "acme-sso",
            issuer: origin,
            clientId: "acme-client",
            clientSecret: "acme-secret",
          }).fetchProfile({
            code: "the-code",
            redirectUri,
            nonce: "the-nonce",
          }),
        ExternalAuthError,
      ),
  );
}

describe("oidcProvider token exchange over a real socket", () => {
  it("maps a provider HTML error page", async () => {
    const error = await oidcExchange(
      html("<html><body>Service Unavailable</body></html>"),
    );
    expect(error.code).toStrictEqual("provider_error");
    expect(error.message).toContain("[acme-sso]");
  });

  it("maps a JSON null token body", async () => {
    const error = await oidcExchange(json(null));
    expect(error.code).toStrictEqual("provider_error");
    expect(error.message).toContain("[acme-sso]");
  });

  it("maps an OAuth2 error body", async () => {
    const error = await oidcExchange(
      json({ error: "invalid_grant", error_description: "code expired" }, 400),
    );
    expect(error.code).toStrictEqual("provider_error");
    expect(error.message).toContain("invalid_grant");
    expect(error.message).toContain("code expired");
  });

  it("maps a token response that carries no id_token", async () => {
    const error = await oidcExchange(json({ access_token: "at" }));
    expect(error.code).toStrictEqual("provider_error");
    expect(error.message).toContain("no id_token");
  });

  it("maps a non-200 status", async () => {
    const error = await oidcExchange(
      respond("gateway blew up", { status: 502 }),
    );
    expect(error.code).toStrictEqual("provider_error");
    expect(error.message).toContain("502");
  });
});
