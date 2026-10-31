import { Hono } from "hono";
import { assert, describe, expect, it, vi } from "vitest";
import { HonoAuthorizationServer } from "../adapters/hono/authorization-server.ts";
import { BasicScope } from "../models/scope.ts";
import type { Token } from "../models/token.ts";
import {
  basicAuthHeader,
  MemoryClientService,
  MemoryTokenService,
  MemoryUserService,
  type TestClient,
  type TestUser,
} from "../testing/_test_fixtures.ts";
import { AuthorizationServer } from "./authorization-server.ts";
import { ClientCredentialsGrant } from "./grants/client-credentials.ts";
import { RefreshTokenGrant } from "./grants/refresh-token.ts";
import { JwksTokenReader } from "./jwks-token-reader.ts";
import {
  createJwtAccessTokenGenerator,
  generateSigningKey,
  StaticSigningKeyProvider,
  verifyJwt,
} from "./signing-keys.ts";

const ISSUER = "https://auth.example.com";
const RESOURCE = "https://api.example.com/workspaces/one";
const OTHER = "https://api.example.com/workspaces/two";
const CLIENT: TestClient = {
  id: "inventory-worker",
  confidential: true,
  grants: ["client_credentials", "refresh_token"],
};
const BOT: TestUser = { id: "inventory-bot", username: "inventory-bot" };
type BoundToken = Token<TestClient, TestUser>;
type Policy = (
  client: TestClient,
  user: TestUser | undefined,
  resource: string | undefined,
  scope?: BasicScope | null,
) => Promise<boolean>;

async function fixture(
  options: {
    transport?: "core" | "hono";
    policy?: Policy | false;
    bot?: boolean;
  } = {},
) {
  const userService = new MemoryUserService<TestUser>();
  const clientService = new MemoryClientService<TestClient, TestUser>(
    userService,
  );
  if (options.bot) await userService.add(BOT, "unused");
  await clientService.add(
    CLIENT,
    "synthetic-secret",
    options.bot ? BOT.id : undefined,
  );
  const tokenService = new MemoryTokenService({ clientService, userService });
  const policy = vi.fn<Policy>(
    options.policy ||
      (async (client, _user, resource, scope) =>
        client.id === CLIENT.id &&
        resource === RESOURCE &&
        scope?.has("read") === true),
  );
  if (options.policy !== false)
    Object.assign(tokenService, { acceptedResource: policy });
  const services = { clientService, tokenService };
  const machine = new ClientCredentialsGrant({ resolve: () => services });
  const refresh = new RefreshTokenGrant({ resolve: () => services });
  const configuration = {
    resolve: () => ({ services, issuer: ISSUER }),
    grants: { client_credentials: machine, refresh_token: refresh },
    introspectionClaims: () => ({ aud: OTHER, active: false }),
  };
  const server =
    options.transport === "hono"
      ? new HonoAuthorizationServer(configuration)
      : new AuthorizationServer(configuration);
  const app = new Hono();
  if (server instanceof HonoAuthorizationServer)
    app.post("/token", server.tokenHandler());
  const generated = vi.spyOn(tokenService, "generateAccessToken");
  const saved = vi.spyOn(tokenService, "save");
  async function send(
    resources: readonly (string | File)[],
    multipart = false,
    secret = "synthetic-secret",
  ) {
    const body = new FormData();
    body.set("grant_type", "client_credentials");
    body.set("scope", "read write");
    for (const resource of resources) body.append("resource", resource);
    const request = new Request(`${ISSUER}/token`, {
      method: "POST",
      headers: basicAuthHeader(CLIENT.id, secret),
      body: multipart
        ? body
        : new URLSearchParams(
            [...body].map(([key, value]) => [key, String(value)]),
          ),
    });
    return await (server instanceof HonoAuthorizationServer
      ? app.request(request)
      : server.handleTokenRequest(request));
  }
  return {
    server,
    machine,
    send,
    tokenService,
    clientService,
    policy,
    generated,
    saved,
  };
}

for (const transport of ["core", "hono"] as const) {
  describe(`single-resource machine issuance (${transport})`, () => {
    for (const bot of [false, true]) {
      it(`persists the exact target for a ${bot ? "bot" : "user-less"} machine and forwards it to generation`, async () => {
        const f = await fixture({ transport, bot });
        const response = await f.send([RESOURCE]);
        expect(response.status).toBe(200);
        const body = await response.json();
        const token = (await f.tokenService.getToken(body.access_token)) as
          | BoundToken
          | undefined;
        expect(token?.resource).toBe(RESOURCE);
        expect(token?.user?.id).toBe(bot ? BOT.id : undefined);
        expect(body.refresh_token).toBeUndefined();
        expect(body.id_token).toBeUndefined();
        expect(f.generated.mock.calls[0]?.at(5)).toBe(RESOURCE);
        expect(f.policy).toHaveBeenCalledWith(
          CLIENT,
          bot ? BOT : undefined,
          RESOURCE,
          expect.any(BasicScope),
        );
      });
    }

    for (const [name, resources] of [
      ["missing", []],
      ["empty", [""]],
      ["relative", ["/workspaces/one"]],
      ["fragment", [`${RESOURCE}#private`]],
      ["empty fragment", [`${RESOURCE}#`]],
      ["leading space", [` ${RESOURCE}`]],
      ["embedded newline", [`${RESOURCE}\nother`]],
      ["trailing newline", [`${RESOURCE}\n`]],
      ["trailing Unicode separator", [`${RESOURCE}\u2028`]],
      ["malformed percent escape", [`${RESOURCE}/%ZZ`]],
      ["Unicode IRI", [`${RESOURCE}/é`]],
      ["raw brackets in path", [`${RESOURCE}/[private]`]],
      ["invalid IPv6", ["https://[invalid]/inventory"]],
      [
        "repeated userinfo separator",
        ["https://one@two@api.example.com/inventory"],
      ],
      ["wrong tenant", [OTHER]],
      ["same target twice", [RESOURCE, RESOURCE]],
      ["different targets", [RESOURCE, OTHER]],
    ] as const) {
      it(`refuses ${name} before generating or saving`, async () => {
        const f = await fixture({ transport });
        const response = await f.send(resources);
        const body = await response.json();
        expect(response.status, JSON.stringify(body)).toBe(400);
        expect(body.error).toBe("invalid_target");
        expect(body.access_token).toBeUndefined();
        expect(f.generated).not.toHaveBeenCalled();
        expect(f.saved).not.toHaveBeenCalled();
        if (name !== "missing" && name !== "wrong tenant") {
          expect(f.policy).not.toHaveBeenCalled();
        }
        expect(response.headers.get("cache-control")).toBe("no-store");
        expect(response.headers.get("pragma")).toBe("no-cache");
        expect(JSON.stringify(body)).not.toContain(RESOURCE);
        expect(JSON.stringify(body)).not.toContain(OTHER);
      });
    }

    it("keeps the HTTP form-only boundary and refuses a File through the grant API", async () => {
      const f = await fixture({ transport });
      const multipart = await f.send([RESOURCE], true);
      expect(multipart.status).toBe(400);
      expect((await multipart.json()).error).toBe("invalid_request");
      expect(f.policy).not.toHaveBeenCalled();
      const body = new FormData();
      body.set("resource", new File([RESOURCE], "resource.txt"));
      body.set("scope", "read");
      await expect(
        f.machine.token(new Request(`${ISSUER}/token`), CLIENT, body),
      ).rejects.toMatchObject({
        extensions: { error: "invalid_target" },
      });
      expect(f.policy).not.toHaveBeenCalled();
      expect(f.generated).not.toHaveBeenCalled();
      expect(f.saved).not.toHaveBeenCalled();
    });

    it("keeps unknown repeated resource fields unchanged when the policy is absent", async () => {
      const f = await fixture({ transport, policy: false });
      const response = await f.send(["first", "second"]);
      expect(response.status).toBe(200);
      const body = await response.json();
      expect(
        ((await f.tokenService.getToken(body.access_token)) as BoundToken)
          ?.resource,
      ).toBeUndefined();
      expect(f.policy).not.toHaveBeenCalled();
      expect(f.generated.mock.calls[0]).toHaveLength(5);
    });
  });
}

describe("resource policy and persisted authority", () => {
  it("allows a policy to admit no target without inventing a binding", async () => {
    const f = await fixture({
      policy: async (_client, _user, resource) => resource === undefined,
    });
    const response = await f.send([]);
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(
      ((await f.tokenService.getToken(body.access_token)) as BoundToken)
        ?.resource,
    ).toBeUndefined();
    expect(f.policy).toHaveBeenCalledExactlyOnceWith(
      CLIENT,
      undefined,
      undefined,
      expect.any(BasicScope),
    );
  });

  it("accepts a policy-approved absolute URN without fetching it", async () => {
    const target = "urn:example:inventory";
    const f = await fixture({
      policy: async (_client, _user, resource) => resource === target,
    });
    const response = await f.send([target]);
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(
      ((await f.tokenService.getToken(body.access_token)) as BoundToken)
        ?.resource,
    ).toBe(target);
  });

  for (const target of [
    "https://api.example.com/a%2Fb?version=1&filter=a/b?c",
    "https://[2001:db8::1]:8443/inventory",
    "https://api.example.com/%C3%A9",
    "urn:example:inventory?version=1",
  ]) {
    it(`preserves a policy-approved URI exactly: ${target}`, async () => {
      const f = await fixture({
        policy: async (_client, _user, resource) => resource === target,
      });
      const response = await f.send([target]);
      expect(response.status).toBe(200);
      const body = await response.json();
      expect(
        ((await f.tokenService.getToken(body.access_token)) as BoundToken)
          ?.resource,
      ).toBe(target);
    });
  }

  it("checks the final narrowed scope rather than the requested scope", async () => {
    const f = await fixture();
    vi.spyOn(f.tokenService, "acceptedScope").mockResolvedValue(
      new BasicScope("read"),
    );
    const response = await f.send([RESOURCE]);
    expect(response.status).toBe(200);
    expect(f.policy.mock.calls[0]?.[3]?.toString()).toBe("read");
    expect((await response.json()).scope).toBe("read");
  });

  it("authenticates the client before invoking target policy", async () => {
    const f = await fixture();
    expect((await f.send([RESOURCE], false, "wrong-secret")).status).toBe(401);
    expect(f.policy).not.toHaveBeenCalled();
    expect(f.generated).not.toHaveBeenCalled();
  });

  it("refuses a target when the authenticated client is no longer enabled", async () => {
    const f = await fixture();
    vi.spyOn(f.clientService, "getAuthenticated").mockResolvedValue(undefined);
    expect((await f.send([RESOURCE])).status).toBe(401);
    expect(f.policy).not.toHaveBeenCalled();
    expect(f.saved).not.toHaveBeenCalled();
  });

  it("does not generate a token when scope acceptance fails", async () => {
    const f = await fixture();
    vi.spyOn(f.tokenService, "acceptedScope").mockResolvedValue(false);
    const response = await f.send([RESOURCE]);
    expect((await response.json()).error).toBe("invalid_scope");
    expect(f.policy).not.toHaveBeenCalled();
    expect(f.generated).not.toHaveBeenCalled();
  });

  it("requires true policy acceptance and fails closed when the policy throws", async () => {
    for (const policy of [
      async () => undefined as unknown as boolean,
      async () => {
        throw new Error("synthetic policy failure");
      },
    ]) {
      const f = await fixture({ policy });
      const response = await f.send([RESOURCE]);
      expect(response.status).toBeGreaterThanOrEqual(400);
      expect(f.generated).not.toHaveBeenCalled();
      expect(f.saved).not.toHaveBeenCalled();
    }
  });

  it("refuses a store that drops the binding from its saved result", async () => {
    const f = await fixture();
    const realSave = MemoryTokenService.prototype.save.bind(f.tokenService);
    f.saved.mockImplementation((async (token: BoundToken) => {
      const saved = await realSave(token);
      delete (saved as BoundToken).resource;
      return saved;
    }) as typeof f.tokenService.save);
    const response = await f.send([RESOURCE]);
    expect(response.status).toBe(500);
    expect((await response.json()).access_token).toBeUndefined();
  });

  it("keeps concurrent targets separate through generation and storage", async () => {
    const f = await fixture({
      policy: async (_client, _user, resource) =>
        resource === RESOURCE || resource === OTHER,
    });
    f.generated.mockImplementation(async () => {
      await Promise.resolve();
      return crypto.randomUUID();
    });
    const responses = await Promise.all([f.send([RESOURCE]), f.send([OTHER])]);
    for (let i = 0; i < responses.length; i++) {
      expect(responses[i].status).toBe(200);
      const body = await responses[i].json();
      expect(
        ((await f.tokenService.getToken(body.access_token)) as BoundToken)
          ?.resource,
      ).toBe([RESOURCE, OTHER][i]);
    }
    expect(
      f.generated.mock.calls
        .map((args) => args.at(5))
        .sort((a, b) => String(a).localeCompare(String(b))),
    ).toStrictEqual([RESOURCE, OTHER].sort((a, b) => a.localeCompare(b)));
  });

  it("emits authoritative target aud for opaque introspection, ahead of extensions", async () => {
    const f = await fixture();
    const issued = await (await f.send([RESOURCE])).json();
    const response = await f.server.handleIntrospectionRequest(
      new Request(`${ISSUER}/introspect`, {
        method: "POST",
        headers: basicAuthHeader(CLIENT.id, "synthetic-secret"),
        body: new URLSearchParams({ token: issued.access_token }),
      }),
    );
    const body = await response.json();
    expect(body.active).toBe(true);
    expect(body.aud).toBe(RESOURCE);
    expect(body.iss).toBe(ISSUER);
  });

  it("refuses resource-bound refresh before generating, rotating or spending the parent", async () => {
    const f = await fixture({ bot: true });
    const parent = {
      accessToken: "parent-access",
      refreshToken: "parent-refresh",
      client: CLIENT,
      user: BOT,
      scope: new BasicScope("read"),
      resource: RESOURCE,
    };
    await f.tokenService.save(parent);
    const realGet = f.tokenService.getRefreshToken.bind(f.tokenService);
    expect((await realGet(parent.refreshToken))?.resource).toBe(RESOURCE);
    f.saved.mockClear();
    const rotate = vi.spyOn(f.tokenService, "rotate");
    const response = await f.server.handleTokenRequest(
      new Request(`${ISSUER}/token`, {
        method: "POST",
        headers: basicAuthHeader(CLIENT.id, "synthetic-secret"),
        body: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: parent.refreshToken,
        }),
      }),
    );
    expect(response.status).toBe(400);
    expect((await response.json()).error).toBe("invalid_target");
    expect(f.generated).not.toHaveBeenCalled();
    expect(rotate).not.toHaveBeenCalled();
    expect(f.saved).not.toHaveBeenCalled();
    expect(await realGet(parent.refreshToken)).toBeDefined();
  });
});

describe("resource-bound JWT audience", () => {
  it("keeps signed issuance, stored metadata and introspection on the same accepted target", async () => {
    const key = await generateSigningKey();
    const f = await fixture();
    const generate = createJwtAccessTokenGenerator({
      signingKeys: new StaticSigningKeyProvider(key),
      issuer: ISSUER,
      audience: OTHER,
    });
    f.generated.mockImplementation(generate);
    const issued = await (await f.send([RESOURCE])).json();
    const stored = await f.tokenService.getToken(issued.access_token);
    expect(stored?.resource).toBe(RESOURCE);
    const claims = await verifyJwt(issued.access_token, key.publicJwk);
    expect(claims?.aud).toBe(stored?.resource);
    const response = await f.server.handleIntrospectionRequest(
      new Request(`${ISSUER}/introspect`, {
        method: "POST",
        headers: basicAuthHeader(CLIENT.id, "synthetic-secret"),
        body: new URLSearchParams({ token: issued.access_token }),
      }),
    );
    expect((await response.json()).aud).toBe(claims?.aud);
    await f.tokenService.revoke(issued.access_token);
    const revoked = await f.server.handleIntrospectionRequest(
      new Request(`${ISSUER}/introspect`, {
        method: "POST",
        headers: basicAuthHeader(CLIENT.id, "synthetic-secret"),
        body: new URLSearchParams({ token: issued.access_token }),
      }),
    );
    expect(await revoked.json()).toStrictEqual({ active: false });
  });

  it("overrides configured audience with the accepted target and verifies exact issuer/audience", async () => {
    const key = await generateSigningKey();
    const provider = new StaticSigningKeyProvider(key);
    const generate = createJwtAccessTokenGenerator({
      signingKeys: provider,
      issuer: ISSUER,
      audience: OTHER,
      userClaims: () => ({ aud: OTHER, iss: "https://wrong.example.com" }),
    });
    const jwt = await Reflect.apply(generate, undefined, [
      CLIENT,
      undefined,
      new BasicScope("read"),
      undefined,
      new Date(Date.now() + 60000),
      RESOURCE,
    ]);
    expect((await verifyJwt(jwt, key.publicJwk))?.aud).toBe(RESOURCE);
    const jwks = await provider.getPublicJwks();
    const reader = (issuer: string, audience: string) =>
      new JwksTokenReader<TestClient, TestUser>({
        issuer,
        audience,
        jwksUri: `${ISSUER}/jwks`,
        getClient: (claims) => ({ id: String(claims.client_id) }),
        fetch: async () => Response.json(jwks),
      });
    expect((await reader(ISSUER, RESOURCE).getToken(jwt))?.claims?.aud).toBe(
      RESOURCE,
    );
    expect(await reader(ISSUER, OTHER).getToken(jwt)).toBeUndefined();
    expect(
      await reader("https://wrong.example.com", RESOURCE).getToken(jwt),
    ).toBeUndefined();
    const legacy = await generate(CLIENT, undefined, new BasicScope("read"));
    expect((await verifyJwt(legacy, key.publicJwk))?.aud).toBe(OTHER);
    assert.exists((await verifyJwt(jwt, key.publicJwk))?.exp);
    const userToken = await generate(
      CLIENT,
      BOT,
      new BasicScope("read"),
      undefined,
      undefined,
      RESOURCE,
    );
    expect((await verifyJwt(userToken, key.publicJwk))?.aud).toBe(RESOURCE);
  });
});
