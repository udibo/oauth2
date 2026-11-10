import { assert, describe, expect, it, vi } from "vitest";
import type { AuthorizationCode } from "../models/authorization-code.ts";
import { BasicScope } from "../models/scope.ts";
import type { RefreshToken, Token } from "../models/token.ts";
import {
  basicAuthHeader,
  MemoryAuthorizationCodeService,
  MemoryClientService,
  MemoryTokenService,
  MemoryUserService,
  type TestClient,
  type TestUser,
} from "../testing/_test_fixtures.ts";
import { generateCodeChallenge, generateCodeVerifier } from "../utils/pkce.ts";
import {
  AuthorizationServer,
  type HandleConsentFn,
} from "./authorization-server.ts";
import { AuthorizationCodeGrant } from "./grants/authorization-code.ts";
import { RefreshTokenGrant } from "./grants/refresh-token.ts";
import type { ResourcePolicyContext } from "./services/token.ts";
import { JwksTokenReader } from "./jwks-token-reader.ts";
import {
  createJwtAccessTokenGenerator,
  generateSigningKey,
  StaticSigningKeyProvider,
  verifyJwt,
} from "./signing-keys.ts";

const ISSUER = "https://auth.example.com";
const RESOURCE = "https://mcp.example.com/mcp";
const OTHER = "https://mcp.example.com/other";
const REDIRECT = "https://client.example.com/callback";
const SECRET = "synthetic-secret";
const CLIENT: TestClient = {
  id: "mcp-client",
  confidential: true,
  grants: ["authorization_code", "refresh_token"],
  redirectUris: [REDIRECT],
};
const ALICE: TestUser = { id: "alice", username: "alice" };
type Policy = (
  client: TestClient,
  user: TestUser | undefined,
  resource: string | undefined,
  scope?: BasicScope | null,
  context?: ResourcePolicyContext,
) => Promise<boolean>;
type Bound = Token<TestClient, TestUser>;
type BoundRefresh = RefreshToken<TestClient, TestUser>;

const SPELLING_VARIANTS = [
  ["a trailing slash", `${RESOURCE}/`],
  ["an upper-case host", "https://MCP.example.com/mcp"],
  ["an upper-case scheme", "HTTPS://mcp.example.com/mcp"],
  ["a percent-encoded path", "https://mcp.example.com/%6Dcp"],
  ["an explicit default port", "https://mcp.example.com:443/mcp"],
  ["a different resource", OTHER],
] as const;

const MALFORMED = [
  ["empty", [""]],
  ["relative", ["/mcp"]],
  ["fragment", [`${RESOURCE}#tools`]],
  ["the same value twice", [RESOURCE, RESOURCE]],
  ["two values", [RESOURCE, OTHER]],
] as const;

async function fixture(
  options: {
    code?: boolean;
    refresh?: boolean;
    policy?: Policy | false;
    atomic?: boolean;
    audience?: string;
  } = {},
) {
  const userService = new MemoryUserService<TestUser>();
  const clientService = new MemoryClientService<TestClient, TestUser>(
    userService,
  );
  await userService.add(ALICE, "unused");
  await clientService.add(CLIENT, SECRET);
  const tokenService = new MemoryTokenService({ clientService, userService });
  const authorizationCodeService = new MemoryAuthorizationCodeService<
    TestClient,
    TestUser
  >({ clientService, userService });
  const policy = vi.fn<Policy>(
    options.policy ||
      (async (client, user, resource) =>
        client.id === CLIENT.id &&
        user?.id === ALICE.id &&
        (resource === undefined || resource === RESOURCE)),
  );
  if (options.policy !== false) {
    Object.assign(tokenService, { acceptedResource: policy });
  }
  if (options.atomic) {
    Object.assign(tokenService, {
      exchangeCode: async (
        code: AuthorizationCode<TestClient, TestUser>,
        token: Bound,
      ) =>
        (await authorizationCodeService.revoke(code))
          ? await tokenService.save(token)
          : undefined,
    });
  }
  const signingKey = await generateSigningKey();
  if (options.audience !== undefined) {
    const generate = createJwtAccessTokenGenerator({
      signingKeys: new StaticSigningKeyProvider(signingKey),
      issuer: ISSUER,
      audience: options.audience,
    });
    Object.assign(tokenService, { generateAccessToken: generate });
  }
  const services = { clientService, tokenService, authorizationCodeService };
  const codeGrant = new AuthorizationCodeGrant({
    resolve: () => services,
    resourceIndicators: options.code ?? true,
  });
  const refreshGrant = new RefreshTokenGrant({
    resolve: () => services,
    resourceIndicators: options.refresh ?? options.code ?? true,
  });
  const server = new AuthorizationServer({
    resolve: () => ({ services, issuer: ISSUER }),
    grants: { authorization_code: codeGrant, refresh_token: refreshGrant },
    signingKeys: new StaticSigningKeyProvider(signingKey),
    introspectionClaims: () => ({ aud: OTHER }),
  });
  const generated = vi.spyOn(tokenService, "generateAccessToken");
  const savedTokens = vi.spyOn(tokenService, "save");
  const savedCodes = vi.spyOn(authorizationCodeService, "save");
  const rotate = vi.spyOn(tokenService, "rotate");
  const revokeFamily = vi.spyOn(tokenService, "revokeFamily");
  const authenticateUser = vi.fn(async () => ({
    user: ALICE,
    authorizedScope: new BasicScope("openid read write"),
  }));
  const verifier = generateCodeVerifier();
  const challenge = await generateCodeChallenge(verifier);

  async function authorize(
    resources: readonly string[],
    extra: Record<string, string> = {},
    handleConsent?: HandleConsentFn<TestClient, BasicScope>,
  ): Promise<Response> {
    const url = new URL(`${ISSUER}/authorize`);
    for (const [name, value] of Object.entries({
      response_type: "code",
      client_id: CLIENT.id,
      redirect_uri: REDIRECT,
      state: "synthetic-state",
      scope: "read",
      code_challenge: challenge,
      code_challenge_method: "S256",
      ...extra,
    })) {
      url.searchParams.set(name, value);
    }
    for (const resource of resources) {
      url.searchParams.append("resource", resource);
    }
    return await server.handleAuthorizeRequest(
      new Request(url),
      authenticateUser,
      handleConsent,
    );
  }

  async function issueCode(
    resources: readonly string[] = [RESOURCE],
    extra: Record<string, string> = {},
  ): Promise<string> {
    const response = await authorize(resources, extra);
    expect(response.status).toBe(302);
    const location = new URL(response.headers.get("location")!);
    expect(location.searchParams.get("error")).toBeNull();
    const code = location.searchParams.get("code");
    assert(code);
    return code;
  }

  async function token(
    parameters: Record<string, string>,
    resources: readonly string[] = [],
    query = "",
  ): Promise<Response> {
    const body = new URLSearchParams(parameters);
    for (const resource of resources) body.append("resource", resource);
    return await server.handleTokenRequest(
      new Request(`${ISSUER}/token${query}`, {
        method: "POST",
        headers: basicAuthHeader(CLIENT.id, SECRET),
        body,
      }),
    );
  }

  async function exchange(
    code: string,
    resources: readonly string[] = [],
    codeVerifier = verifier,
    query = "",
  ): Promise<Response> {
    return await token(
      {
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT,
        code_verifier: codeVerifier,
      },
      resources,
      query,
    );
  }

  async function refresh(
    refreshToken: string,
    resources: readonly string[] = [],
    extra: Record<string, string> = {},
    query = "",
  ): Promise<Response> {
    return await token(
      { grant_type: "refresh_token", refresh_token: refreshToken, ...extra },
      resources,
      query,
    );
  }

  async function introspect(value: string): Promise<Record<string, unknown>> {
    const response = await server.handleIntrospectionRequest(
      new Request(`${ISSUER}/introspect`, {
        method: "POST",
        headers: basicAuthHeader(CLIENT.id, SECRET),
        body: new URLSearchParams({ token: value }),
      }),
    );
    return await response.json();
  }

  return {
    server,
    codeGrant,
    tokenService,
    authorizationCodeService,
    signingKey,
    policy,
    generated,
    savedTokens,
    savedCodes,
    rotate,
    revokeFamily,
    authenticateUser,
    verifier,
    authorize,
    issueCode,
    exchange,
    refresh,
    introspect,
  };
}

type Fixture = Awaited<ReturnType<typeof fixture>>;

async function issueTokens(
  f: Fixture,
  resources: readonly string[] = [RESOURCE],
): Promise<{ access_token: string; refresh_token: string }> {
  const response = await f.exchange(await f.issueCode(resources));
  const body = await response.json();
  expect(response.status, JSON.stringify(body)).toBe(200);
  return body;
}

async function expectInvalidTarget(response: Response): Promise<void> {
  const body = await response.json();
  expect(response.status, JSON.stringify(body)).toBe(400);
  expect(body.error).toBe("invalid_target");
  expect(body.access_token).toBeUndefined();
  expect(JSON.stringify(body)).not.toContain("mcp.example.com");
}

function expectRedirectError(response: Response, error: string): URL {
  expect(response.status).toBe(302);
  const location = new URL(response.headers.get("location")!);
  expect(location.origin + location.pathname).toBe(REDIRECT);
  expect(location.searchParams.get("error")).toBe(error);
  expect(location.searchParams.get("code")).toBeNull();
  expect(location.searchParams.get("state")).toBe("synthetic-state");
  expect(location.searchParams.get("iss")).toBe(ISSUER);
  return location;
}

describe("without resourceIndicators on the code and refresh grants", () => {
  it("ignores resource at authorization and exchange, even when acceptedResource is set", async () => {
    const f = await fixture({ code: false, refresh: false });
    const code = await f.issueCode([RESOURCE, `${OTHER}#fragment`]);
    expect(f.policy).not.toHaveBeenCalled();
    expect(
      (await f.authorizationCodeService.get(code))?.resource,
    ).toBeUndefined();
    const response = await f.exchange(code, ["not a uri", OTHER]);
    const body = await response.json();
    expect(response.status, JSON.stringify(body)).toBe(200);
    expect(
      (await f.tokenService.getToken(body.access_token))?.resource,
    ).toBeUndefined();
    expect(f.generated.mock.calls[0]).toHaveLength(5);
    expect(f.policy).not.toHaveBeenCalled();
  });

  it("ignores resource on the refresh of an unbound token", async () => {
    const f = await fixture({ code: false, refresh: false });
    const issued = await issueTokens(f, []);
    const response = await f.refresh(issued.refresh_token, [OTHER, OTHER]);
    const body = await response.json();
    expect(response.status, JSON.stringify(body)).toBe(200);
    expect(
      (await f.tokenService.getRefreshToken(body.refresh_token))?.resource,
    ).toBeUndefined();
  });

  it("still refuses a resource-bound refresh token without spending it", async () => {
    const f = await fixture({ code: true, refresh: false });
    const issued = await issueTokens(f);
    const response = await f.refresh(issued.refresh_token);
    expect((await response.json()).error).toBe("invalid_target");
    expect(f.rotate).not.toHaveBeenCalled();
    assert(await f.tokenService.getRefreshToken(issued.refresh_token));
  });

  it("refuses to bind a code to a resource the grant was not opted into", async () => {
    const f = await fixture({ code: false });
    const grant = f.server.grants.authorization_code as AuthorizationCodeGrant<
      TestClient,
      TestUser
    >;
    await expect(
      grant.generateAuthorizationCode(
        { client: CLIENT, user: ALICE, resource: RESOURCE },
        new Request(`${ISSUER}/authorize`),
      ),
    ).rejects.toMatchObject({ extensions: { error: "server_error" } });
    expect(f.savedCodes).not.toHaveBeenCalled();
  });
});

describe("authorization request with resourceIndicators", () => {
  it("stores the accepted resource exactly with the code after asking the policy", async () => {
    const f = await fixture();
    const code = await f.issueCode([RESOURCE]);
    expect((await f.authorizationCodeService.get(code))?.resource).toBe(
      RESOURCE,
    );
    expect(f.policy).toHaveBeenCalledExactlyOnceWith(
      CLIENT,
      ALICE,
      RESOURCE,
      expect.any(BasicScope),
      { grantType: "authorization_code" },
    );
    expect(f.policy.mock.calls[0]?.[3]?.toString()).toBe("read");
  });

  it("asks the policy about a request without a resource and stores none", async () => {
    const f = await fixture();
    const code = await f.issueCode([]);
    expect(f.policy).toHaveBeenCalledExactlyOnceWith(
      CLIENT,
      ALICE,
      undefined,
      expect.any(BasicScope),
      { grantType: "authorization_code" },
    );
    const stored = await f.authorizationCodeService.get(code);
    assert(stored);
    expect("resource" in stored).toBe(false);
  });

  it("lets the policy require a resource", async () => {
    const f = await fixture({
      policy: async (_client, _user, resource) => resource === RESOURCE,
    });
    expectRedirectError(await f.authorize([]), "invalid_target");
    expect(f.savedCodes).not.toHaveBeenCalled();
  });

  it("asks the policy with the consented scope", async () => {
    const f = await fixture();
    vi.spyOn(f.tokenService, "acceptedScope").mockResolvedValue(
      new BasicScope("read"),
    );
    await f.issueCode([RESOURCE], { scope: "read write" });
    expect(f.policy.mock.calls[0]?.[3]?.toString()).toBe("read");
  });

  for (const [name, resources] of MALFORMED) {
    it(`redirects invalid_target for ${name} before signing in or asking the policy`, async () => {
      const f = await fixture();
      const location = expectRedirectError(
        await f.authorize(resources),
        "invalid_target",
      );
      expect(location.search).not.toContain("mcp.example.com");
      expect(f.authenticateUser).not.toHaveBeenCalled();
      expect(f.policy).not.toHaveBeenCalled();
      expect(f.savedCodes).not.toHaveBeenCalled();
    });
  }

  for (const policy of [
    async () => false,
    async () => undefined as unknown as boolean,
    async () => "true" as unknown as boolean,
  ]) {
    it(`redirects invalid_target when the policy answers ${String(policy.toString())}`, async () => {
      const f = await fixture({ policy });
      expectRedirectError(await f.authorize([OTHER]), "invalid_target");
      expect(f.savedCodes).not.toHaveBeenCalled();
    });
  }

  it("issues no code when the policy throws", async () => {
    const f = await fixture({
      policy: async () => {
        throw new Error("synthetic policy failure");
      },
    });
    const response = await f.authorize([RESOURCE]);
    expect(response.headers.get("location") ?? "").not.toContain("code=");
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(f.savedCodes).not.toHaveBeenCalled();
  });

  it("answers without redirecting when the redirect_uri is not registered", async () => {
    const f = await fixture();
    const response = await f.authorize([`${RESOURCE}#tools`], {
      redirect_uri: "https://attacker.example.com/callback",
    });
    expect(response.status).toBe(401);
    expect(response.headers.get("location")).toBeNull();
    expect((await response.json()).error).toBe("unauthorized_client");
  });

  it("answers without redirecting when the client is unknown", async () => {
    const f = await fixture();
    const response = await f.authorize([`${RESOURCE}#tools`], {
      client_id: "unknown-client",
    });
    expect(response.headers.get("location")).toBeNull();
    expect((await response.json()).error).toBe("invalid_client");
  });

  it("fails loudly when the token service has no acceptedResource policy", async () => {
    const f = await fixture({ policy: false });
    expectRedirectError(await f.authorize([RESOURCE]), "server_error");
    expect(f.savedCodes).not.toHaveBeenCalled();
  });

  it("refuses a code store whose save result drops the resource", async () => {
    const f = await fixture();
    const realSave = MemoryAuthorizationCodeService.prototype.save.bind(
      f.authorizationCodeService,
    );
    f.savedCodes.mockImplementation(async (code) => {
      await realSave(code);
      const { resource: _resource, ...dropped } = code;
      return dropped;
    });
    const revoke = vi.spyOn(f.authorizationCodeService, "revoke");
    expectRedirectError(await f.authorize([RESOURCE]), "server_error");
    expect(revoke).toHaveBeenCalledOnce();
    const stored = f.savedCodes.mock.calls[0]?.[0];
    assert(stored);
    expect(await f.authorizationCodeService.get(stored.code)).toBeUndefined();
  });

  it("refuses a code store that returns its input from save but loses the resource on get", async () => {
    const f = await fixture();
    const realGet = f.authorizationCodeService.get.bind(
      f.authorizationCodeService,
    );
    vi.spyOn(f.authorizationCodeService, "get").mockImplementation(
      async (code) => {
        const stored = await realGet(code);
        if (stored) delete stored.resource;
        return stored;
      },
    );
    expectRedirectError(await f.authorize([RESOURCE]), "server_error");
    const stored = f.savedCodes.mock.calls[0]?.[0];
    assert(stored);
    expect(await realGet(stored.code)).toBeUndefined();
  });
});

for (const atomic of [false, true]) {
  describe(`authorization code exchange with resourceIndicators (${atomic ? "exchangeCode" : "revoke then save"})`, () => {
    for (const [name, resources] of [
      ["omits", []],
      ["repeats", [RESOURCE]],
    ] as const) {
      it(`binds the access and refresh tokens to the code's resource when the request ${name} it`, async () => {
        const f = await fixture({ atomic });
        const response = await f.exchange(await f.issueCode(), resources);
        const body = await response.json();
        expect(response.status, JSON.stringify(body)).toBe(200);
        expect(
          (await f.tokenService.getToken(body.access_token))?.resource,
        ).toBe(RESOURCE);
        expect(
          (await f.tokenService.getRefreshToken(body.refresh_token))?.resource,
        ).toBe(RESOURCE);
        expect(f.generated.mock.calls[0]?.at(5)).toBe(RESOURCE);
        expect(f.policy).toHaveBeenCalledOnce();
      });
    }

    for (const [name, value] of SPELLING_VARIANTS) {
      it(`refuses ${name} and consumes the code`, async () => {
        const f = await fixture({ atomic });
        const code = await f.issueCode();
        await expectInvalidTarget(await f.exchange(code, [value]));
        expect(f.generated).not.toHaveBeenCalled();
        expect(f.savedTokens).not.toHaveBeenCalled();
        const retry = await f.exchange(code, [RESOURCE]);
        expect((await retry.json()).error).toBe("invalid_grant");
        expect(f.savedTokens).not.toHaveBeenCalled();
      });
    }

    for (const [name, resources] of MALFORMED) {
      it(`refuses ${name} and consumes the code`, async () => {
        const f = await fixture({ atomic });
        const code = await f.issueCode();
        await expectInvalidTarget(await f.exchange(code, resources));
        expect(f.savedTokens).not.toHaveBeenCalled();
        expect((await (await f.exchange(code)).json()).error).toBe(
          "invalid_grant",
        );
      });
    }

    it("issues unbound tokens from a code issued without a resource", async () => {
      const f = await fixture({ atomic });
      const body = await issueTokens(f, []);
      expect(
        (await f.tokenService.getToken(body.access_token))?.resource,
      ).toBeUndefined();
      expect(
        (await f.tokenService.getRefreshToken(body.refresh_token))?.resource,
      ).toBeUndefined();
      expect(f.generated.mock.calls[0]).toHaveLength(5);
    });

    it("refuses to add a resource at the token request to a code issued without one", async () => {
      const f = await fixture({ atomic });
      const code = await f.issueCode([]);
      await expectInvalidTarget(await f.exchange(code, [RESOURCE]));
      expect(f.savedTokens).not.toHaveBeenCalled();
      expect((await (await f.exchange(code)).json()).error).toBe(
        "invalid_grant",
      );
    });

    it("keeps PKCE ahead of the resource check", async () => {
      const f = await fixture({ atomic });
      const code = await f.issueCode();
      const response = await f.exchange(
        code,
        [RESOURCE],
        generateCodeVerifier(),
      );
      expect((await response.json()).error).toBe("invalid_grant");
      expect(f.savedTokens).not.toHaveBeenCalled();
    });

    it("refuses a token store that drops the binding and revokes what it saved", async () => {
      const f = await fixture({ atomic });
      const realGet = f.tokenService.getToken.bind(f.tokenService);
      vi.spyOn(f.tokenService, "getToken").mockImplementation(async (value) => {
        const stored = await realGet(value);
        if (stored) delete stored.resource;
        return stored;
      });
      const response = await f.exchange(await f.issueCode());
      const body = await response.json();
      expect(response.status).toBe(500);
      expect(body.access_token).toBeUndefined();
      const saved = f.savedTokens.mock.calls[0]?.[0];
      assert(saved);
      expect(await realGet(saved.accessToken)).toBeUndefined();
    });

    it("refuses a token store that drops the binding from refresh-token reads", async () => {
      const f = await fixture({ atomic });
      const realGet = f.tokenService.getRefreshToken.bind(f.tokenService);
      vi.spyOn(f.tokenService, "getRefreshToken").mockImplementation(
        async (value) => {
          const stored = await realGet(value);
          if (stored) delete stored.resource;
          return stored;
        },
      );
      const response = await f.exchange(await f.issueCode());
      expect(response.status).toBe(500);
      expect((await response.json()).refresh_token).toBeUndefined();
    });
  });
}

describe("OIDC with a resource-bound code", () => {
  it("still issues the id_token for the client while the access token targets the resource", async () => {
    const f = await fixture({ audience: OTHER });
    const code = await f.issueCode([RESOURCE], {
      scope: "openid read",
      nonce: "synthetic-nonce",
    });
    const body = await (await f.exchange(code)).json();
    const idToken = await verifyJwt(body.id_token, f.signingKey.publicJwk);
    expect(idToken?.aud).toBe(CLIENT.id);
    expect(idToken?.nonce).toBe("synthetic-nonce");
    const access = await verifyJwt(body.access_token, f.signingKey.publicJwk);
    expect(access?.aud).toBe(RESOURCE);
  });
});

describe("refresh with resourceIndicators", () => {
  it("keeps the binding on the successor access and refresh tokens across rotations", async () => {
    const f = await fixture();
    let current = (await issueTokens(f)).refresh_token;
    for (const resources of [[], [RESOURCE], []] as const) {
      const response = await f.refresh(current, resources);
      const body = await response.json();
      expect(response.status, JSON.stringify(body)).toBe(200);
      expect((await f.tokenService.getToken(body.access_token))?.resource).toBe(
        RESOURCE,
      );
      const successor = (await f.tokenService.getRefreshToken(
        body.refresh_token,
      )) as BoundRefresh | undefined;
      expect(successor?.resource).toBe(RESOURCE);
      expect(f.generated.mock.lastCall?.at(5)).toBe(RESOURCE);
      expect(await f.tokenService.getRefreshToken(current)).toBeUndefined();
      current = body.refresh_token;
    }
    expect(f.policy).toHaveBeenCalledOnce();
  });

  it("narrows scope without losing the binding", async () => {
    const f = await fixture();
    const issued = await issueTokens(f);
    const response = await f.refresh(issued.refresh_token, [], {
      scope: "read",
    });
    const body = await response.json();
    expect(response.status, JSON.stringify(body)).toBe(200);
    expect(body.scope).toBe("read");
    expect((await f.tokenService.getToken(body.access_token))?.resource).toBe(
      RESOURCE,
    );
    expect(
      (await f.refresh(body.refresh_token, [], { scope: "write" })).status,
    ).toBe(400);
  });

  for (const [name, resources] of [
    ...SPELLING_VARIANTS.map(([label, value]) => [label, [value]] as const),
    ...MALFORMED,
  ]) {
    it(`refuses ${name} on a bound token without rotating, spending or revoking it`, async () => {
      const f = await fixture();
      const issued = await issueTokens(f);
      f.generated.mockClear();
      f.savedTokens.mockClear();
      await expectInvalidTarget(
        await f.refresh(issued.refresh_token, resources),
      );
      expect(f.generated).not.toHaveBeenCalled();
      expect(f.rotate).not.toHaveBeenCalled();
      expect(f.savedTokens).not.toHaveBeenCalled();
      expect(f.revokeFamily).not.toHaveBeenCalled();
      expect(
        (await f.tokenService.getRefreshToken(issued.refresh_token))?.resource,
      ).toBe(RESOURCE);
      expect(
        (await f.tokenService.getToken(issued.access_token))?.resource,
      ).toBe(RESOURCE);
      const retry = await f.refresh(issued.refresh_token);
      expect(retry.status).toBe(200);
    });
  }

  it("refuses to add a binding to an unbound token and leaves it usable", async () => {
    const f = await fixture();
    const issued = await issueTokens(f, []);
    await expectInvalidTarget(
      await f.refresh(issued.refresh_token, [RESOURCE]),
    );
    expect(f.rotate).not.toHaveBeenCalled();
    const response = await f.refresh(issued.refresh_token);
    const body = await response.json();
    expect(response.status, JSON.stringify(body)).toBe(200);
    expect(
      (await f.tokenService.getRefreshToken(body.refresh_token))?.resource,
    ).toBeUndefined();
    expect(f.generated.mock.lastCall).toHaveLength(5);
  });

  it("keeps the binding through the two-step rotation without rotate", async () => {
    const f = await fixture();
    Object.assign(f.tokenService, { rotate: undefined });
    const issued = await issueTokens(f);
    const body = await (await f.refresh(issued.refresh_token)).json();
    expect(
      (await f.tokenService.getRefreshToken(body.refresh_token))?.resource,
    ).toBe(RESOURCE);
  });

  it("refuses a successor whose store dropped the binding", async () => {
    const f = await fixture();
    const issued = await issueTokens(f);
    const realGet = f.tokenService.getRefreshToken.bind(f.tokenService);
    f.rotate.mockImplementation(async (current, next) => {
      const { resource: _resource, ...dropped } = next;
      return await MemoryTokenService.prototype.rotate.call(
        f.tokenService,
        current,
        dropped,
      );
    });
    const response = await f.refresh(issued.refresh_token);
    expect(response.status).toBe(500);
    const saved = f.rotate.mock.calls[0]?.[1];
    assert(saved);
    expect(await realGet(saved.refreshToken)).toBeUndefined();
  });
});

describe("audience of tokens from the code and refresh grants", () => {
  it("puts the bound resource in the JWT aud ahead of the configured audience, through refresh", async () => {
    const f = await fixture({ audience: OTHER });
    const issued = await issueTokens(f);
    const refreshed = await (await f.refresh(issued.refresh_token)).json();
    for (const value of [issued.access_token, refreshed.access_token]) {
      expect((await verifyJwt(value, f.signingKey.publicJwk))?.aud).toBe(
        RESOURCE,
      );
    }
    const jwks = { keys: [f.signingKey.publicJwk] };
    const reader = (audience: string) =>
      new JwksTokenReader<TestClient, TestUser>({
        issuer: ISSUER,
        audience,
        jwksUri: `${ISSUER}/jwks`,
        getClient: (claims) => ({ id: String(claims.client_id) }),
        fetch: async () => Response.json(jwks),
      });
    assert(await reader(RESOURCE).getToken(refreshed.access_token));
    expect(
      await reader(OTHER).getToken(refreshed.access_token),
    ).toBeUndefined();
  });

  it("keeps the configured audience for an unbound code", async () => {
    const f = await fixture({ audience: OTHER });
    const issued = await issueTokens(f, []);
    expect(
      (await verifyJwt(issued.access_token, f.signingKey.publicJwk))?.aud,
    ).toBe(OTHER);
  });

  it("introspects bound access and refresh tokens with the resource as aud, ahead of extensions", async () => {
    const f = await fixture();
    const issued = await issueTokens(f);
    const refreshed = await (await f.refresh(issued.refresh_token)).json();
    for (const value of [refreshed.access_token, refreshed.refresh_token]) {
      const body = await f.introspect(value);
      expect(body.active).toBe(true);
      expect(body.aud).toBe(RESOURCE);
    }
    const unbound = await issueTokens(f, []);
    expect((await f.introspect(unbound.access_token)).aud).toBe(OTHER);
  });
});

describe("acceptedResource context and consent", () => {
  it("tells the policy the authorization endpoint is asking for the code grant", async () => {
    const f = await fixture();
    await f.issueCode([RESOURCE]);
    expect(f.policy.mock.calls[0]?.[4]).toStrictEqual({
      grantType: "authorization_code",
    });
  });

  it("lets a policy separate machine from user issuance by grant type", async () => {
    const f = await fixture({
      policy: async (_client, _user, resource, _scope, context) =>
        context?.grantType === "authorization_code" && resource === RESOURCE,
    });
    await f.issueCode([RESOURCE]);
  });

  it("passes the exact requested resource to the consent handler and to authenticateUser", async () => {
    const spelled = "https://mcp.example.com/mcp?tenant=%41";
    const f = await fixture({ policy: async () => true });
    f.authenticateUser.mockResolvedValue({
      user: ALICE,
      authorizedScope: undefined as unknown as BasicScope,
    });
    const handleConsent = vi.fn<HandleConsentFn<TestClient, BasicScope>>(
      async () => ({ approved: true }),
    );
    const code = await (async () => {
      const response = await f.authorize([spelled], {}, handleConsent);
      const location = new URL(response.headers.get("location")!);
      return location.searchParams.get("code");
    })();
    assert(code);
    expect(handleConsent).toHaveBeenCalledOnce();
    expect(handleConsent.mock.calls[0]?.[3]?.resource).toBe(spelled);
    const authenticateArgs = f.authenticateUser.mock.calls[0] as unknown[];
    expect(
      (authenticateArgs[1] as { resource?: string } | undefined)?.resource,
    ).toBe(spelled);
    expect((await f.authorizationCodeService.get(code))?.resource).toBe(
      spelled,
    );
  });

  for (const code of [false, true]) {
    it(`gives the consent handler no resource ${code ? "when none was named" : "without resourceIndicators"}`, async () => {
      const f = await fixture({ code });
      f.authenticateUser.mockResolvedValue({
        user: ALICE,
        authorizedScope: undefined as unknown as BasicScope,
      });
      const handleConsent = vi.fn<HandleConsentFn<TestClient, BasicScope>>(
        async () => ({ approved: true }),
      );
      await f.authorize(code ? [] : [RESOURCE], {}, handleConsent);
      expect(handleConsent).toHaveBeenCalledOnce();
      const authentication = handleConsent.mock.calls[0]?.[3];
      assert(authentication);
      expect("resource" in authentication).toBe(false);
    });
  }

  it("still asks the policy under prompt=none with remembered consent", async () => {
    const f = await fixture({
      policy: async (_client, _user, resource) => resource === RESOURCE,
    });
    const handleConsent = vi.fn<HandleConsentFn<TestClient, BasicScope>>(
      async () => ({ approved: true }),
    );
    expectRedirectError(
      await f.authorize([OTHER], { prompt: "none" }, handleConsent),
      "invalid_target",
    );
    expect(handleConsent).not.toHaveBeenCalled();
    expect(f.policy).toHaveBeenCalledOnce();
    expect(f.savedCodes).not.toHaveBeenCalled();
    const response = await f.authorize(
      [RESOURCE],
      { prompt: "none" },
      handleConsent,
    );
    const location = new URL(response.headers.get("location")!);
    assert(location.searchParams.get("code"));
    expect(handleConsent).not.toHaveBeenCalled();
  });

  it("refuses a code that a generateAuthorizationCode override returned without the accepted resource", async () => {
    const f = await fixture();
    const original = f.codeGrant.generateAuthorizationCode.bind(f.codeGrant);
    vi.spyOn(f.codeGrant, "generateAuthorizationCode").mockImplementation(
      async (options, request) =>
        await original({ ...options, resource: null }, request),
    );
    expectRedirectError(await f.authorize([RESOURCE]), "server_error");
  });
});

describe("additional resource binding cases", () => {
  it("refuses a token store that invents a binding on an unbound issuance", async () => {
    const f = await fixture();
    const code = await f.issueCode([]);
    f.savedTokens.mockImplementation((async (token: Bound) => ({
      ...(await MemoryTokenService.prototype.save.call(f.tokenService, token)),
      resource: OTHER,
    })) as typeof f.tokenService.save);
    const response = await f.exchange(code);
    expect(response.status).toBe(500);
    expect((await response.json()).access_token).toBeUndefined();
  });

  for (const atomic of [false, true]) {
    it(`never issues an unbound or mismatched token from concurrent exchanges of one code (${atomic ? "exchangeCode" : "revoke then save"})`, async () => {
      const f = await fixture({ atomic });
      const code = await f.issueCode();
      const [matching, mismatching] = await Promise.all([
        f.exchange(code, [RESOURCE]),
        f.exchange(code, [OTHER]),
      ]);
      expect(mismatching.status).toBe(400);
      expect(["invalid_target", "invalid_grant"]).toContain(
        (await mismatching.json()).error,
      );
      expect([200, 400]).toContain(matching.status);
      const body = await matching.json();
      if (matching.status === 200) {
        expect(
          (await f.tokenService.getToken(body.access_token))?.resource,
        ).toBe(RESOURCE);
      }
      for (const [saved] of f.savedTokens.mock.calls) {
        expect(saved.resource).toBe(RESOURCE);
      }
      expect(f.savedTokens.mock.calls.length).toBeLessThanOrEqual(1);
    });
  }

  it("never issues a mismatched successor from concurrent refreshes", async () => {
    const f = await fixture();
    const issued = await issueTokens(f);
    const [matching, mismatching] = await Promise.all([
      f.refresh(issued.refresh_token),
      f.refresh(issued.refresh_token, [OTHER]),
    ]);
    expect(mismatching.status).toBe(400);
    expect(["invalid_target", "invalid_grant"]).toContain(
      (await mismatching.json()).error,
    );
    const body = await matching.json();
    expect(matching.status, JSON.stringify(body)).toBe(200);
    expect(
      (await f.tokenService.getRefreshToken(body.refresh_token))?.resource,
    ).toBe(RESOURCE);
    for (const [, next] of f.rotate.mock.calls) {
      expect(next.resource).toBe(RESOURCE);
    }
  });

  it("keeps the binding when the token service does not rotate the refresh token", async () => {
    const f = await fixture();
    const issued = await issueTokens(f);
    vi.spyOn(f.tokenService, "generateRefreshToken").mockResolvedValue(
      undefined,
    );
    const response = await f.refresh(issued.refresh_token);
    const body = await response.json();
    expect(response.status, JSON.stringify(body)).toBe(200);
    expect((await f.tokenService.getToken(body.access_token))?.resource).toBe(
      RESOURCE,
    );
    expect(f.rotate.mock.calls[0]?.[1].refreshToken).toBe(issued.refresh_token);
    expect(f.rotate.mock.calls[0]?.[1].resource).toBe(RESOURCE);
  });

  it("keeps a bound code bound after the code grant's option is turned off", async () => {
    const f = await fixture();
    const code = await f.issueCode();
    Object.defineProperty(f.codeGrant, "resourceIndicators", { value: false });
    const response = await f.exchange(code, [OTHER]);
    const body = await response.json();
    expect(response.status, JSON.stringify(body)).toBe(200);
    expect((await f.tokenService.getToken(body.access_token))?.resource).toBe(
      RESOURCE,
    );
    expect(
      (await f.tokenService.getRefreshToken(body.refresh_token))?.resource,
    ).toBe(RESOURCE);
  });

  it("ignores resource in the token endpoint's query string", async () => {
    const f = await fixture();
    const code = await f.issueCode([]);
    const query = `?resource=${encodeURIComponent(RESOURCE)}`;
    const response = await f.exchange(code, [], undefined, query);
    const body = await response.json();
    expect(response.status, JSON.stringify(body)).toBe(200);
    expect(
      (await f.tokenService.getToken(body.access_token))?.resource,
    ).toBeUndefined();
    const refreshed = await f.refresh(body.refresh_token, [], {}, query);
    const next = await refreshed.json();
    expect(refreshed.status, JSON.stringify(next)).toBe(200);
    expect(
      (await f.tokenService.getRefreshToken(next.refresh_token))?.resource,
    ).toBeUndefined();
  });
});
