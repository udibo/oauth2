import { describe, expect, it } from "vitest";

import { HonoAuthorizationServer } from "../adapters/hono/authorization-server.ts";
import {
  InsufficientScopeError,
  InvalidRequestError,
  InvalidTokenError,
} from "../errors.ts";
import type { BasicScope } from "../models/scope.ts";
import {
  basicAuthHeader,
  formRequest,
  MemoryAuthorizationCodeService,
  MemoryClientService,
  MemoryDeviceAuthorizationService,
  MemoryTokenService,
  MemoryUserService,
  type TestClient,
  type TestUser,
} from "../testing/_test_fixtures.ts";
import {
  AuthorizationServer,
  type AuthorizationServerOptions,
  ENDPOINT_PATHS,
} from "./authorization-server.ts";
import { AuthorizationCodeGrant } from "./grants/authorization-code.ts";
import { ClientCredentialsGrant } from "./grants/client-credentials.ts";
import type { SigningKeyProvider } from "./signing-keys.ts";

const ORIGIN = "https://auth.example.com";
const CLIENT_ID = "fixture-client";
const ERROR_FORMATS = ["oauth2", "problem-details"] as const;
const RFC_MEMBERS = new Set(["error", "error_description", "error_uri"]);
type Transport = "core" | "hono";
type Options = Partial<
  AuthorizationServerOptions<TestClient, TestUser, BasicScope>
>;

async function createServer(
  transport: Transport,
  options: Options,
): Promise<{
  server: AuthorizationServer<TestClient, TestUser, BasicScope>;
  fetch: (request: Request) => Promise<Response>;
}> {
  const userService = new MemoryUserService<TestUser>();
  const clientService = new MemoryClientService<TestClient, TestUser>(
    userService,
  );
  await clientService.add(
    { id: CLIENT_ID, grants: ["client_credentials"] },
    "fixture-secret",
  );
  const services = {
    clientService,
    userService,
    tokenService: new MemoryTokenService<TestClient, TestUser>({
      clientService,
      userService,
    }),
    authorizationCodeService: new MemoryAuthorizationCodeService<
      TestClient,
      TestUser
    >({ clientService, userService }),
    deviceAuthorizationService: new MemoryDeviceAuthorizationService<
      TestClient,
      TestUser
    >({ clientService, userService }),
  };
  const serverOptions: AuthorizationServerOptions<
    TestClient,
    TestUser,
    BasicScope
  > = {
    resolve: () => ({
      services,
      issuer: ORIGIN,
      verificationUri: `${ORIGIN}/device`,
    }),
    grants: {
      authorization_code: new AuthorizationCodeGrant({
        resolve: () => services,
      }),
      client_credentials: new ClientCredentialsGrant({
        resolve: () => services,
      }),
    },
    endSession: () => ({}),
    ...options,
  };
  if (transport === "core") {
    const server = new AuthorizationServer(serverOptions);
    const handlers: Record<string, (request: Request) => Promise<Response>> = {
      [ENDPOINT_PATHS.token]: (r) => server.handleTokenRequest(r),
      [ENDPOINT_PATHS.revocation]: (r) => server.handleRevocationRequest(r),
      [ENDPOINT_PATHS.introspection]: (r) =>
        server.handleIntrospectionRequest(r),
      [ENDPOINT_PATHS.deviceAuthorization]: (r) =>
        server.handleDeviceAuthorizationRequest(r),
      [ENDPOINT_PATHS.authorization]: (r) =>
        server.handleAuthorizeRequest(r, () => Promise.resolve(null)),
      [ENDPOINT_PATHS.endSession]: (r) => server.handleEndSessionRequest(r),
      [ENDPOINT_PATHS.metadata]: (r) => server.handleMetadataRequest(r),
      [ENDPOINT_PATHS.oidcMetadata]: (r) => server.handleOidcMetadataRequest(r),
      [ENDPOINT_PATHS.jwks]: (r) => server.handleJwksRequest(r),
      [ENDPOINT_PATHS.userinfo]: (r) => server.handleUserInfoRequest(r),
    };
    return {
      server,
      fetch: (request) => handlers[new URL(request.url).pathname]!(request),
    };
  }
  const server = new HonoAuthorizationServer(serverOptions);
  const app = server.routes({ authenticateUser: () => Promise.resolve(null) });
  return { server, fetch: async (request) => await app.request(request) };
}

const failingSigningKeys: SigningKeyProvider = {
  getSigningKey: () => Promise.reject(new Error("key store unreachable")),
  getPublicJwks: () => Promise.reject(new Error("key store unreachable")),
};

const NO_STORE = { "cache-control": "no-store", pragma: "no-cache" };
const BASIC_CHALLENGE = {
  ...NO_STORE,
  "www-authenticate": 'Basic realm="Service"',
};

interface EndpointError {
  endpoint: string;
  request: () => Request;
  options?: Options;
  status: number;
  error: string;
  headers?: Record<string, string>;
}

const endpointErrors: EndpointError[] = [
  {
    endpoint: "token with an unsupported grant_type",
    request: () =>
      formRequest(`${ORIGIN}${ENDPOINT_PATHS.token}`, {
        grant_type: "urn:example:unsupported",
      }),
    status: 400,
    error: "unsupported_grant_type",
    headers: NO_STORE,
  },
  {
    endpoint: "token with a wrong Basic secret",
    request: () =>
      formRequest(
        `${ORIGIN}${ENDPOINT_PATHS.token}`,
        { grant_type: "client_credentials" },
        basicAuthHeader(CLIENT_ID, "wrong-secret"),
      ),
    status: 401,
    error: "invalid_client",
    headers: BASIC_CHALLENGE,
  },
  {
    endpoint: "revocation without client credentials",
    request: () =>
      formRequest(`${ORIGIN}${ENDPOINT_PATHS.revocation}`, { token: "x" }),
    status: 401,
    error: "invalid_client",
    headers: NO_STORE,
  },
  {
    endpoint: "revocation with a wrong Basic secret",
    request: () =>
      formRequest(
        `${ORIGIN}${ENDPOINT_PATHS.revocation}`,
        { token: "x" },
        basicAuthHeader(CLIENT_ID, "wrong-secret"),
      ),
    status: 401,
    error: "invalid_client",
    headers: BASIC_CHALLENGE,
  },
  {
    endpoint: "introspection without client credentials",
    request: () =>
      formRequest(`${ORIGIN}${ENDPOINT_PATHS.introspection}`, { token: "x" }),
    status: 401,
    error: "invalid_client",
    headers: NO_STORE,
  },
  {
    endpoint: "device authorization without client credentials",
    request: () =>
      formRequest(`${ORIGIN}${ENDPOINT_PATHS.deviceAuthorization}`, {
        scope: "read",
      }),
    status: 401,
    error: "invalid_client",
    headers: NO_STORE,
  },
  {
    endpoint: "authorization without a redirect target",
    request: () =>
      new Request(
        `${ORIGIN}${ENDPOINT_PATHS.authorization}?response_type=code`,
      ),
    status: 400,
    error: "invalid_request",
  },
  {
    endpoint: "end session with an oversized body",
    request: () =>
      formRequest(`${ORIGIN}${ENDPOINT_PATHS.endSession}`, {
        padding: "a".repeat(70_000),
      }),
    status: 413,
    error: "invalid_request",
  },
  {
    endpoint: "metadata whose context cannot be resolved",
    request: () => new Request(`${ORIGIN}${ENDPOINT_PATHS.metadata}`),
    options: {
      resolve: () => {
        throw new Error("tenant lookup failed");
      },
    },
    status: 500,
    error: "server_error",
  },
  {
    endpoint: "OIDC metadata with issuance off",
    request: () => new Request(`${ORIGIN}${ENDPOINT_PATHS.oidcMetadata}`),
    status: 404,
    error: "not_found",
  },
  {
    endpoint: "JWKS with issuance off",
    request: () => new Request(`${ORIGIN}${ENDPOINT_PATHS.jwks}`),
    status: 404,
    error: "not_found",
  },
  {
    endpoint: "JWKS whose key provider fails",
    request: () => new Request(`${ORIGIN}${ENDPOINT_PATHS.jwks}`),
    options: { signingKeys: failingSigningKeys },
    status: 500,
    error: "server_error",
  },
];

describe("OAuth endpoint error format", () => {
  for (const transport of ["core", "hono"] as const) {
    for (const errorFormat of ERROR_FORMATS) {
      for (const {
        endpoint,
        request,
        options,
        status,
        error,
        headers,
      } of endpointErrors) {
        it(`${transport} answers ${endpoint} in the RFC 6749 format under errorFormat ${errorFormat}`, async () => {
          const { fetch } = await createServer(transport, {
            ...options,
            errorFormat,
          });

          const response = await fetch(request());

          expect(response.status).toBe(status);
          expect(response.headers.get("content-type")).toBe(
            "application/json;charset=UTF-8",
          );
          for (const [name, value] of Object.entries(headers ?? {})) {
            expect(response.headers.get(name)).toBe(value);
          }
          const body = await response.json();
          expect(body.error).toBe(error);
          expect(body.error_description).toMatch(/\S/);
          expect(
            Object.keys(body).filter((member) => !RFC_MEMBERS.has(member)),
          ).toStrictEqual([]);
          expect(JSON.stringify(body)).not.toMatch(
            /tenant lookup failed|key store unreachable/,
          );
        });
      }
    }

    for (const { endpoint, request, options } of endpointErrors) {
      it(`${transport} answers ${endpoint} identically under either errorFormat`, async () => {
        const responses = await Promise.all(
          ERROR_FORMATS.map(async (errorFormat) =>
            (await createServer(transport, { ...options, errorFormat })).fetch(
              request(),
            ),
          ),
        );
        const [oauth2, problem] = await Promise.all(
          responses.map(async (response) => ({
            status: response.status,
            headers: [...response.headers],
            body: await response.json(),
          })),
        );

        expect(problem).toStrictEqual(oauth2);
      });
    }

    it(`${transport} answers a UserInfo bearer refusal as problem details under errorFormat problem-details`, async () => {
      const { fetch } = await createServer(transport, {
        errorFormat: "problem-details",
      });

      const response = await fetch(
        new Request(`${ORIGIN}${ENDPOINT_PATHS.userinfo}`),
      );

      expect(response.status).toBe(401);
      expect(response.headers.get("content-type")).toBe(
        "application/problem+json",
      );
      expect(response.headers.get("www-authenticate")).toMatch(/^Bearer /);
      expect((await response.json()).status).toBe(401);
    });

    it(`${transport} answers a UserInfo bearer refusal in the RFC format under errorFormat oauth2`, async () => {
      const { fetch } = await createServer(transport, {
        errorFormat: "oauth2",
      });

      const response = await fetch(
        new Request(`${ORIGIN}${ENDPOINT_PATHS.userinfo}`),
      );

      expect(response.status).toBe(401);
      expect(response.headers.get("content-type")).toBe(
        "application/json;charset=UTF-8",
      );
      expect(response.headers.get("www-authenticate")).toMatch(/^Bearer /);
      const body = await response.json();
      expect(body.error).toBe("access_denied");
      expect(body.status).toBe(undefined);
    });

    for (const [errorFormat, contentType] of [
      ["problem-details", "application/problem+json"],
      ["oauth2", "application/json;charset=UTF-8"],
    ] as const) {
      it(`${transport} formats handleAuthError by errorFormat ${errorFormat}`, async () => {
        const { server } = await createServer(transport, { errorFormat });
        const refusal = await server
          .authenticate(new Request(`${ORIGIN}/api/resource`))
          .then(
            () => undefined,
            (error: unknown) => error,
          );

        const response = server.handleAuthError(refusal);

        expect(response.status).toBe(401);
        expect(response.headers.get("content-type")).toBe(contentType);
        expect(response.headers.get("www-authenticate")).toMatch(/^Bearer /);
        await response.arrayBuffer();
      });
    }
  }

  describe("protected-resource refusal body", () => {
    const refusals = [
      {
        name: "invalid_token",
        error: () => new InvalidTokenError("token expired"),
        problemMembers: ["detail", "error", "status", "title"],
        challenge:
          'Bearer realm="Service", error="invalid_token", error_description="token expired"',
      },
      {
        name: "insufficient_scope",
        error: () =>
          new InsufficientScopeError("insufficient scope", {
            extensions: { requiredScope: "write" },
          }),
        problemMembers: ["detail", "error", "requiredScope", "status", "title"],
        challenge:
          'Bearer realm="Service", error="insufficient_scope", error_description="insufficient scope", scope="write"',
      },
    ];

    for (const { name, error, problemMembers, challenge } of refusals) {
      it(`keeps the ${name} problem-details body to the problem members, error and extensions`, async () => {
        const { server } = await createServer("core", {
          errorFormat: "problem-details",
        });

        const response = server.handleAuthError(error());

        expect(response.headers.get("content-type")).toBe(
          "application/problem+json",
        );
        expect(Object.keys(await response.json()).sort()).toStrictEqual(
          problemMembers,
        );
      });

      it(`carries the ${name} error and error_description in the challenge under either errorFormat`, async () => {
        for (const errorFormat of ERROR_FORMATS) {
          const { server } = await createServer("core", { errorFormat });

          const response = server.handleAuthError(error());

          expect(response.headers.get("www-authenticate")).toBe(challenge);
          await response.arrayBuffer();
        }
      });

      it(`keeps the ${name} oauth2 body to error and error_description`, async () => {
        const { server } = await createServer("core", {
          errorFormat: "oauth2",
        });

        const response = server.handleAuthError(error());

        expect(response.headers.get("content-type")).toBe(
          "application/json;charset=UTF-8",
        );
        expect(Object.keys(await response.json()).sort()).toStrictEqual([
          "error",
          "error_description",
        ]);
      });
    }

    it("keeps a missing-credentials refusal to the problem members and error", async () => {
      const { fetch } = await createServer("core", {
        errorFormat: "problem-details",
      });

      const response = await fetch(
        new Request(`${ORIGIN}${ENDPOINT_PATHS.userinfo}`),
      );

      expect(response.headers.get("www-authenticate")).toBe(
        'Bearer realm="Service"',
      );
      expect(Object.keys(await response.json()).sort()).toStrictEqual([
        "detail",
        "error",
        "status",
        "title",
      ]);
    });

    it("emits error_description and error_uri in a problem-details body only when the error sets them", async () => {
      const { server } = await createServer("core", {
        errorFormat: "problem-details",
      });

      const response = server.handleAuthError(
        new InvalidTokenError("token expired", {
          extensions: {
            error_description: "Sign in again.",
            error_uri: "https://auth.example.com/errors/expired",
          },
        }),
      );

      const body = await response.json();
      expect(body.detail).toBe("token expired");
      expect(body.error_description).toBe("Sign in again.");
      expect(body.error_uri).toBe("https://auth.example.com/errors/expired");
      expect(body.type).toBe("https://auth.example.com/errors/expired");
    });

    it("keeps a typed refusal's URI in type alone in a problem-details body", async () => {
      const { server } = await createServer("core", {
        errorFormat: "problem-details",
      });
      const refusal = new InvalidTokenError("token expired", {
        type: "https://auth.example.com/errors/expired",
      });

      const body = await server.handleAuthError(refusal).json();

      expect(body.type).toBe("https://auth.example.com/errors/expired");
      expect("error_uri" in body).toBe(false);
      expect(refusal.extensions.error_uri).toBe(undefined);
    });
  });

  it("answers a typed endpoint error with error_uri from its type", async () => {
    const { fetch } = await createServer("core", {
      errorFormat: "problem-details",
      endSession: () => {
        throw new InvalidRequestError("logout_hint is malformed", {
          type: "https://auth.example.com/errors/logout-hint",
        });
      },
    });

    const response = await fetch(
      new Request(`${ORIGIN}${ENDPOINT_PATHS.endSession}`),
    );

    expect(response.status).toBe(400);
    expect(await response.json()).toStrictEqual({
      error: "invalid_request",
      error_description: "logout_hint is malformed",
      error_uri: "https://auth.example.com/errors/logout-hint",
    });
  });
});
