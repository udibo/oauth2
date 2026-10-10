import { describe, expect, it, vi } from "vitest";
import { rejection } from "../_test_assert.ts";
import { Hono } from "hono";

import { HonoAuthorizationServer } from "../adapters/hono/authorization-server.ts";
import { InvalidRequestError } from "../errors.ts";
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
} from "./authorization-server.ts";
import { AuthorizationCodeGrant } from "./grants/authorization-code.ts";
import { ClientCredentialsGrant } from "./grants/client-credentials.ts";
import { DeviceAuthorizationGrant } from "./grants/device-authorization.ts";
import type { DispatchableGrant } from "./grants/grant.ts";
import { PasswordGrant } from "./grants/password.ts";
import { RefreshTokenGrant } from "./grants/refresh-token.ts";

const DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";
const CUSTOM_GRANT = "urn:example:custom";
type Endpoint = "token" | "revocation" | "introspection" | "device";
type Transport = "core" | "hono";

async function createFixture(
  transport: Transport,
  options: Pick<
    AuthorizationServerOptions<TestClient, TestUser, BasicScope>,
    "errorFormat" | "throwOnError"
  > = {},
) {
  const userService = new MemoryUserService<TestUser>();
  const clientService = new MemoryClientService<TestClient, TestUser>(
    userService,
  );
  const tokenService = new MemoryTokenService<TestClient, TestUser>({
    clientService,
    userService,
  });
  const authorizationCodeService = new MemoryAuthorizationCodeService<
    TestClient,
    TestUser
  >({ clientService, userService });
  const deviceAuthorizationService = new MemoryDeviceAuthorizationService<
    TestClient,
    TestUser
  >({ clientService, userService });
  const client: TestClient = {
    id: "fixture-client",
    grants: [
      "client_credentials",
      "authorization_code",
      "refresh_token",
      "password",
      DEVICE_GRANT,
      CUSTOM_GRANT,
    ],
  };
  await clientService.add(client, "fixture-secret");
  await tokenService.save({ client, accessToken: "fixture-token" });
  const services = {
    clientService,
    tokenService,
    userService,
    authorizationCodeService,
    deviceAuthorizationService,
  };
  const grantResolve = vi.fn(() => services);
  const clientCredentials = new ClientCredentialsGrant({
    resolve: grantResolve,
  });
  let extensions: Record<string, FormDataEntryValue[]> = {};
  const grants: Record<string, DispatchableGrant<TestClient, TestUser>> = {
    client_credentials: clientCredentials,
    authorization_code: new AuthorizationCodeGrant({ resolve: grantResolve }),
    refresh_token: new RefreshTokenGrant({ resolve: grantResolve }),
    password: new PasswordGrant({ resolve: grantResolve }),
    [DEVICE_GRANT]: new DeviceAuthorizationGrant({ resolve: grantResolve }),
    [CUSTOM_GRANT]: {
      grantType: CUSTOM_GRANT,
      issuesIdToken: false,
      getAuthenticatedClient: (request, body) =>
        clientCredentials.getAuthenticatedClient(request, body),
      token: (request, authenticatedClient, body) => {
        extensions = Object.fromEntries(
          ["resource", "audience", "custom"].map((name) => [
            name,
            body.getAll(name),
          ]),
        );
        return clientCredentials.token(request, authenticatedClient, body);
      },
    },
  };
  const resolve = vi.fn(() => ({
    services,
    issuer: "https://auth.example.com",
    verificationUri: "https://auth.example.com/device",
  }));
  const serverOptions = { ...options, resolve, grants };
  const server =
    transport === "hono"
      ? new HonoAuthorizationServer(serverOptions)
      : new AuthorizationServer(serverOptions);
  const observers = [
    vi.spyOn(clientService, "getAuthenticated"),
    vi.spyOn(clientService, "get"),
    vi.spyOn(tokenService, "getToken"),
    vi.spyOn(tokenService, "getRefreshToken"),
    vi.spyOn(tokenService, "save"),
    vi.spyOn(tokenService, "revoke"),
    vi.spyOn(authorizationCodeService, "get"),
    vi.spyOn(deviceAuthorizationService, "getByDeviceCode"),
    vi.spyOn(deviceAuthorizationService, "save"),
    ...Object.values(grants).flatMap((grant) => [
      vi.spyOn(grant, "getAuthenticatedClient"),
      vi.spyOn(grant, "token"),
    ]),
  ];
  const handlers = {
    token: server.handleTokenRequest.bind(server),
    revocation: server.handleRevocationRequest.bind(server),
    introspection: server.handleIntrospectionRequest.bind(server),
    device: server.handleDeviceAuthorizationRequest.bind(server),
  };
  let app: Hono | undefined;
  if (server instanceof HonoAuthorizationServer) {
    app = new Hono();
    app.post("/token", server.tokenHandler());
    app.post("/revocation", server.revocationHandler());
    app.post("/introspection", server.introspectionHandler());
    app.post("/device", server.deviceAuthorizationHandler());
  }
  return {
    server,
    tokenService,
    async send(
      endpoint: Endpoint,
      fields: URLSearchParams,
      headers: Record<string, string> = {},
    ): Promise<Response> {
      const request = formRequest(
        `http://localhost/${endpoint}`,
        fields,
        headers,
      );
      return await (app ? app.request(request) : handlers[endpoint](request));
    },
    assertNoWork(): void {
      expect([
        resolve.mock.calls.length,
        grantResolve.mock.calls.length,
        ...observers.map((observer) => observer.mock.calls.length),
      ]).toStrictEqual(Array.from({ length: observers.length + 2 }, () => 0));
    },
    extensions: () => extensions,
    [Symbol.dispose](): void {
      for (const observer of observers.toReversed()) observer.mockRestore();
    },
  };
}

function fieldsFor(
  endpoint: Endpoint,
  grantType = "client_credentials",
): URLSearchParams {
  const fields = new URLSearchParams({
    client_id: "fixture-client",
    client_secret: "fixture-secret",
  });
  if (endpoint === "token") {
    for (const [name, value] of Object.entries({
      grant_type: grantType,
      scope: "read",
      code: "fixture-code",
      redirect_uri: "https://example.com/callback",
      code_verifier: "A".repeat(43),
      refresh_token: "fixture-refresh",
      username: "fixture-user",
      password: "fixture-password",
      device_code: "fixture-device",
    }))
      fields.set(name, value);
  } else if (endpoint === "device") {
    fields.set("scope", "read");
  } else {
    fields.set("token", "fixture-token");
    fields.set("token_type_hint", "access_token");
  }
  return fields;
}

async function assertRefusal(
  response: Response,
  errorFormat: "oauth2" | "problem-details" = "oauth2",
): Promise<void> {
  expect(response.status).toBe(400);
  expect(response.headers.get("cache-control")).toBe("no-store");
  expect(response.headers.get("pragma")).toBe("no-cache");
  expect(response.headers.get("www-authenticate")).toBe(null);
  const body = await response.json();
  expect(body.error).toBe("invalid_request");
  expect(response.headers.get("content-type")).toBe(
    errorFormat === "oauth2"
      ? "application/json;charset=UTF-8"
      : "application/problem+json",
  );
  expect(JSON.stringify(body).includes("fixture-secret")).toBe(false);
  expect(JSON.stringify(body).includes("conflicting-value")).toBe(false);
  if (errorFormat === "problem-details") expect(body.status).toBe(400);
}

const cases: {
  endpoint: Endpoint;
  grantType?: string;
  parameters: string[];
}[] = [
  {
    endpoint: "token",
    grantType: "client_credentials",
    parameters: ["grant_type", "client_id", "client_secret", "scope"],
  },
  {
    endpoint: "token",
    grantType: "authorization_code",
    parameters: ["code", "redirect_uri", "code_verifier"],
  },
  {
    endpoint: "token",
    grantType: "refresh_token",
    parameters: ["refresh_token", "scope"],
  },
  {
    endpoint: "token",
    grantType: "password",
    parameters: ["username", "password", "scope"],
  },
  { endpoint: "token", grantType: DEVICE_GRANT, parameters: ["device_code"] },
  {
    endpoint: "revocation",
    parameters: ["client_id", "client_secret", "token", "token_type_hint"],
  },
  {
    endpoint: "introspection",
    parameters: ["client_id", "client_secret", "token", "token_type_hint"],
  },
  { endpoint: "device", parameters: ["client_id", "client_secret", "scope"] },
];

describe("singleton protocol form parameters", () => {
  for (const transport of ["core", "hono"] as const) {
    for (const { endpoint, grantType, parameters } of cases) {
      for (const parameter of parameters) {
        for (const repetition of ["identical", "conflicting"] as const) {
          it(`${transport} refuses ${repetition} ${parameter} on ${endpoint} ${grantType ?? ""} before context, authentication or storage`, async () => {
            using fixture = await createFixture(transport);
            const fields = fieldsFor(endpoint, grantType);
            fields.append(
              parameter,
              repetition === "identical"
                ? fields.get(parameter)!
                : "conflicting-value",
            );
            await assertRefusal(await fixture.send(endpoint, fields));
            fixture.assertNoWork();
            expect(
              (await fixture.tokenService.getToken("fixture-token"))
                ?.accessToken,
            ).toBe("fixture-token");
          });
        }
      }
    }

    for (const endpoint of [
      "token",
      "revocation",
      "introspection",
      "device",
    ] as const) {
      for (const secret of ["fixture-secret", "invalid-secret"]) {
        it(`${transport} refuses repeated client_id before Basic authentication on ${endpoint} with ${secret === "fixture-secret" ? "valid" : "invalid"} header credentials`, async () => {
          using fixture = await createFixture(transport);
          const fields = fieldsFor(endpoint);
          fields.append("client_id", "fixture-client");
          await assertRefusal(
            await fixture.send(
              endpoint,
              fields,
              basicAuthHeader("fixture-client", secret),
            ),
          );
          fixture.assertNoWork();
        });
      }
      it(`${transport} preserves repeated unknown and resource/audience fields on ${endpoint}`, async () => {
        using fixture = await createFixture(transport);
        const fields = fieldsFor(endpoint);
        for (const parameter of ["resource", "audience", "custom"]) {
          fields.append(parameter, "first");
          fields.append(parameter, "second");
        }
        const response = await fixture.send(endpoint, fields);
        expect(response.status).toBe(200);
        await response.arrayBuffer();
      });
      it(`${transport} preserves valid singleton ${endpoint} requests`, async () => {
        using fixture = await createFixture(transport);
        const response = await fixture.send(endpoint, fieldsFor(endpoint));
        expect(response.status).toBe(200);
        await response.arrayBuffer();
      });
      it(`${transport} keeps problem details and cache headers on malformed ${endpoint} forms`, async () => {
        using fixture = await createFixture(transport, {
          errorFormat: "problem-details",
        });
        const fields = fieldsFor(endpoint);
        fields.append("client_id", "fixture-client");
        await assertRefusal(
          await fixture.send(endpoint, fields),
          "problem-details",
        );
        fixture.assertNoWork();
      });
    }

    it(`${transport} keeps unrelated and multivalue extension parameters on the client-credentials grant`, async () => {
      using fixture = await createFixture(transport);
      const fields = fieldsFor("token");
      for (const parameter of [
        "resource",
        "audience",
        "custom",
        "code",
        "token_type_hint",
      ]) {
        fields.delete(parameter);
        fields.append(parameter, "first");
        fields.append(parameter, "second");
      }
      const response = await fixture.send(
        "token",
        fields,
        basicAuthHeader("fixture-client", "fixture-secret"),
      );
      expect(response.status).toBe(200);
      await response.arrayBuffer();
    });

    it(`${transport} passes repeated extension values intact to a custom grant`, async () => {
      using fixture = await createFixture(transport);
      const fields = fieldsFor("token", CUSTOM_GRANT);
      for (const parameter of ["resource", "audience", "custom"]) {
        fields.append(parameter, "first");
        fields.append(parameter, "second");
      }
      const response = await fixture.send("token", fields);
      expect(response.status).toBe(200);
      await response.arrayBuffer();
      expect(fixture.extensions()).toStrictEqual({
        resource: ["first", "second"],
        audience: ["first", "second"],
        custom: ["first", "second"],
      });
    });
  }

  it("prepares the original invalid-request error before a throwOnError refusal", async () => {
    using fixture = await createFixture("core", { throwOnError: true });
    const fields = fieldsFor("token");
    fields.append("grant_type", "client_credentials");
    const error = await rejection(
      () => fixture.send("token", fields),
      InvalidRequestError,
    );
    expect(error.headers.get("cache-control")).toBe("no-store");
    expect(error.headers.get("pragma")).toBe("no-cache");
    fixture.assertNoWork();
  });
});
