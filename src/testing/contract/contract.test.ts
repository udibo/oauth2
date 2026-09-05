/**
 * Runs every contract suite against the `Memory*Service` fixtures and the
 * shipped token readers.
 *
 * Two purposes: (1) ensures the runners themselves work end-to-end, and
 * (2) the `Memory*Service` family is exercised by exactly the checks
 * consumers will run against their own implementations — if a memory
 * fixture quietly drifts from the contract, this catches it.
 */

import {
  MemoryAuthorizationCodeService,
  MemoryClientService,
  MemoryDeviceAuthorizationService,
  MemoryTokenService,
  MemoryUserService,
} from "../services.ts";
import type { TestClient, TestUser } from "../_test_fixtures.ts";
import { IntrospectionTokenReader } from "../../server/introspection-token-reader.ts";
import { JwksTokenReader } from "../../server/jwks-token-reader.ts";
import { generateSigningKey, signJwt } from "../../server/signing-keys.ts";

import { runUserServiceContractTests } from "./user.ts";
import { runClientServiceContractTests } from "./client.ts";
import { runTokenServiceContractTests } from "./token.ts";
import { runTokenReaderContractTests } from "./token-reader.ts";
import { runAuthorizationCodeServiceContractTests } from "./authorization-code.ts";
import { runDeviceAuthorizationServiceContractTests } from "./device-authorization.ts";
import { MemoryMfaStore } from "../../identity/mfa/service.ts";
import { MemoryTokenFlowStore } from "../../identity/token-flow.ts";
import { MemoryOtpStore } from "../../identity/otp.ts";
import { MemoryRateLimitStore } from "../../identity/rate-limit.ts";
import { MemoryLockoutStore } from "../../identity/lockout.ts";
import { runMfaStoreContractTests } from "./mfa-store.ts";
import { runTokenFlowStoreContractTests } from "./token-flow-store.ts";
import { runOtpStoreContractTests } from "./otp-store.ts";
import { runRateLimitStoreContractTests } from "./rate-limit-store.ts";
import { runLockoutStoreContractTests } from "./lockout-store.ts";

runUserServiceContractTests<TestUser>({
  describeName: "MemoryUserService satisfies UserServiceInterface contract",
  makeService: () => new MemoryUserService<TestUser>(),
  addUser: (svc, user, password) =>
    (svc as MemoryUserService<TestUser>).add(user, password),
});

runClientServiceContractTests<TestClient, TestUser>({
  describeName: "MemoryClientService satisfies ClientServiceInterface contract",
  makeServices: () => {
    const userService = new MemoryUserService<TestUser>();
    const clientService = new MemoryClientService<TestClient, TestUser>(
      userService,
    );
    return { userService, clientService };
  },
  addUser: (svc, user, pw) =>
    (svc as MemoryUserService<TestUser>).add(user, pw),
  addClient: (svc, client, secret, ownerUserId) =>
    (svc as MemoryClientService<TestClient, TestUser>).add(
      client,
      secret,
      ownerUserId,
    ),
});

runTokenServiceContractTests<TestClient, TestUser>({
  describeName: "MemoryTokenService satisfies TokenServiceInterface contract",
  makeServices: () => {
    const userService = new MemoryUserService<TestUser>();
    const clientService = new MemoryClientService<TestClient, TestUser>(
      userService,
    );
    const tokenService = new MemoryTokenService<TestClient, TestUser>({
      clientService,
      userService,
    });
    return { userService, clientService, tokenService };
  },
  addUser: (svc, user, pw) =>
    (svc as MemoryUserService<TestUser>).add(user, pw),
  addClient: (svc, client, secret, ownerUserId) =>
    (svc as MemoryClientService<TestClient, TestUser>).add(
      client,
      secret,
      ownerUserId,
    ),
});

runAuthorizationCodeServiceContractTests<TestClient, TestUser>({
  describeName:
    "MemoryAuthorizationCodeService satisfies AuthorizationCodeServiceInterface contract",
  makeServices: () => {
    const userService = new MemoryUserService<TestUser>();
    const clientService = new MemoryClientService<TestClient, TestUser>(
      userService,
    );
    const authorizationCodeService = new MemoryAuthorizationCodeService<
      TestClient,
      TestUser
    >({ clientService, userService });
    return { userService, clientService, authorizationCodeService };
  },
  addUser: (svc, user, pw) =>
    (svc as MemoryUserService<TestUser>).add(user, pw),
  addClient: (svc, client, secret, ownerUserId) =>
    (svc as MemoryClientService<TestClient, TestUser>).add(
      client,
      secret,
      ownerUserId,
    ),
});

runDeviceAuthorizationServiceContractTests<TestClient, TestUser>({
  describeName:
    "MemoryDeviceAuthorizationService satisfies DeviceAuthorizationServiceInterface contract",
  makeServices: () => {
    const userService = new MemoryUserService<TestUser>();
    const clientService = new MemoryClientService<TestClient, TestUser>(
      userService,
    );
    const deviceAuthorizationService = new MemoryDeviceAuthorizationService<
      TestClient,
      TestUser
    >({ clientService, userService });
    return { userService, clientService, deviceAuthorizationService };
  },
  addUser: (svc, user, pw) =>
    (svc as MemoryUserService<TestUser>).add(user, pw),
  addClient: (svc, client, secret, ownerUserId) =>
    (svc as MemoryClientService<TestClient, TestUser>).add(
      client,
      secret,
      ownerUserId,
    ),
});

const ISSUER = "https://auth.example.com";
const AUDIENCE = "https://api.example.com";

runTokenReaderContractTests<TestClient, TestUser>({
  describeName:
    "IntrospectionTokenReader satisfies TokenReaderInterface contract",
  setup: () => ({
    reader: new IntrospectionTokenReader<TestClient, TestUser>({
      introspectionEndpoint: `${ISSUER}/introspect`,
      clientId: "api",
      clientSecret: "api-secret",
      getClient: (data) => ({ id: String(data.client_id) }),
      getUser: (data) =>
        data.sub ? { id: data.sub, username: "user-1" } : undefined,
      fetch: (_url, init) => {
        const token = new URLSearchParams(String(init?.body)).get("token");
        return Promise.resolve(
          Response.json(
            token === "valid-token"
              ? {
                active: true,
                token_type: "Bearer",
                client_id: "my-client",
                sub: "u1",
                scope: "read write",
                exp: Math.floor(Date.now() / 1000) + 3600,
              }
              : { active: false },
          ),
        );
      },
    }),
    validAccessToken: "valid-token",
    expected: { clientId: "my-client", userId: "u1", scope: "read write" },
    invalidAccessTokens: ["unknown-token"],
  }),
});

runTokenReaderContractTests<TestClient, TestUser>({
  describeName: "JwksTokenReader satisfies TokenReaderInterface contract",
  setup: async () => {
    const key = await generateSigningKey();
    const now = Math.floor(Date.now() / 1000);
    const claims = {
      iss: ISSUER,
      sub: "u1",
      client_id: "my-client",
      aud: AUDIENCE,
      iat: now,
      exp: now + 3600,
      scope: "read write",
    };
    return {
      reader: new JwksTokenReader<TestClient, TestUser>({
        issuer: ISSUER,
        audience: AUDIENCE,
        jwksUri: `${ISSUER}/jwks`,
        getClient: (c) => ({ id: String(c.client_id) }),
        getUser: (c) => c.sub ? { id: c.sub, username: "user-1" } : undefined,
        fetch: () => Promise.resolve(Response.json({ keys: [key.publicJwk] })),
      }),
      validAccessToken: await signJwt(key, claims, { typ: "at+jwt" }),
      expected: { clientId: "my-client", userId: "u1", scope: "read write" },
      invalidAccessTokens: [
        "not-a-jwt",
        await signJwt(key, { ...claims, iss: "https://evil.example.com" }, {
          typ: "at+jwt",
        }),
        await signJwt(key, { ...claims, exp: now - 3600 }, { typ: "at+jwt" }),
      ],
    };
  },
});

runMfaStoreContractTests({
  describeName: "MemoryMfaStore satisfies MfaStore contract",
  makeStore: () => new MemoryMfaStore(),
});

runTokenFlowStoreContractTests({
  describeName: "MemoryTokenFlowStore satisfies TokenFlowStore contract",
  makeStore: () => new MemoryTokenFlowStore(),
});

runOtpStoreContractTests({
  describeName: "MemoryOtpStore satisfies OtpStore contract",
  makeStore: () => new MemoryOtpStore(),
});

runRateLimitStoreContractTests({
  describeName: "MemoryRateLimitStore satisfies RateLimitStore contract",
  makeStore: () => new MemoryRateLimitStore(),
});

runLockoutStoreContractTests({
  describeName: "MemoryLockoutStore satisfies LockoutStore contract",
  makeStore: () => new MemoryLockoutStore(),
});
