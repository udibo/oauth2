import { afterEach, describe, expect, it } from "vitest";

import { AuthorizationCodeGrant } from "../../server/grants/authorization-code.ts";
import { ClientCredentialsGrant } from "../../server/grants/client-credentials.ts";
import { RefreshTokenGrant } from "../../server/grants/refresh-token.ts";
import {
  ENDPOINT_METHODS,
  ENDPOINT_PATHS,
} from "../../server/authorization-server.ts";
import {
  basicAuthHeader,
  MemoryAuthorizationCodeService,
  MemoryClientService,
  MemoryTokenService,
  MemoryUserService,
  type TestClient,
  type TestUser,
} from "../../testing/_test_fixtures.ts";
import {
  generateCodeChallenge,
  generateCodeVerifier,
} from "../../utils/pkce.ts";

import {
  EXPRESS_VERSIONS,
  type Listening,
  listen,
  recordErrors,
} from "./_test_express.ts";
import {
  type ExpressAuthenticateUserFn,
  ExpressAuthorizationServer,
} from "./authorization-server.ts";

const ISSUER = "https://auth.example.com";
const REDIRECT_URI = "https://app.example.com/callback";
const testUser: TestUser = { id: "user-1", username: "testuser" };
const webClient: TestClient = {
  id: "web",
  grants: ["authorization_code", "refresh_token"],
  redirectUris: [REDIRECT_URI],
};
const machineClient: TestClient = {
  id: "machine",
  grants: ["client_credentials"],
};
const FORM = { "content-type": "application/x-www-form-urlencoded" };

async function createServer(
  options: { maxBodyBytes?: number } = {},
): Promise<ExpressAuthorizationServer<TestClient, TestUser>> {
  const userService = new MemoryUserService();
  const clientService = new MemoryClientService(userService);
  const tokenService = new MemoryTokenService({ clientService, userService });
  const authorizationCodeService = new MemoryAuthorizationCodeService({
    clientService,
    userService,
  });
  await userService.add(testUser, "password");
  await clientService.add(webClient, "web-secret");
  await clientService.add(machineClient, "machine-secret");
  return new ExpressAuthorizationServer<TestClient, TestUser>({
    resolve: () => ({
      services: { clientService, tokenService },
      issuer: ISSUER,
      authorizationEndpoint: `${ISSUER}/oauth2/authorize`,
      tokenEndpoint: `${ISSUER}/oauth2/token`,
      revocationEndpoint: `${ISSUER}/oauth2/revoke`,
      introspectionEndpoint: `${ISSUER}/oauth2/introspect`,
    }),
    grants: {
      authorization_code: new AuthorizationCodeGrant<TestClient, TestUser>({
        resolve: () => ({
          clientService,
          tokenService,
          authorizationCodeService,
        }),
        allowRefreshToken: true,
      }),
      refresh_token: new RefreshTokenGrant<TestClient, TestUser>({
        resolve: () => ({ clientService, tokenService }),
      }),
      client_credentials: new ClientCredentialsGrant<TestClient, TestUser>({
        resolve: () => ({ clientService, tokenService }),
      }),
    },
    scopesSupported: ["read", "write"],
    maxBodyBytes: options.maxBodyBytes,
  });
}

const signedIn: ExpressAuthenticateUserFn<TestUser> = () =>
  Promise.resolve({ user: testUser });

function form(fields: Record<string, string>): string {
  return new URLSearchParams(fields).toString();
}

describe.each(EXPRESS_VERSIONS)(
  "ExpressAuthorizationServer on %s",
  (_, express) => {
    let listening: Listening | undefined;

    afterEach(async () => {
      await listening?.close();
      listening = undefined;
    });

    async function serve(app: ReturnType<typeof express>): Promise<string> {
      listening = await listen(app);
      return listening.origin;
    }

    async function authorize(
      origin: string,
      verifier: string,
      extra: Record<string, string> = {},
    ): Promise<Response> {
      const query = new URLSearchParams({
        response_type: "code",
        client_id: webClient.id,
        redirect_uri: REDIRECT_URI,
        state: "state-1",
        scope: "read",
        code_challenge: await generateCodeChallenge(verifier),
        code_challenge_method: "S256",
        ...extra,
      });
      return fetch(`${origin}/oauth2/authorize?${query}`, {
        redirect: "manual",
      });
    }

    it("runs the authorization-code and PKCE flow, refresh, revocation and a protected route", async () => {
      const server = await createServer();
      const app = express();
      app.use("/oauth2", server.routes({ authenticateUser: signedIn }));
      app.get("/api/me", server.protect("read"), (_req, res) => {
        res.json({ user: server.getContext(res).user?.id });
      });
      const origin = await serve(app);

      const verifier = generateCodeVerifier();
      const authorized = await authorize(origin, verifier);
      expect(authorized.status).toBe(302);
      const callback = new URL(authorized.headers.get("location") ?? "");
      expect(`${callback.origin}${callback.pathname}`).toBe(REDIRECT_URI);
      expect(callback.searchParams.get("state")).toBe("state-1");
      expect(callback.searchParams.get("iss")).toBe(ISSUER);
      const code = callback.searchParams.get("code") ?? "";

      const exchanged = await fetch(`${origin}/oauth2/token`, {
        method: "POST",
        headers: { ...FORM, ...basicAuthHeader(webClient.id, "web-secret") },
        body: form({
          grant_type: "authorization_code",
          code,
          redirect_uri: REDIRECT_URI,
          code_verifier: verifier,
        }),
      });
      expect(exchanged.status).toBe(200);
      expect(exchanged.headers.get("cache-control")).toBe("no-store");
      const tokens = (await exchanged.json()) as {
        access_token: string;
        refresh_token: string;
        token_type: string;
        scope: string;
      };
      expect(tokens.token_type).toBe("Bearer");
      expect(tokens.scope).toBe("read");

      const me = await fetch(`${origin}/api/me`, {
        headers: { authorization: `Bearer ${tokens.access_token}` },
      });
      expect(me.status).toBe(200);
      expect(await me.json()).toStrictEqual({ user: testUser.id });

      const refreshed = await fetch(`${origin}/oauth2/token`, {
        method: "POST",
        headers: { ...FORM, ...basicAuthHeader(webClient.id, "web-secret") },
        body: form({
          grant_type: "refresh_token",
          refresh_token: tokens.refresh_token,
        }),
      });
      expect(refreshed.status).toBe(200);
      const rotated = (await refreshed.json()) as { access_token: string };
      expect(rotated.access_token).not.toBe(tokens.access_token);

      const revoked = await fetch(`${origin}/oauth2/revoke`, {
        method: "POST",
        headers: { ...FORM, ...basicAuthHeader(webClient.id, "web-secret") },
        body: form({ token: rotated.access_token }),
      });
      expect(revoked.status).toBe(200);

      const introspected = await fetch(`${origin}/oauth2/introspect`, {
        method: "POST",
        headers: { ...FORM, ...basicAuthHeader(webClient.id, "web-secret") },
        body: form({ token: rotated.access_token }),
      });
      expect(await introspected.json()).toStrictEqual({ active: false });

      const afterRevoke = await fetch(`${origin}/api/me`, {
        headers: { authorization: `Bearer ${rotated.access_token}` },
      });
      expect(afterRevoke.status).toBe(401);
    });

    it("serves exactly the paths and verbs the endpoint table declares, plus HEAD for GET", async () => {
      const server = await createServer();
      const app = express();
      app.use("/oauth2", server.routes({ authenticateUser: signedIn }));
      app.use((_req, res) => {
        res.status(404).set("x-fell-through", "1").end();
      });
      const origin = await serve(app);

      for (const [key, path] of Object.entries(ENDPOINT_PATHS)) {
        const methods = ENDPOINT_METHODS[key as keyof typeof ENDPOINT_PATHS];
        for (const method of ["GET", "HEAD", "POST", "PUT"]) {
          const response = await fetch(`${origin}/oauth2${path}`, {
            method,
            redirect: "manual",
          });
          await response.body?.cancel();
          const served =
            methods.includes(method) ||
            (method === "HEAD" && methods.includes("GET"));
          expect(
            response.headers.get("x-fell-through"),
            `${method} ${path} ${served ? "served" : "fell through"}`,
          ).toBe(served ? null : "1");
        }
      }
    });

    it("falls through to later routes for a path it does not serve", async () => {
      const server = await createServer();
      const app = express();
      app.use("/oauth2", server.routes({ authenticateUser: signedIn }));
      app.get("/oauth2/custom", (_req, res) => {
        res.send("custom");
      });
      const origin = await serve(app);

      const response = await fetch(`${origin}/oauth2/custom`);
      expect(await response.text()).toBe("custom");
    });

    it("passes the Express request and response to authenticateUser and writes its Response", async () => {
      const server = await createServer();
      const app = express();
      const seen: { originalUrl?: string; locals?: unknown }[] = [];
      app.use("/oauth2", (_req, res, next) => {
        res.locals.marker = "set-by-earlier-middleware";
        next();
      });
      app.use(
        "/oauth2",
        server.routes({
          authenticateUser: (req, res) => {
            seen.push({
              originalUrl: req.originalUrl,
              locals: res.locals.marker,
            });
            return Promise.resolve(
              new Response(null, {
                status: 302,
                headers: {
                  location: `/login?return_to=${encodeURIComponent(req.originalUrl ?? "")}`,
                },
              }),
            );
          },
        }),
      );
      const origin = await serve(app);

      const response = await authorize(origin, generateCodeVerifier());
      expect(response.status).toBe(302);
      const location = new URL(response.headers.get("location") ?? "", origin);
      expect(location.pathname).toBe("/login");
      expect(location.searchParams.get("return_to")).toMatch(
        /^\/oauth2\/authorize\?response_type=code&/,
      );
      expect(seen).toHaveLength(1);
      expect(seen[0].originalUrl).toMatch(/^\/oauth2\/authorize\?/);
      expect(seen[0].locals).toBe("set-by-earlier-middleware");
    });

    it("redirects with access_denied when authenticateUser returns null", async () => {
      const server = await createServer();
      const app = express();
      app.use(
        "/oauth2",
        server.routes({ authenticateUser: () => Promise.resolve(null) }),
      );
      const origin = await serve(app);

      const response = await authorize(origin, generateCodeVerifier());
      const location = new URL(response.headers.get("location") ?? "");
      expect(location.searchParams.get("error")).toBe("access_denied");
    });

    it("passes the Express request to handleConsent and writes its consent page", async () => {
      const server = await createServer();
      const app = express();
      const consentedFor: string[] = [];
      app.use(
        "/oauth2",
        server.routes({
          authenticateUser: signedIn,
          handleConsent: (req, _res, client, scope) => {
            consentedFor.push(`${client.id} ${scope} ${req.method}`);
            return Promise.resolve(
              new Response("<h1>Allow?</h1>", {
                headers: { "content-type": "text/html" },
              }),
            );
          },
        }),
      );
      const origin = await serve(app);

      const response = await authorize(origin, generateCodeVerifier());
      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toBe("text/html");
      expect(await response.text()).toBe("<h1>Allow?</h1>");
      expect(consentedFor).toStrictEqual(["web read GET"]);
    });

    it("keeps Set-Cookie headers earlier middleware set alongside its own", async () => {
      const server = await createServer();
      const app = express();
      app.use("/oauth2", (_req, res, next) => {
        res.cookie("session", "kept");
        next();
      });
      app.use(
        "/oauth2",
        server.routes({
          authenticateUser: () => {
            const headers = new Headers({ location: "/login" });
            headers.append("set-cookie", "pending=one");
            headers.append("set-cookie", "attempt=two");
            return Promise.resolve(
              new Response(null, { status: 302, headers }),
            );
          },
        }),
      );
      const origin = await serve(app);

      const response = await authorize(origin, generateCodeVerifier());
      expect(
        response.headers.getSetCookie().map((cookie) => cookie.split(";")[0]),
      ).toStrictEqual(["session=kept", "pending=one", "attempt=two"]);
    });

    it("passes an error to next instead of reading a body a parser already consumed", async () => {
      const server = await createServer();
      const app = express();
      const { errors, handler } = recordErrors();
      app.use(express.urlencoded({ extended: false }));
      app.use("/oauth2", server.routes({ authenticateUser: signedIn }));
      app.use(handler);
      const origin = await serve(app);

      const response = await fetch(`${origin}/oauth2/token`, {
        method: "POST",
        headers: {
          ...FORM,
          ...basicAuthHeader(machineClient.id, "machine-secret"),
        },
        body: form({ grant_type: "client_credentials" }),
      });
      expect(response.status).toBe(500);
      expect(await response.text()).toMatch(
        /before any body-parsing middleware/,
      );
      expect(errors).toHaveLength(1);
    });

    it("hands the core the raw form, so a repeated parameter is refused", async () => {
      const server = await createServer();
      const app = express();
      app.use("/oauth2", server.routes({ authenticateUser: signedIn }));
      const origin = await serve(app);

      const response = await fetch(`${origin}/oauth2/token`, {
        method: "POST",
        headers: {
          ...FORM,
          ...basicAuthHeader(machineClient.id, "machine-secret"),
        },
        body: "grant_type=client_credentials&grant_type=client_credentials",
      });
      expect(response.status).toBe(400);
      expect(((await response.json()) as { error: string }).error).toBe(
        "invalid_request",
      );
    });

    it("refuses a JSON token request rather than reading it as a form", async () => {
      const server = await createServer();
      const app = express();
      app.use("/oauth2", server.routes({ authenticateUser: signedIn }));
      const origin = await serve(app);

      const response = await fetch(`${origin}/oauth2/token`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...basicAuthHeader(machineClient.id, "machine-secret"),
        },
        body: JSON.stringify({ grant_type: "client_credentials" }),
      });
      expect(response.status).toBe(400);
      expect(((await response.json()) as { error: string }).error).toBe(
        "invalid_request",
      );
    });

    it("applies maxBodyBytes to a streamed body with no content-length", async () => {
      const server = await createServer({ maxBodyBytes: 1024 });
      const app = express();
      app.use("/oauth2", server.routes({ authenticateUser: signedIn }));
      const origin = await serve(app);

      const payload = new TextEncoder().encode(
        `grant_type=client_credentials&pad=${"a".repeat(4096)}`,
      );
      let pulled = 0;
      const stream = new ReadableStream<Uint8Array>({
        pull(controller) {
          if (pulled >= payload.byteLength) return controller.close();
          controller.enqueue(payload.subarray(pulled, pulled + 256));
          pulled += 256;
        },
      });
      const init: RequestInit & { duplex: "half" } = {
        method: "POST",
        headers: {
          ...FORM,
          ...basicAuthHeader(machineClient.id, "machine-secret"),
        },
        body: stream,
        duplex: "half",
      };
      const response = await fetch(`${origin}/oauth2/token`, init);
      expect(response.status).toBe(413);
      expect(((await response.json()) as { error: string }).error).toBe(
        "invalid_request",
      );
    });

    it("serves the metadata document at the mount's well-known path", async () => {
      const server = await createServer();
      const app = express();
      app.use("/oauth2", server.routes({ authenticateUser: signedIn }));
      const origin = await serve(app);

      const response = await fetch(
        `${origin}/oauth2/.well-known/oauth-authorization-server`,
      );
      expect(response.status).toBe(200);
      const metadata = (await response.json()) as {
        issuer: string;
        token_endpoint: string;
      };
      expect(metadata.issuer).toBe(ISSUER);
      expect(metadata.token_endpoint).toBe(`${ISSUER}/oauth2/token`);
    });

    it("mounts the individual handler factories at custom paths", async () => {
      const server = await createServer();
      const app = express();
      app.post("/custom/token", server.tokenHandler());
      const origin = await serve(app);

      const response = await fetch(`${origin}/custom/token`, {
        method: "POST",
        headers: {
          ...FORM,
          ...basicAuthHeader(machineClient.id, "machine-secret"),
        },
        body: form({ grant_type: "client_credentials" }),
      });
      expect(response.status).toBe(200);
      expect(
        ((await response.json()) as { token_type: string }).token_type,
      ).toBe("Bearer");
    });

    it("protects its own API routes with per-route scopes and inline authentication", async () => {
      const server = await createServer();
      const app = express();
      app.use("/oauth2", server.routes({ authenticateUser: signedIn }));
      app.use("/api", server.protect());
      app.get("/api/read", server.requireScope("read"), (_req, res) => {
        res.send("read");
      });
      app.get("/api/write", server.require({ scope: "write" }), (_req, res) => {
        res.send("written");
      });
      app.get("/inline", (req, res, next) => {
        server.authenticate(req, "read").then((context) => {
          res.json({ client: context.client.id });
        }, next);
      });
      const origin = await serve(app);

      const issued = await fetch(`${origin}/oauth2/token`, {
        method: "POST",
        headers: {
          ...FORM,
          ...basicAuthHeader(machineClient.id, "machine-secret"),
        },
        body: form({ grant_type: "client_credentials", scope: "read" }),
      });
      const { access_token } = (await issued.json()) as {
        access_token: string;
      };
      const headers = { authorization: `Bearer ${access_token}` };

      expect(
        await (await fetch(`${origin}/api/read`, { headers })).text(),
      ).toBe("read");
      expect((await fetch(`${origin}/api/write`, { headers })).status).toBe(
        403,
      );
      expect(
        await (await fetch(`${origin}/inline`, { headers })).json(),
      ).toStrictEqual({ client: machineClient.id });
    });

    it("passes an error authenticateUser throws to next", async () => {
      const server = await createServer();
      const app = express();
      const { errors, handler } = recordErrors();
      server.throwOnError = true;
      app.use(
        "/oauth2",
        server.routes({
          authenticateUser: () =>
            Promise.reject(new Error("session store down")),
        }),
      );
      app.use(handler);
      const origin = await serve(app);

      const response = await authorize(origin, generateCodeVerifier());
      expect(response.status).toBe(500);
      expect(errors).toHaveLength(1);
      expect(errors[0]).toBeInstanceOf(Error);
    });
  },
);
